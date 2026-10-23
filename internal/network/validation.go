package network

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type ValidationSettings struct {
	Target           string `json:"target"`
	Contains         string `json:"contains"`
	FailureAction    string `json:"failure_action"`
	FailureThreshold int    `json:"failure_threshold"`
}

const DefaultPoolValidationTarget = "https://www.baidu.com"

// PoolHealth keeps page content assertions separate from task target checks.
type PoolHealth struct {
	Configuration string      `json:"configuration"`
	Version       int64       `json:"version"`
	Failures      int         `json:"failures"`
	Observation   Observation `json:"observation"`
	Generation    uint64      `json:"generation"`
}

type PoolValidationResult struct {
	Checked           int           `json:"checked"`
	Passed            int           `json:"passed"`
	Failed            int           `json:"failed"`
	Skipped           int           `json:"skipped"`
	Disabled          int           `json:"disabled"`
	Deleted           int           `json:"deleted"`
	Observations      []Observation `json:"observations"`
	PruningSuppressed bool          `json:"pruning_suppressed,omitempty"`
	Reason            string        `json:"reason,omitempty"`
}

func normalizeValidation(settings ValidationSettings) (ValidationSettings, error) {
	settings.Target = strings.TrimSpace(settings.Target)
	if settings.FailureAction == "" {
		settings.FailureAction = "keep"
	}
	if settings.FailureAction != "keep" && settings.FailureAction != "disable" && settings.FailureAction != "delete" {
		return settings, fmt.Errorf("save pool validation: failure action must be keep, disable or delete")
	}
	if settings.FailureThreshold == 0 {
		settings.FailureThreshold = 3
	}
	if settings.FailureThreshold < 1 || settings.FailureThreshold > 10 {
		return settings, fmt.Errorf("save pool validation: failure threshold must be between 1 and 10")
	}
	if len(settings.Contains) > 65536 {
		return settings, fmt.Errorf("save pool validation: expected substring exceeds 64 KiB")
	}
	if settings.Target != "" {
		t, err := ParseTarget(settings.Target)
		if err != nil {
			return settings, fmt.Errorf("save pool validation target: %w", err)
		}
		if t.Scheme != "http" && t.Scheme != "https" {
			return settings, fmt.Errorf("save pool validation: target must use HTTP or HTTPS")
		}
		parsed, err := url.Parse(settings.Target)
		if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return settings, fmt.Errorf("save pool validation: target query and fragment are unsupported")
		}
		settings.Target = t.URL()
	}
	return settings, nil
}

func (s *Service) validationSettingsLocked() (ValidationSettings, error) {
	settings := s.state.Validation
	if settings == (ValidationSettings{}) {
		settings.Target = DefaultPoolValidationTarget
	}
	return normalizeValidation(settings)
}

func (s *Service) ValidationSettings() ValidationSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	settings, _ := s.validationSettingsLocked()
	return settings
}

func (s *Service) SaveValidationSettings(settings ValidationSettings) (ValidationSettings, error) {
	settings, err := normalizeValidation(settings)
	if err != nil {
		return settings, err
	}
	err = s.mutate(func() error {
		old, _ := s.validationSettingsLocked()
		if old != settings {
			s.state.PoolHealth = map[string]PoolHealth{}
		}
		s.state.Validation = settings
		return nil
	})
	return settings, err
}

type poolProbe struct {
	node           Node
	credential     Credential
	observation    Observation
	cleanupFailure bool
}

func validationFingerprint(settings ValidationSettings) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("target-get-v1/%q/%q/%s/%d", settings.Target, settings.Contains, settings.FailureAction, settings.FailureThreshold))))
}

func validatePoolProxy(ctx context.Context, item poolProbe, target Target, settings ValidationSettings, fingerprint string) poolProbe {
	n := item.node
	started := time.Now()
	o := Observation{NodeID: n.ID, Target: target.URL(), Context: fmt.Sprintf("pool/%s/%d", fingerprint, n.Version), ObservedAt: started.UTC(), ExpiresAt: started.Add(5 * time.Minute).UTC(), Stage: "connect"}
	u, err := url.Parse(n.Address)
	if err != nil {
		o.Reason = "invalid saved proxy address"
		item.observation = o
		return item
	}
	if n.HasAuth {
		u.User = url.UserPassword(item.credential.Username, item.credential.Password)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: http.ProxyURL(u), TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	connectStatus := 0
	transport.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, response *http.Response) error {
		connectStatus = response.StatusCode
		return nil
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target.URL(), nil)
	if err == nil {
		var response *http.Response
		response, err = client.Do(req)
		if err == nil {
			targetResponse(&o, response.StatusCode)
			item.cleanupFailure = response.StatusCode == http.StatusProxyAuthRequired
			if o.Reachable && settings.Contains != "" {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
				switch {
				case response.StatusCode >= 400:
					o.Reachable = false
					o.Stage = "http_status"
					o.Reason = "target returned an HTTP error response"
				case readErr != nil:
					o.Reachable = false
					o.Stage = "content"
					o.Reason = "could not read target response body"
				case len(body) > 1<<20:
					o.Reachable = false
					o.Stage = "content"
					o.Reason = "target response exceeds 1 MiB validation limit"
				case !strings.Contains(string(body), settings.Contains):
					o.Reachable = false
					o.Stage = "content"
					o.Reason = "target response does not contain expected substring"
				}
			}
			_ = response.Body.Close()
		}
	}
	if err != nil {
		o.Reason = strings.ReplaceAll(err.Error(), u.String(), n.Address)
		if item.credential.Password != "" {
			o.Reason = strings.ReplaceAll(o.Reason, item.credential.Password, "[redacted]")
		}
		item.cleanupFailure = ctx.Err() == nil
		if connectStatus != 0 && connectStatus != http.StatusOK {
			o.HTTPStatus = connectStatus
			o.Stage = "http_status"
			o.Reason = "proxy CONNECT returned an HTTP error response"
			item.cleanupFailure = false
			if connectStatus == http.StatusProxyAuthRequired {
				o.Stage = "proxy_auth"
				o.Reason = "proxy authentication required or rejected"
				item.cleanupFailure = ctx.Err() == nil
			}
		}
	}
	o.LatencyMS = time.Since(started).Milliseconds()
	item.observation = o
	return item
}

func (s *Service) ValidatePool(ctx context.Context, _ Identity, ids []string) (PoolValidationResult, error) {
	settings, generation, err := s.beginPoolValidation(ctx, nil)
	if err != nil {
		return PoolValidationResult{Observations: []Observation{}}, err
	}
	return s.validatePool(ctx, ids, &settings, false, generation)
}

func (s *Service) beginPoolValidation(ctx context.Context, expected *ValidationSettings) (ValidationSettings, uint64, error) {
	var settings ValidationSettings
	var generation uint64
	err := s.mutate(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		settings, _ = s.validationSettingsLocked()
		if expected != nil && settings != *expected {
			return fmt.Errorf("pool validation settings changed; completed batch results are preserved")
		}
		if s.state.ValidationGeneration == ^uint64(0) {
			return fmt.Errorf("pool validation generation exhausted")
		}
		s.state.ValidationGeneration++
		generation = s.state.ValidationGeneration
		return nil
	})
	return settings, generation, err
}

// ValidatePoolWithSettings keeps a multi-batch job on its original validation configuration.
func (s *Service) ValidatePoolWithSettings(ctx context.Context, _ Identity, ids []string, settings ValidationSettings) (PoolValidationResult, error) {
	settings, err := normalizeValidation(settings)
	if err != nil {
		return PoolValidationResult{Observations: []Observation{}}, err
	}
	result := PoolValidationResult{Observations: []Observation{}}
	if len(ids) == 0 {
		for _, n := range s.Nodes() {
			ids = append(ids, n.ID)
		}
	}
	if len(ids) > 10000 {
		return result, fmt.Errorf("pool validation accepts at most 10000 node IDs per job")
	}
	_, generation, err := s.beginPoolValidation(ctx, &settings)
	if err != nil {
		return result, err
	}
	seen := map[string]bool{}
	unique := []string{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	sort.Strings(unique)
	batchSize := 1000
	if jobControl(ctx) != nil {
		batchSize = 8
	}
	reportJobProgress(ctx, JobProgress{Kind: "validation", Stage: "validating", Total: len(unique)})
	for offset := 0; offset < len(unique); offset += batchSize {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		end := offset + batchSize
		if end > len(unique) {
			end = len(unique)
		}
		finish, err := beginJobUnit(ctx)
		if err != nil {
			return result, err
		}
		batch, err := s.validatePool(ctx, unique[offset:end], &settings, true, generation)
		reportJobProgress(ctx, JobProgress{Kind: "validation", Stage: "validating", Completed: batch.Checked + batch.Skipped, Passed: batch.Passed, Failed: batch.Failed, Skipped: batch.Skipped})
		finish()
		result.Checked += batch.Checked
		result.Passed += batch.Passed
		result.Failed += batch.Failed
		result.Skipped += batch.Skipped
		result.Observations = append(result.Observations, batch.Observations...)
		if batch.Reason != "" {
			result.Reason = batch.Reason
		}
		if err != nil {
			return result, err
		}
	}
	if settings.Target == "" {
		result.Reason = "validation target is not configured"
	}
	finish, err := beginJobUnit(ctx)
	if err != nil {
		return result, err
	}
	defer finish()
	if err := s.finishPoolValidation(ctx, settings, &result, generation); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Service) validatePool(ctx context.Context, ids []string, expected *ValidationSettings, deferCleanup bool, generation uint64) (PoolValidationResult, error) {
	result := PoolValidationResult{Observations: []Observation{}}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	s.mu.RLock()
	settings, _ := s.validationSettingsLocked()
	if expected != nil && settings != *expected {
		s.mu.RUnlock()
		return result, fmt.Errorf("pool validation settings changed; completed batch results are preserved")
	}
	if len(ids) == 0 {
		for id, n := range s.state.Nodes {
			if n.ProjectID == "" {
				ids = append(ids, id)
			}
		}
	}
	ids = append([]string{}, ids...)
	sort.Strings(ids)
	seen := map[string]bool{}
	items := []poolProbe{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		n, ok := s.state.Nodes[id]
		if !ok || n.ProjectID != "" || !n.Enabled || settings.Target == "" || len(items) >= 1000 {
			result.Skipped++
			continue
		}
		items = append(items, poolProbe{node: n, credential: s.state.Credentials[id]})
	}
	s.mu.RUnlock()
	if settings.Target == "" {
		result.Reason = "validation target is not configured"
		return result, nil
	}
	target, err := ParseTarget(settings.Target)
	if err != nil {
		return result, err
	}
	fingerprint := validationFingerprint(settings)
	jobs := make(chan poolProbe)
	completed := make(chan poolProbe, len(items))
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					continue
				}
				completed <- validatePoolProxy(ctx, item, target, settings, fingerprint)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, item := range items {
			select {
			case jobs <- item:
			case <-ctx.Done():
				return
			}
		}
	}()
	workers.Wait()
	close(completed)
	checked := []poolProbe{}
	responsive := 0
	for item := range completed {
		checked = append(checked, item)
		if item.observation.HTTPStatus != 0 && item.observation.HTTPStatus != 407 {
			responsive++
		}
	}
	sort.Slice(checked, func(a, b int) bool { return checked[a].node.ID < checked[b].node.ID })
	result.Checked = len(checked)
	result.Skipped += len(items) - len(checked)
	for _, item := range checked {
		result.Observations = append(result.Observations, item.observation)
		if item.observation.Reachable {
			result.Passed++
		} else {
			result.Failed++
		}
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if !deferCleanup && responsive == 0 && result.Failed > 0 && settings.FailureAction != "keep" {
		result.PruningSuppressed = true
		result.Reason = "no proxy received a target response; cleanup suppressed to protect the pool from a failing validation target"
	}
	retired := []string{}
	err = s.mutate(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, _ := s.validationSettingsLocked()
		if current != settings {
			result.PruningSuppressed = true
			result.Reason = "validation settings changed while probes were running"
			return nil
		}
		if s.state.PoolHealth == nil {
			s.state.PoolHealth = map[string]PoolHealth{}
		}
		for _, item := range checked {
			n, ok := s.state.Nodes[item.node.ID]
			if !ok || n != item.node || s.state.Credentials[n.ID] != item.credential {
				continue
			}
			h := s.state.PoolHealth[n.ID]
			// Wall-clock timestamps may be equal on Windows; persisted generations order overlapping jobs.
			if h.Version == n.Version && h.Configuration == fingerprint && h.Generation > generation {
				continue
			}
			if h.Version != n.Version || h.Configuration != fingerprint {
				h = PoolHealth{Configuration: fingerprint, Version: n.Version}
			}
			h.Observation = item.observation
			h.Generation = generation
			if item.cleanupFailure {
				h.Failures++
			} else {
				h.Failures = 0
			}
			s.state.PoolHealth[n.ID] = h
			s.state.Observations = append(s.state.Observations, item.observation)
			if deferCleanup || !item.cleanupFailure || h.Failures < settings.FailureThreshold || result.PruningSuppressed || settings.FailureAction == "keep" {
				continue
			}
			if s.applyPoolActionLocked(n, h, settings, &result) {
				retired = append(retired, n.ID)
			}
		}
		if len(s.state.Observations) > 2000 {
			s.state.Observations = append([]Observation{}, s.state.Observations[len(s.state.Observations)-2000:]...)
		}
		return nil
	})
	if err != nil {
		result.Disabled = 0
		result.Deleted = 0
		return result, err
	}
	for _, id := range retired {
		s.retireNodeUsage(id)
	}
	return result, nil
}

func (s *Service) applyPoolActionLocked(n Node, health PoolHealth, settings ValidationSettings, result *PoolValidationResult) bool {
	for _, policy := range s.state.Policies {
		if policy.Mode == "fixed_proxy" && policy.ProxyID == n.ID {
			return false
		}
	}
	if settings.FailureAction == "disable" {
		n.Enabled = false
		n.Version++
		s.state.Nodes[n.ID] = n
		health.Version = n.Version
		health.Observation.Context = fmt.Sprintf("pool/%s/%d", health.Configuration, n.Version)
		s.state.PoolHealth[n.ID] = health
		result.Disabled++
	} else {
		delete(s.state.Nodes, n.ID)
		delete(s.state.Credentials, n.ID)
		delete(s.state.PoolHealth, n.ID)
		result.Deleted++
	}
	return true
}

func (s *Service) finishPoolValidation(ctx context.Context, settings ValidationSettings, result *PoolValidationResult, generation uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	responsive := false
	for _, observation := range result.Observations {
		if observation.HTTPStatus != 0 && observation.HTTPStatus != 407 {
			responsive = true
			break
		}
	}
	if !responsive && result.Failed > 0 && settings.FailureAction != "keep" {
		result.PruningSuppressed = true
		result.Reason = "no proxy received a target response; cleanup suppressed to protect the pool from a failing validation target"
	}
	retired := []string{}
	err := s.mutate(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, _ := s.validationSettingsLocked()
		if current != settings {
			return fmt.Errorf("pool validation settings changed; completed batch results are preserved")
		}
		if result.PruningSuppressed || settings.FailureAction == "keep" {
			return nil
		}
		fingerprint := validationFingerprint(settings)
		for _, observation := range result.Observations {
			n, ok := s.state.Nodes[observation.NodeID]
			if !ok || n.ProjectID != "" || !n.Enabled {
				continue
			}
			health := s.state.PoolHealth[n.ID]
			if health.Configuration != fingerprint || health.Version != n.Version || health.Observation.Context != observation.Context || health.Generation != generation {
				continue
			}
			if health.Failures < settings.FailureThreshold || health.Observation.Reachable || (health.Observation.Stage != "connect" && health.Observation.Stage != "proxy_auth") {
				continue
			}
			if s.applyPoolActionLocked(n, health, settings, result) {
				retired = append(retired, n.ID)
			}
		}
		return nil
	})
	if err != nil {
		result.Disabled = 0
		result.Deleted = 0
		return err
	}
	for _, id := range retired {
		s.retireNodeUsage(id)
	}
	return nil
}
