package handler

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"cyberstrike-ai/internal/network"
	"github.com/gin-gonic/gin"
)

func (h *NetworkHandler) getValidation(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	c.JSON(200, h.Service.ValidationSettings())
}

func (h *NetworkHandler) putValidation(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	var req network.ValidationSettings
	if !networkJSON(c, &req) {
		return
	}
	settings, err := h.Service.SaveValidationSettings(req)
	if err != nil {
		networkError(c, err)
		return
	}
	c.JSON(200, settings)
}

func (h *NetworkHandler) bulkProxies(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	var req struct {
		NodeIDs []string `json:"node_ids"`
		Action  string   `json:"action"`
	}
	if !networkJSON(c, &req) {
		return
	}
	result, err := h.Service.BulkUpdateProxies(req.NodeIDs, req.Action)
	if err != nil {
		networkError(c, err)
		return
	}
	c.JSON(200, result)
}

func (h *NetworkHandler) validatePool(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	var req struct {
		NodeIDs []string `json:"node_ids"`
	}
	if !networkJSON(c, &req) {
		return
	}
	if len(req.NodeIDs) > 10000 {
		networkFailure(c, 400, "pool validation accepts at most 10000 explicit node IDs")
		return
	}
	if len(req.NodeIDs) == 0 {
		for _, n := range h.Service.Nodes() {
			req.NodeIDs = append(req.NodeIDs, n.ID)
		}
	}
	if len(req.NodeIDs) > 10000 {
		networkFailure(c, 400, "pool validation accepts at most 10000 nodes per job")
		return
	}
	// Stable unique batches ensure explicit duplicates cannot consume repeated probes.
	unique := map[string]bool{}
	ids := []string{}
	for _, id := range req.NodeIDs {
		if !unique[id] {
			unique[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	session, _ := h.user(c)
	identity := network.Identity{UserID: session.UserID, RunnerID: "local"}
	settings := h.Service.ValidationSettings()
	h.startPoolJob(c, 20*time.Minute, true, func(ctx context.Context) (interface{}, error) {
		return h.Service.ValidatePoolWithSettings(ctx, identity, ids, settings)
	})
}

type sourceBatchResult struct {
	network.SyncResult
	SourceIDs []string `json:"source_ids"`
	Failed    int      `json:"failed"`
}

func addSourceResult(result *sourceBatchResult, part network.SyncResult) {
	result.Imported += part.Imported
	result.Skipped += part.Skipped
	result.Pages += part.Pages
	for kind, count := range part.Unsupported {
		result.Unsupported[kind] += count
	}
}

func (h *NetworkHandler) syncSources(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	var req struct {
		SourceIDs []string `json:"source_ids"`
	}
	if !networkJSON(c, &req) {
		return
	}
	if len(req.SourceIDs) > 20 {
		networkFailure(c, 400, "batch synchronization accepts at most 20 source IDs")
		return
	}
	if len(req.SourceIDs) == 0 {
		for _, source := range h.Service.Sources() {
			req.SourceIDs = append(req.SourceIDs, source.ID)
		}
	}
	ids := append([]string{}, req.SourceIDs...)
	sort.Strings(ids)
	h.startPoolJob(c, 20*time.Minute, true, func(ctx context.Context) (interface{}, error) {
		return h.syncSourceBatch(ctx, ids)
	})
}

func (h *NetworkHandler) syncSourceBatch(ctx context.Context, ids []string) (sourceBatchResult, error) {
	result := sourceBatchResult{SyncResult: network.SyncResult{Unsupported: map[string]int{}}, SourceIDs: []string{}}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if err := ctx.Err(); err != nil {
			return result, err
		}
		part, err := h.Service.SyncSource(ctx, id, h.Fetcher)
		addSourceResult(&result, part)
		result.SourceIDs = append(result.SourceIDs, id)
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err != nil {
			result.Failed++
		}
	}
	if result.Failed > 0 {
		return result, fmt.Errorf("synchronization failed for %d sources; completed counts are preserved", result.Failed)
	}
	return result, nil
}

func (h *NetworkHandler) importSubscriptions(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	var req struct {
		Content string   `json:"content"`
		URLs    []string `json:"urls"`
		Name    string   `json:"name"`
	}
	if !networkJSON(c, &req) {
		return
	}
	hasContent := strings.TrimSpace(req.Content) != ""
	if hasContent == (len(req.URLs) > 0) || len(req.URLs) > 20 {
		networkFailure(c, 400, "provide subscription content or between 1 and 20 subscription URLs")
		return
	}
	if len(req.Content) > 2<<20 || len(req.Name) > 200 {
		networkFailure(c, 400, "subscription content exceeds 2 MiB or name exceeds 200 characters")
		return
	}
	if req.Name == "" {
		req.Name = "Imported subscription"
	}
	// Validate every URL before creating any saved source.
	for _, raw := range req.URLs {
		if err := validateSubscriptionURL(raw); err != nil {
			networkError(c, err)
			return
		}
	}
	h.startPoolJob(c, 20*time.Minute, true, func(ctx context.Context) (interface{}, error) {
		result := sourceBatchResult{SyncResult: network.SyncResult{Unsupported: map[string]int{}}, SourceIDs: []string{}}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if hasContent {
			finish, err := network.BeginJobUnit(ctx)
			if err != nil {
				return result, err
			}
			defer finish()
			part, err := h.Service.ImportProxyText(req.Content, "subscription-import")
			result.Imported = part.Imported
			result.Skipped = part.Skipped
			result.Unsupported = part.Unsupported
			network.ReportJobProgress(ctx, network.JobProgress{Kind: "source", Stage: "collecting", Imported: part.Imported, Skipped: part.Skipped})
			return result, err
		}
		for index, raw := range req.URLs {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			name := req.Name
			if len(req.URLs) > 1 {
				name = fmt.Sprintf("%.180s %d", name, index+1)
			}
			saved, err := h.Service.SaveSource(network.Source{Name: name, Kind: "subscription", URL: raw, Limit: network.MaxProxyImport})
			if err != nil {
				return result, fmt.Errorf("save imported subscription %d failed", index+1)
			}
			result.SourceIDs = append(result.SourceIDs, saved.ID)
			part, err := h.Service.SyncSource(ctx, saved.ID, h.Fetcher)
			addSourceResult(&result, part)
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			if err != nil {
				result.Failed++
			}
		}
		if result.Failed > 0 {
			return result, fmt.Errorf("synchronization failed for %d imported subscriptions; saved sources and counts are preserved", result.Failed)
		}
		return result, nil
	})
}

func validateSubscriptionURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || strings.ContainsAny(raw, "\r\n\x00") || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("invalid subscription URL; expected HTTP(S) URL without user information")
	}
	return nil
}
