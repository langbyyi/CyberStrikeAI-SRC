package multiagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const maxExecutionStateCheckpointBytes = 4 << 20

// fileCheckPointStore implements adk.CheckPointStore with one file per checkpoint id.
type fileCheckPointStore struct {
	dir            string
	conversationID string
	orchestration  string
}

func newFileCheckPointStore(baseDir string) (*fileCheckPointStore, error) {
	if strings.TrimSpace(baseDir) == "" {
		return nil, fmt.Errorf("checkpoint base dir empty")
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	return &fileCheckPointStore{dir: abs}, nil
}

func (s *fileCheckPointStore) BindExecutionState(conversationID, orchestration string) {
	if s == nil {
		return
	}
	s.conversationID = normalizeExecutionCheckpointConversationID(conversationID)
	s.orchestration = normalizeExecutionCheckpointOrchestration(orchestration)
}

func (s *fileCheckPointStore) path(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("checkpoint id empty")
	}
	if strings.ContainsAny(id, `/\`) {
		return "", fmt.Errorf("invalid checkpoint id")
	}
	return filepath.Join(s.dir, id+".ckpt"), nil
}

func (s *fileCheckPointStore) executionStatePath(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("checkpoint id empty")
	}
	if strings.ContainsAny(id, `/\`) {
		return "", fmt.Errorf("invalid checkpoint id")
	}
	return filepath.Join(s.dir, id+".state.json"), nil
}

func (s *fileCheckPointStore) Get(ctx context.Context, checkPointID string) ([]byte, bool, error) {
	_ = ctx
	p, err := s.path(checkPointID)
	if err != nil {
		return nil, false, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return b, true, nil
}

func (s *fileCheckPointStore) Set(ctx context.Context, checkPointID string, checkPoint []byte) error {
	p, err := s.path(checkPointID)
	if err != nil {
		return err
	}
	if err := writeCheckpointFile(p, checkPoint); err != nil {
		return err
	}
	if s.conversationID == "" {
		return nil
	}
	envelope := newExecutionStateCheckpointEnvelope(s.conversationID, s.orchestration)
	stateBytes, err := json.Marshal(envelope)
	if err != nil {
		_ = os.Remove(p)
		return fmt.Errorf("marshal execution state checkpoint: %w", err)
	}
	if len(stateBytes) > maxExecutionStateCheckpointBytes {
		_ = os.Remove(p)
		return fmt.Errorf("execution state checkpoint exceeds %d bytes", maxExecutionStateCheckpointBytes)
	}
	statePath, err := s.executionStatePath(checkPointID)
	if err != nil {
		_ = os.Remove(p)
		return err
	}
	if err := writeCheckpointFile(statePath, stateBytes); err != nil {
		_ = os.Remove(p)
		_ = os.Remove(statePath)
		return fmt.Errorf("write execution state checkpoint: %w", err)
	}
	return nil
}

func (s *fileCheckPointStore) RestoreExecutionState(ctx context.Context, checkPointID string) (bool, error) {
	if s == nil || s.conversationID == "" {
		return false, fmt.Errorf("execution state checkpoint binding missing")
	}
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	statePath, err := s.executionStatePath(checkPointID)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Size() > maxExecutionStateCheckpointBytes {
		return false, fmt.Errorf("execution state checkpoint exceeds %d bytes", maxExecutionStateCheckpointBytes)
	}
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		return false, err
	}
	var envelope executionStateCheckpointEnvelope
	if err := json.Unmarshal(stateBytes, &envelope); err != nil {
		return false, fmt.Errorf("decode execution state checkpoint: %w", err)
	}
	if err := validateExecutionStateCheckpointEnvelope(envelope, s.conversationID, s.orchestration); err != nil {
		return false, err
	}
	restoreConversationExecutionState(s.conversationID, envelope.ExecutionState)
	return true, nil
}

func einoCheckpointReadyForResume(ctx context.Context, store *fileCheckPointStore, checkPointID string) (bool, error) {
	if store == nil {
		return false, nil
	}
	if _, exists, err := store.Get(ctx, checkPointID); err != nil {
		return false, err
	} else if !exists {
		return false, nil
	}
	restored, err := store.RestoreExecutionState(ctx, checkPointID)
	if err != nil {
		return false, err
	}
	if !restored {
		return false, fmt.Errorf("execution state checkpoint missing")
	}
	return true, nil
}

func (s *fileCheckPointStore) Delete(ctx context.Context, checkPointID string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	checkpointPath, err := s.path(checkPointID)
	if err != nil {
		return err
	}
	statePath, err := s.executionStatePath(checkPointID)
	if err != nil {
		return err
	}
	var deleteErrors []error
	for _, path := range []string{checkpointPath, statePath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			deleteErrors = append(deleteErrors, err)
		}
	}
	return errors.Join(deleteErrors...)
}

func writeCheckpointFile(path string, content []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
