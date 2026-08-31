package hitl

import (
	"context"
	"time"

	"cyberstrike-ai/internal/approval"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

const retentionPurgeInterval = time.Hour

// Service manages terminal unified approval retention.
type Service struct {
	db     *database.DB
	cfg    *config.Config
	logger *zap.Logger
}

// NewService creates a HITL audit log retention service.
func NewService(db *database.DB, cfg *config.Config, logger *zap.Logger) *Service {
	return &Service{db: db, cfg: cfg, logger: logger}
}

// RetentionDays returns configured retention; 0 means keep forever.
func (s *Service) RetentionDays() int {
	if s == nil || s.cfg == nil {
		return config.HitlConfig{}.RetentionDaysEffective()
	}
	return s.cfg.Hitl.RetentionDaysEffective()
}

// PurgeExpired deletes terminal unified approvals older than retention_days when configured.
func (s *Service) PurgeExpired() {
	if s == nil || s.db == nil || s.cfg == nil {
		return
	}
	days := s.cfg.Hitl.RetentionDaysEffective()
	if days <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	approvalStore := approval.NewSQLiteStore(s.db)
	if err := approvalStore.EnsureSchema(context.Background()); err != nil {
		if s.logger != nil {
			s.logger.Warn("initialize approval retention schema", zap.Error(err))
		}
		return
	}
	approvalCount, err := approvalStore.PurgeTerminalBefore(context.Background(), cutoff)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("purge expired unified approvals", zap.Error(err))
		}
		return
	}
	if approvalCount > 0 && s.logger != nil {
		s.logger.Info("purged expired unified approvals", zap.Int64("deleted", approvalCount), zap.Int("retention_days", days))
	}
}

// StartRetentionLoop periodically purges expired unified approval rows.
func StartRetentionLoop(s *Service, logger *zap.Logger) {
	if s == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(retentionPurgeInterval)
		defer ticker.Stop()
		for range ticker.C {
			s.PurgeExpired()
			if logger != nil {
				logger.Debug("hitl audit log retention tick completed")
			}
		}
	}()
}
