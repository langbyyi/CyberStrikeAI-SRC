package approval

import (
	"context"
	"errors"
	"sync"
	"time"
)

// HumanReviewBroker connects durable approval rows to live HTTP decisions.
// The database remains authoritative; this channel only wakes the currently
// running invocation and is intentionally not restored after process restart.
type HumanReviewBroker struct {
	mu      sync.Mutex
	pending map[string]chan ReviewDecision
}

func NewHumanReviewBroker() *HumanReviewBroker {
	return &HumanReviewBroker{pending: make(map[string]chan ReviewDecision)}
}

func (b *HumanReviewBroker) Review(ctx context.Context, request ReviewRequest) (ReviewDecision, error) {
	if b == nil || request.Approval == nil || request.Approval.ID == "" {
		return ReviewDecision{}, ErrReviewerUnavailable
	}
	decisionCh := make(chan ReviewDecision, 1)
	b.mu.Lock()
	if _, exists := b.pending[request.Approval.ID]; exists {
		b.mu.Unlock()
		return ReviewDecision{}, ErrStateConflict
	}
	b.pending[request.Approval.ID] = decisionCh
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, request.Approval.ID)
		b.mu.Unlock()
	}()

	var timeout <-chan time.Time
	var timer *time.Timer
	if request.Approval.ExpiresAt != nil {
		duration := time.Until(*request.Approval.ExpiresAt)
		if duration <= 0 {
			return ReviewDecision{}, ErrApprovalExpired
		}
		timer = time.NewTimer(duration)
		timeout = timer.C
		defer timer.Stop()
	}
	select {
	case decision := <-decisionCh:
		return decision, nil
	case <-timeout:
		return ReviewDecision{}, ErrApprovalExpired
	case <-ctx.Done():
		return ReviewDecision{}, ctx.Err()
	}
}

func (b *HumanReviewBroker) Decide(approvalID string, decision ReviewDecision) error {
	if b == nil {
		return ErrReviewerUnavailable
	}
	if decision.Decision != ReviewerApprove && decision.Decision != ReviewerReject {
		return errors.New("human decision must be approve or reject")
	}
	decision.ActorType = "human"
	b.mu.Lock()
	decisionCh, ok := b.pending[approvalID]
	b.mu.Unlock()
	if !ok {
		return ErrNotFound
	}
	select {
	case decisionCh <- decision:
		return nil
	default:
		return ErrStateConflict
	}
}

func (b *HumanReviewBroker) HasPending(approvalID string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.pending[approvalID]
	return ok
}
