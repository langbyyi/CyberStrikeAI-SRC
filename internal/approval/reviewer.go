package approval

import "context"

const (
	ReviewerApprove = "approve"
	ReviewerReject  = "reject"
)

type ReviewRequest struct {
	Approval   *Request
	Invocation Invocation
	Assessment Assessment
}

type ReviewDecision struct {
	Decision  string
	Comment   string
	ActorType string
	ActorID   string
	Metadata  map[string]any
}

type Reviewer interface {
	Review(context.Context, ReviewRequest) (ReviewDecision, error)
}
