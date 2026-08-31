package handler

// hitlDecision is the internal audit-model response. The unified approval
// coordinator accepts only approve/reject and never applies argument edits.
type hitlDecision struct {
	Decision string
	Comment  string
}
