package network

// SourceProvider exposes availability, never provider credentials.
type SourceProvider struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
}
