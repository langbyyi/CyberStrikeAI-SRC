package handler

import "encoding/json"

// Keep omission distinct from false without changing the public request shape.
func (r *AddOrUpdateExternalMCPRequest) UnmarshalJSON(data []byte) error {
	type plain AddOrUpdateExternalMCPRequest
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var presence struct {
		Config struct {
			Enable   *bool `json:"external_mcp_enable"`
			Disabled *bool `json:"disabled"`
		} `json:"config"`
	}
	if err := json.Unmarshal(data, &presence); err != nil {
		return err
	}
	*r = AddOrUpdateExternalMCPRequest(decoded)
	r.enable = presence.Config.Enable
	r.disabled = presence.Config.Disabled
	return nil
}

func (r AddOrUpdateExternalMCPRequest) activation(previous, exists bool) bool {
	if r.disabled != nil && *r.disabled {
		return false
	}
	if r.enable != nil {
		return *r.enable
	}
	if r.disabled != nil {
		return !*r.disabled
	}
	if exists {
		return previous
	}
	return true
}
