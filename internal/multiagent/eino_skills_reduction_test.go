package multiagent

import (
	"context"
	"testing"

	"cyberstrike-ai/internal/config"
)

func TestPrepareEinoSkillsStillCreatesReductionBackendWhenSkillsDisabled(t *testing.T) {
	ma := &config.MultiAgentConfig{
		EinoSkills: config.MultiAgentEinoSkillsConfig{Disable: true},
		EinoMiddleware: config.MultiAgentEinoMiddlewareConfig{
			ReductionEnable: true,
		},
	}
	loc, skillMW, fsTools, skillsRoot, err := prepareEinoSkills(context.Background(), "", ma, nil)
	if err != nil {
		t.Fatal(err)
	}
	if loc == nil {
		t.Fatal("reduction backend must exist even when Skills are disabled")
	}
	if skillMW != nil || fsTools || skillsRoot != "" {
		t.Fatalf("Skills unexpectedly enabled: mw=%v fs=%v root=%q", skillMW, fsTools, skillsRoot)
	}
}
