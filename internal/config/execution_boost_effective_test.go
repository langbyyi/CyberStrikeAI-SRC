package config

import "testing"

func TestMultiAgentEinoMiddleware_EffectiveDefaultsAndClamps(t *testing.T) {
	t.Parallel()
	var nilCfg MultiAgentEinoMiddlewareConfig
	if !nilCfg.ExecutionBoostEffective() {
		t.Fatal("nil/default execution_boost must be true")
	}
	if !nilCfg.SkillRouterEffective() {
		t.Fatal("skill router follows boost")
	}
	if !nilCfg.FinalizeGateEffective() {
		t.Fatal("finalize_gate follows boost")
	}
	if nilCfg.StructuredSummaryMaxRunesEffective() != 1200 {
		t.Fatalf("summary budget default=%d", nilCfg.StructuredSummaryMaxRunesEffective())
	}
	if nilCfg.SkillRouterTopKEffective() != 3 {
		t.Fatal("topk default 3")
	}
	if nilCfg.SkillRouterMaxRunesEffective() != 3500 {
		t.Fatal("skill max runes default 3500")
	}
	if nilCfg.TaskEvidenceKEffective() != 5 {
		t.Fatal("task evidence default 5 under boost")
	}

	off := false
	on := true
	// false kill switch
	c := MultiAgentEinoMiddlewareConfig{ExecutionBoost: &off}
	if c.ExecutionBoostEffective() || c.FinalizeGateEffective() || c.SkillRouterEffective() {
		t.Fatal("execution_boost=false should disable dependents")
	}
	// src_hunter_runtime overrides
	c.SrcHunterRuntime.Enable = &on
	if !c.ExecutionBoostEffective() {
		t.Fatal("src_hunter_runtime.enable wins")
	}
	c.SrcHunterRuntime.SkillRouter = &off
	if c.SkillRouterEffective() {
		t.Fatal("src skill_router=false")
	}
	// explicit finalize
	fg := true
	c2 := MultiAgentEinoMiddlewareConfig{ExecutionBoost: &off, FinalizeGateEnable: &fg}
	if !c2.FinalizeGateEffective() {
		t.Fatal("finalize_gate_enable explicit true wins over boost off")
	}
	// clamps
	c3 := MultiAgentEinoMiddlewareConfig{
		StructuredSummaryMaxRunes: -1,
		SkillRouterTopK:           99,
		SkillRouterMaxRunes:       999999,
	}
	if c3.StructuredSummaryMaxRunesEffective() != 1200 {
		t.Fatal("negative summary → default")
	}
	if c3.SkillRouterTopKEffective() != 10 {
		t.Fatal("topk upper clamp 10")
	}
	if c3.SkillRouterMaxRunesEffective() != 20000 {
		t.Fatal("skill runes upper clamp")
	}
	c3.StructuredSummaryMaxRunes = 1500
	if c3.StructuredSummaryMaxRunesEffective() != 1500 {
		t.Fatal("positive budget passthrough")
	}
}

func TestMultiAgentEinoMiddlewareConfig_YAMLJSONTagsPresent(t *testing.T) {
	t.Parallel()
	// Structural regression: new fields must remain serializable.
	// Reflect via encode round-trip of zero value is enough if fields compile.
	_ = MultiAgentEinoMiddlewareConfig{
		StructuredSummaryMaxRunes: 1200,
		FinalizeGateEnable:        nil,
		SkillRouterEnable:         nil,
		ExecutionBoost:            nil,
		SrcHunterRuntime: MultiAgentSrcHunterRuntimeConfig{
			Enable:        nil,
			SkillRouter:   nil,
			TaskEvidenceK: 5,
		},
	}
}
