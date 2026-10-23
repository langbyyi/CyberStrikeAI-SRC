package app

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/network"
	projectctx "cyberstrike-ai/internal/project"
	"cyberstrike-ai/internal/security"
)

type projectNetworkHTTPTransport struct {
	*network.TargetTransport
	validate func() error
}

func (t *projectNetworkHTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	return t.TargetTransport.RoundTrip(request)
}

func networkHTTPClient(db *database.DB, service *network.Service) func(context.Context, string, *http.Client) (*http.Client, error) {
	return func(ctx context.Context, project string, baseline *http.Client) (*http.Client, error) {
		if project != "" {
			if current := mcp.MCPProjectIDFromContext(ctx); current != "" && current != project {
				return nil, fmt.Errorf("target connection belongs to another project")
			}
			ctx = mcp.WithMCPProjectID(ctx, project)
		}
		identity, scope, err := networkContext(ctx, db, service)
		if err != nil {
			return nil, err
		}
		finish, err := security.BeginTaskNetworkOperation(ctx)
		if err != nil {
			return nil, err
		}
		if err = finish(); err != nil {
			return nil, err
		}
		transport := http.DefaultTransport.(*http.Transport)
		if baseline.Transport != nil {
			var ok bool
			transport, ok = baseline.Transport.(*http.Transport)
			if !ok {
				return nil, fmt.Errorf("target HTTP routing requires a standard transport")
			}
		}
		client := *baseline
		client.Transport = &projectNetworkHTTPTransport{
			TargetTransport: service.TargetHTTPTransport(identity, scope, transport.Clone()),
			validate: func() error {
				current, currentScope, err := networkContext(ctx, db, service)
				if err != nil {
					return err
				}
				// A client may outlive a project edit or follow a redirect. Never
				// route a later request with the scope accepted at construction.
				if current.Key() != identity.Key() || !slices.Equal(currentScope.Targets, scope.Targets) || !slices.Equal(currentScope.Exclude, scope.Exclude) {
					return fmt.Errorf("project testing scope changed; recreate the target HTTP client before retrying")
				}
				return nil
			},
		}
		return &client, nil
	}
}

func networkIdentity(ctx context.Context) network.Identity {
	principal, _ := authctx.PrincipalFromContext(ctx)
	identity := network.Identity{UserID: principal.UserID, ProjectID: strings.TrimSpace(mcp.MCPProjectIDFromContext(ctx)), ConversationID: mcp.MCPConversationIDFromContext(ctx), RunnerID: "local"}
	if scope := security.ProcessScopeFromContext(ctx); scope != nil {
		identity.RunID = scope.ID
	}
	return identity
}

func networkContext(ctx context.Context, db *database.DB, s *network.Service) (network.Identity, network.Scope, error) {
	principal, authenticated := authctx.PrincipalFromContext(ctx)
	identity := networkIdentity(ctx)
	if identity.ProjectID == "" && db != nil && identity.ConversationID != "" {
		identity.ProjectID, _ = db.GetConversationProjectID(identity.ConversationID)
	}
	scope := network.Scope{}
	if identity.ProjectID != "" {
		if !authenticated || db == nil || !db.UserCanAccessResource(identity.UserID, principal.ScopeFor("project:read"), "project", identity.ProjectID) {
			return identity, scope, fmt.Errorf("no access to project network context")
		}
		p, err := db.GetProject(identity.ProjectID)
		if err != nil {
			return identity, scope, err
		}
		scope, _, err = projectctx.NetworkScope(p, s, db)
		if err != nil {
			return identity, scope, err
		}
	}
	return identity, scope, nil
}
func networkCommandPreparer(db *database.DB, s *network.Service) func(context.Context, *exec.Cmd) error {
	return func(ctx context.Context, cmd *exec.Cmd) error {
		i, scope, err := networkContext(ctx, db, s)
		if err != nil {
			return err
		}
		return s.PrepareCommand(ctx, i, scope, cmd)
	}
}
func networkTaskCloser(s *network.Service) func(context.Context) {
	return func(ctx context.Context) {
		// Cleanup uses the immutable run identity even after access is revoked
		// or the conversation is moved to a different project.
		s.ReleaseTask(networkIdentity(ctx))
	}
}
func networkResult(value interface{}, err error) (*mcp.ToolResult, error) {
	if err != nil {
		if failed, ok := err.(*network.AcquireError); ok {
			return textResult(mustNetworkJSON(map[string]interface{}{"error": failed.Error(), "attempts": failed.Attempts, "alternatives": failed.Alternatives}), true), nil
		}
		return textResult(err.Error(), true), nil
	}
	return textResult(mustNetworkJSON(value), false), nil
}
func mustNetworkJSON(value interface{}) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return "network response encoding failed"
	}
	return string(raw)
}
func networkStringArgument(args map[string]interface{}, key string, required bool) (string, error) {
	value, exists := args[key]
	if !exists && !required {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("network argument %s must be a string", key)
	}
	text = strings.TrimSpace(text)
	if required && text == "" {
		return "", fmt.Errorf("network argument %s is required", key)
	}
	return text, nil
}
func networkNodeIDs(args map[string]interface{}) ([]string, error) {
	value, exists := args["node_ids"]
	if !exists {
		return nil, nil
	}
	var ids []string
	switch values := value.(type) {
	case []string:
		ids = append(ids, values...)
	case []interface{}:
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("network argument node_ids must contain only non-empty strings")
			}
			ids = append(ids, text)
		}
	default:
		return nil, fmt.Errorf("network argument node_ids must be an array of strings")
	}
	if len(ids) > 8 {
		return nil, fmt.Errorf("network argument node_ids supports at most 8 nodes")
	}
	seen := map[string]bool{}
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, fmt.Errorf("network argument node_ids must contain only non-empty strings")
		}
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	return unique, nil
}

func networkPageInteger(args map[string]interface{}, key string, fallback, minimum, maximum int) (int, error) {
	value, exists := args[key]
	if !exists {
		return fallback, nil
	}
	var number float64
	switch v := value.(type) {
	case float64:
		number = v
	case int:
		number = float64(v)
	case json.Number:
		parsed, err := v.Float64()
		if err != nil {
			return 0, fmt.Errorf("network_status %s must be an integer between %d and %d", key, minimum, maximum)
		}
		number = parsed
	default:
		return 0, fmt.Errorf("network_status %s must be an integer between %d and %d", key, minimum, maximum)
	}
	if math.IsNaN(number) || number < float64(minimum) || number > float64(maximum) || math.Trunc(number) != number {
		return 0, fmt.Errorf("network_status %s must be an integer between %d and %d", key, minimum, maximum)
	}
	return int(number), nil
}

func networkStatus(s *network.Service, identity network.Identity, scope network.Scope, args map[string]interface{}) (interface{}, error) {
	offset, err := networkPageInteger(args, "offset", 0, 0, 2147483647)
	if err != nil {
		return nil, err
	}
	limit, err := networkPageInteger(args, "limit", 10, 1, 20)
	if err != nil {
		return nil, err
	}
	textArgument := func(key, fallback string, allowed []string) (string, error) {
		value, exists := args[key]
		if !exists {
			return fallback, nil
		}
		text, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("network_status %s must be a string", key)
		}
		text = strings.TrimSpace(text)
		if len(allowed) > 0 && !slices.Contains(allowed, text) {
			return "", fmt.Errorf("network_status %s must be one of %s", key, strings.Join(allowed, ", "))
		}
		return text, nil
	}
	target, err := textArgument("target", "", nil)
	if err != nil {
		return nil, err
	}
	status, err := textArgument("status", "all", []string{"all", "enabled", "disabled", "passed", "failed", "untested"})
	if err != nil {
		return nil, err
	}
	protocol, err := textArgument("protocol", "all", []string{"all", "http", "https", "socks5", "socks5h"})
	if err != nil {
		return nil, err
	}
	poolHealth := s.PoolObservations()
	candidates := []network.Candidate{}
	if target != "" {
		candidates, err = s.Candidates(identity, target)
		if err != nil {
			return nil, err
		}
	} else {
		for _, node := range s.Nodes() {
			candidates = append(candidates, network.Candidate{Node: node})
		}
	}
	bestCandidates := append([]network.Candidate{}, candidates...)
	slices.SortFunc(candidates, func(a, b network.Candidate) int { return strings.Compare(a.Node.ID, b.Node.ID) })
	summary := map[string]int{"total": len(candidates), "enabled": 0, "disabled": 0, "passed": 0, "failed": 0, "untested": 0}
	filtered := make([]network.Candidate, 0, len(candidates))
	now := time.Now()
	for _, candidate := range candidates {
		node := candidate.Node
		if node.Enabled {
			summary["enabled"]++
		} else {
			summary["disabled"]++
		}
		observation := candidate.Observation
		if target == "" {
			if health, ok := poolHealth[node.ID]; ok {
				observation = &health
			}
		}
		state := "untested"
		if observation != nil && now.Before(observation.ExpiresAt) {
			if observation.Reachable {
				state = "passed"
			} else {
				state = "failed"
			}
		}
		summary[state]++
		if protocol != "all" && node.Scheme != protocol {
			continue
		}
		if status == "enabled" && !node.Enabled || status == "disabled" && node.Enabled {
			continue
		}
		if status == "passed" && (!node.Enabled || state != "passed") {
			continue
		}
		if (status == "failed" || status == "untested") && state != status {
			continue
		}
		filtered = append(filtered, candidate)
	}
	total := len(filtered)
	eligible := make(map[string]bool, total)
	for _, candidate := range filtered {
		eligible[candidate.Node.ID] = true
	}
	page := filtered[min(offset, total):min(offset+limit, total)]
	nodes := make([]network.Node, 0, len(page))
	healthPage := map[string]network.Observation{}
	for _, candidate := range page {
		nodes = append(nodes, candidate.Node)
		if health, ok := poolHealth[candidate.Node.ID]; ok {
			healthPage[candidate.Node.ID] = health
		}
	}
	policy := s.Policy(identity.ProjectID)
	execution := map[string]interface{}{"project_id": identity.ProjectID, "conversation_id": identity.ConversationID, "run_id": identity.RunID, "runner_id": identity.RunnerID, "status_only": true, "selected_lease": nil, "target_lease": nil, "platform": runtime.GOOS, "command_context_available": identity.ConversationID != "", "selected_lease_matches_target": false, "needs_acquire_for_exec_target": false, "automatic_project_network": policy.Mode != "auto"}
	selected, hasSelected := s.SelectedLease(identity)
	if hasSelected {
		execution["selected_lease"] = selected
	}
	nextAction := "provide_target"
	if policy.Mode != "auto" && len(scope.Targets) == 0 {
		nextAction = "assess_initial_targets"
	}
	var nextCall interface{}
	if target != "" {
		parsed, err := network.ParseTarget(target)
		if err != nil {
			return nil, err
		}
		targetPolicy := s.TargetPolicy(identity, scope, parsed)
		execution["effective_target_mode"] = targetPolicy.Mode
		execution["automatic_project_network"] = targetPolicy.Mode != "auto"
		matching, hasMatching := s.SelectedLeaseForTarget(identity, parsed)
		if hasMatching {
			execution["target_lease"] = matching
		}
		selectedMatches := hasSelected && selected.Mode == "proxy" && (network.Scope{Targets: []string{selected.Target}}).Contains(parsed)
		execution["selected_lease_matches_target"] = selectedMatches
		execution["needs_acquire_for_exec_target"] = targetPolicy.Mode == "auto" && !selectedMatches
		switch {
		case policy.Mode != "auto" && len(scope.Targets) == 0:
			nextAction = "assess_initial_targets"
			execution["needs_acquire_for_exec_target"] = false
		case identity.ProjectID != "" && len(scope.Targets) > 0 && !scope.Contains(parsed):
			nextAction = "target_out_of_scope"
		case identity.ConversationID == "":
			nextAction = "open_task_context"
		case runtime.GOOS != "linux":
			nextAction = "use_linux_runner"
		case targetPolicy.Mode != "auto":
			nextAction = "execute_with_project_policy"
		case selectedMatches:
			nextAction = "execute_local_tool"
		default:
			nextAction = "acquire_target_proxy"
			arguments := map[string]interface{}{"target": target}
			if hasMatching && eligible[matching.NodeID] {
				arguments["node_id"] = matching.NodeID
			} else {
				for _, candidate := range bestCandidates {
					if eligible[candidate.Node.ID] && candidate.Node.Enabled && candidate.Node.ProjectID == "" && (candidate.Observation == nil || !now.Before(candidate.Observation.ExpiresAt) || candidate.Observation.Reachable) {
						arguments["node_id"] = candidate.Node.ID
						break
					}
				}
			}
			if _, exists := arguments["node_id"]; exists {
				nextCall = map[string]interface{}{"tool": "network_acquire", "arguments": arguments}
			} else {
				nextAction = "inspect_proxy_failures"
			}
		}
	}
	sources := s.Sources()
	for index := range sources {
		sources[index].Query = ""
		sources[index].URL = ""
	}
	healthBasis := "pool_validation"
	if target != "" {
		healthBasis = "target_observations"
	}
	result := map[string]interface{}{
		"sources": sources, "policy": policy, "vpn": s.VPNStatus(identity.ProjectID), "bindings": s.Bindings(identity.ProjectID), "scope": scope,
		"nodes": nodes, "total": total, "offset": offset, "limit": limit, "summary": summary, "pool_observations": healthPage, "validation_target": s.ValidationSettings().Target,
		"filters": map[string]string{"status": status, "protocol": protocol, "target": target}, "execution": execution, "health_basis": healthBasis, "next_action": nextAction, "next_call": nextCall,
		"usage": "status 仅查看历史结果，不会激活代理。对当前目标使用 network_diagnose 验证候选，再 network_acquire(target,node_id)；后续 exec 等本地工具按本任务租约分流。项目固定代理/VPN由执行层自动接入，不能用全局池覆盖。结束时 network_release(lease_id)。selected_lease 为 exec 使用的最新租约；target_lease 为当前目标的租约。切换 exec 目标时若 needs_acquire_for_exec_target=true，先按 next_call 重新申请该目标。next_call 仅为调用建议，status 不会执行它。",
	}
	if target != "" {
		result["candidates"] = page
	}
	if offset+len(page) < total {
		result["next_offset"] = offset + len(page)
	}
	return result, nil
}

func registerNetworkTools(server *mcp.Server, s *network.Service, db *database.DB, fetch network.SourceFetch) {
	definitions := []struct {
		name, description string
		required          []string
		properties        map[string]interface{}
		run               func(context.Context, network.Identity, network.Scope, map[string]interface{}) (interface{}, error)
	}{
		{"network_status", "只读查看代理池、验证摘要和当前执行任务的网络租约，不会连接或切换代理。可按 status(all/enabled/disabled/passed/failed/untested)、protocol 筛选；target 表示历史目标验证，未传时使用最近全池验证。默认每页10个，limit最多20个，按 next_offset 翻页，节点按固定ID排序。execution说明当前命令租约是否匹配target；next_call是建议调用，不会自动执行。passed 只包含启用且验证未过期的通过节点。使用前调用 network_diagnose，再 network_acquire 指定 node_id，exec 等本地工具才会在本任务中使用该目标代理；项目固定代理/VPN自动接入。", nil,
			map[string]interface{}{
				"target":   map[string]string{"type": "string"},
				"status":   map[string]interface{}{"type": "string", "enum": []string{"all", "enabled", "disabled", "passed", "failed", "untested"}},
				"protocol": map[string]interface{}{"type": "string", "enum": []string{"all", "http", "https", "socks5", "socks5h"}},
				"offset":   map[string]interface{}{"type": "integer", "minimum": 0, "maximum": 2147483647},
				"limit":    map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 20},
			}, func(ctx context.Context, i network.Identity, scope network.Scope, args map[string]interface{}) (interface{}, error) {
				value, err := networkStatus(s, i, scope, args)
				if err != nil {
					return nil, err
				}
				if i.ProjectID != "" {
					p, err := db.GetProject(i.ProjectID)
					if err != nil {
						return nil, err
					}
					if result, ok := value.(map[string]interface{}); ok {
						currentScope, key, err := projectctx.NetworkScope(p, s)
						if err != nil {
							return nil, err
						}
						result["bindings"] = s.BindingViews(i.ProjectID, currentScope, key)
						result["project_context"] = map[string]interface{}{"description": p.Description, "scope_json": p.ScopeJSON, "testing_specification": p.TestingSpecification, "scope_context": key, "workflow": "Agent 结合当前任务、项目描述和当前测试规范判断初始及后续资产。规则之外的登记须提交 scope_basis 授权依据、evidence 发现证据和本次 scope_context；指纹变化先重读 status 并重判。用户明确给出的通配域名/网段用 scope_origin=declared。页面引用、CNAME、共享 IP 本身不构成授权。用户排除不可覆盖。"}
					}
				}
				return value, nil
			}},
		{"network_diagnose", "验证指定代理对当前目标的连通性。node_ids 最多8个，省略时最多3个；项目固定VPN/代理优先，不允许改用全局池。HTTP拒绝与网络不可达分别记录。", []string{"target"}, map[string]interface{}{"target": map[string]string{"type": "string"}, "node_ids": map[string]interface{}{"type": "array", "maxItems": 8, "items": map[string]string{"type": "string"}}}, func(ctx context.Context, i network.Identity, scope network.Scope, args map[string]interface{}) (interface{}, error) {
			target, err := networkStringArgument(args, "target", true)
			if err != nil {
				return nil, err
			}
			ids, err := networkNodeIDs(args)
			if err != nil {
				return nil, err
			}
			results, err := s.Diagnose(ctx, i, scope, target, ids)
			// A failed probe on one node must not discard the results already collected.
			if err != nil && len(results) > 0 {
				return map[string]interface{}{"results": results, "error": err.Error()}, nil
			}
			return results, err
		}},
		{"network_acquire", "为当前测试任务选定网络出口。可显式传 node_id 选择代理节点；省略时最多尝试3个节点。选定后本会话的本地工具自动使用该目标网络。项目下发的固定代理/VPN不可覆盖。", []string{"target"}, map[string]interface{}{"target": map[string]string{"type": "string"}, "node_id": map[string]string{"type": "string"}}, func(ctx context.Context, i network.Identity, scope network.Scope, args map[string]interface{}) (interface{}, error) {
			target, err := networkStringArgument(args, "target", true)
			if err != nil {
				return nil, err
			}
			node, err := networkStringArgument(args, "node_id", false)
			if err != nil {
				return nil, err
			}
			return s.Acquire(ctx, i, scope, network.AcquireRequest{Target: target, NodeID: node})
		}},
		{"network_release", "释放当前任务申请的网络租约；不能释放其他用户/任务的租约。", []string{"lease_id"}, map[string]interface{}{"lease_id": map[string]string{"type": "string"}}, func(ctx context.Context, i network.Identity, scope network.Scope, args map[string]interface{}) (interface{}, error) {
			id, err := networkStringArgument(args, "lease_id", true)
			if err != nil {
				return nil, err
			}
			err = s.Release(i, id)
			return map[string]bool{"released": err == nil}, err
		}},
		{"network_bind_asset", "在发起目标请求前登记初始或后续发现的项目网络资产。Agent 理解用户任务、项目描述和测试规范中的授权范围；已有规则外的资产必须同时提供 scope_basis（授权依据）和 evidence（发现及关联证据）。scope_origin 默认 discovered，仅登记具体域名/IP；用户明确给出的通配域名或网段使用 declared，并引用用户原文，不能从发现单个后端推断整段授权。系统校验明确路由规则，不推断归属；页面链接/CNAME/共享IP本身不构成授权。不确定时不登记，不能覆盖排除项。后续本地工具自动使用项目VPN/固定代理，范围变更后需重判。", []string{"target", "evidence"}, map[string]interface{}{"target": map[string]string{"type": "string"}, "evidence": map[string]string{"type": "string"}, "scope_basis": map[string]string{"type": "string", "description": "Agent 对当前用户授权及项目规范的判断依据；未命中现有规则时必填。"}, "scope_origin": map[string]interface{}{"type": "string", "enum": []string{"discovered", "declared"}, "description": "discovered=过程中确认的具体资产；declared=用户明确给出的范围，通配域名/网段须引用原始授权。"}}, func(ctx context.Context, i network.Identity, scope network.Scope, args map[string]interface{}) (interface{}, error) {
			target, err := networkStringArgument(args, "target", true)
			if err != nil {
				return nil, err
			}
			evidence, err := networkStringArgument(args, "evidence", true)
			if err != nil {
				return nil, err
			}
			basis, err := networkStringArgument(args, "scope_basis", false)
			if err != nil {
				return nil, err
			}
			origin, err := networkStringArgument(args, "scope_origin", false)
			if err != nil {
				return nil, err
			}
			if origin != "" && origin != "declared" && origin != "discovered" {
				return nil, fmt.Errorf("scope_origin must be discovered or declared")
			}
			if i.ProjectID == "" || db == nil {
				return nil, fmt.Errorf("asset binding requires a project-bound task")
			}
			p, err := db.GetProject(i.ProjectID)
			if err != nil {
				return nil, err
			}
			base, key, err := projectctx.DeclaredNetworkScope(p, s, db)
			if err != nil {
				return nil, err
			}
			if basis != "" {
				expected, err := networkStringArgument(args, "scope_context", true)
				if err != nil {
					return nil, err
				}
				if expected != key {
					return nil, fmt.Errorf("project scope changed; call network_status and reassess the asset before binding")
				}
				return s.BindAssessedAsset(ctx, i.ProjectID, target, evidence, basis, key, s.AssessedScope(i.ProjectID, base, key), origin)
			}
			return s.BindAsset(ctx, i.ProjectID, target, evidence, false, "agent", base)
		}},
		{"network_sync_source", "同步管理员已配置的全局代理来源（FOFA/订阅），有分页和数量预算。搜索结果是否可用由来源配置与验证决定，不能猜测密码。", []string{"source_id"}, map[string]interface{}{"source_id": map[string]string{"type": "string"}}, func(ctx context.Context, i network.Identity, scope network.Scope, args map[string]interface{}) (interface{}, error) {
			id, err := networkStringArgument(args, "source_id", true)
			if err != nil {
				return nil, err
			}
			return s.SyncSource(ctx, id, fetch)
		}},
	}
	for _, def := range definitions {
		d := def
		if d.name == "network_bind_asset" {
			d.properties["scope_context"] = map[string]string{"type": "string", "description": "提供 scope_basis 时必填：先读取 network_status.project_context.scope_context 并原样回传；变化后重读并重新判断。"}
			d.description += " 提供 scope_basis 时必须回传 network_status.project_context.scope_context，防止在范围变更后提交旧判断。"
		}
		schema := map[string]interface{}{"type": "object", "properties": d.properties}
		if len(d.required) > 0 {
			schema["required"] = d.required
		}
		shortDescription := d.description
		if d.name == "network_status" {
			shortDescription = "只读查看代理池和本任务网络状态。传 target 检查租约是否适用于本次 exec 目标，按 next_call 获取下一步调用建议；支持状态/协议筛选和分页。"
		}
		server.RegisterTool(mcp.Tool{Name: d.name, ShortDescription: shortDescription, Description: d.description, InputSchema: schema}, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
			if _, ok := authctx.PrincipalFromContext(ctx); !ok {
				return networkResult(nil, fmt.Errorf("authenticated network context required"))
			}
			i, scope, err := networkContext(ctx, db, s)
			if err != nil {
				return networkResult(nil, err)
			}
			finish, err := security.BeginTaskNetworkOperation(ctx)
			if err != nil {
				return networkResult(nil, err)
			}
			value, err := d.run(ctx, i, scope, args)
			if closed := finish(); closed != nil {
				return networkResult(nil, closed)
			}
			return networkResult(value, err)
		})
	}
}
func networkExternalGuard(db *database.DB, s *network.Service, base mcp.InvocationGuard) mcp.InvocationGuard {
	return func(ctx context.Context, name string, args map[string]interface{}) (context.Context, map[string]interface{}, error) {
		i, _, err := networkContext(ctx, db, s)
		if err != nil {
			return ctx, args, err
		}
		_, selected := s.SelectedLease(i)
		if s.Policy(i.ProjectID).Mode != "auto" || selected {
			return ctx, args, fmt.Errorf("external MCP tool %s has no verified project-network adapter; use local tools on the project runner", name)
		}
		if base != nil {
			return base(ctx, name, args)
		}
		return ctx, args, nil
	}
}
