package handler

import (
	"strings"

	"cyberstrike-ai/internal/network"
)

func mergeNetworkOpenAPI(spec map[string]interface{}) {
	schemas := spec["components"].(map[string]interface{})["schemas"].(map[string]interface{})
	for name, schema := range networkOpenAPISchemas() {
		schemas[name] = schema
	}
	paths := spec["paths"].(map[string]interface{})
	for path, item := range networkOpenAPIPaths() {
		paths[path] = item
	}
}

func networkObject(properties map[string]interface{}, required ...string) map[string]interface{} {
	schema := map[string]interface{}{"type": "object", "properties": properties}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func networkOpenAPISchemas() map[string]interface{} {
	text := func() map[string]interface{} { return map[string]interface{}{"type": "string"} }
	boolean := func() map[string]interface{} { return map[string]interface{}{"type": "boolean"} }
	version := func() map[string]interface{} {
		return map[string]interface{}{"type": "integer", "format": "int64", "minimum": 0}
	}
	return map[string]interface{}{
		"NetworkError": networkObject(map[string]interface{}{
			"error": map[string]interface{}{"type": "string", "description": "网络 Handler 返回以 network_ 开头的稳定错误码；公共认证中间件可能返回旧式错误文案"}, "message": text(),
		}, "error"),
		"NetworkNode": networkObject(map[string]interface{}{
			"id": text(), "project_id": text(), "address": map[string]interface{}{"type": "string", "description": "脱敏代理 URI，不包含用户名或密码"},
			"scheme": text(), "host": text(), "port": text(), "has_auth": boolean(), "enabled": boolean(), "source": text(), "version": version(),
		}),
		"NetworkScope": networkObject(map[string]interface{}{"targets": stringArraySchema(), "exclude": stringArraySchema()}),
		"NetworkPolicy": networkObject(map[string]interface{}{
			"mode":     map[string]interface{}{"type": "string", "enum": []string{"auto", "fixed_proxy", "fixed_vpn"}},
			"proxy_id": text(), "vpn_profile_id": text(), "targets": stringArraySchema(), "exclude": stringArraySchema(), "dns_servers": stringArraySchema(),
			"version": version(),
		}, "mode", "version"),
		"NetworkPolicyRequest": map[string]interface{}{"allOf": []interface{}{refSchema("NetworkPolicy"), networkObject(map[string]interface{}{
			"proxy_address": map[string]interface{}{"type": "string", "writeOnly": true, "description": "可选带认证代理 URI；保存后仅返回脱敏节点信息"},
		})}},
		"NetworkSource": networkObject(map[string]interface{}{
			"id": map[string]interface{}{"type": "string", "description": "POST 保存时省略为新增；传入已有 ID 为更新"}, "name": text(),
			"kind": map[string]interface{}{"type": "string", "enum": []string{"fofa", "quake", "shodan", "zoomeye", "hunter", "subscription"}}, "query": text(),
			"url":   map[string]interface{}{"type": "string", "description": "订阅 URL；读取时仅显示协议和主机，隐藏路径、查询与片段中的令牌"},
			"limit": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 10000, "default": 100},
		}, "name", "kind"),
		"NetworkSourceProvider": networkObject(map[string]interface{}{"kind": text(), "name": text(), "configured": boolean()}),
		"NetworkEvent": networkObject(map[string]interface{}{
			"at": text(), "kind": text(), "project": text(), "from": text(), "to": text(), "reason": text(),
			"policy_version": map[string]interface{}{"type": "integer", "format": "int64", "minimum": 0},
		}, "at", "kind"),
		"NetworkValidationSettings": networkObject(map[string]interface{}{
			"target":            map[string]interface{}{"type": "string", "default": network.DefaultPoolValidationTarget, "description": "HTTP(S) 验证 URL；初始默认百度，已有配置保留；显式保存为空时跳过验证"},
			"contains":          map[string]interface{}{"type": "string", "maxLength": 65536, "description": "通过代理对验证目标执行 GET；可选响应子串，最多读取 1 MiB 响应正文"},
			"failure_action":    map[string]interface{}{"type": "string", "enum": []string{"keep", "disable", "delete"}, "default": "keep"},
			"failure_threshold": map[string]interface{}{"type": "integer", "minimum": 1, "maximum": 10, "default": 3},
		}),
		"NetworkPoolValidationResult": networkObject(map[string]interface{}{
			"checked": version(), "passed": version(), "failed": version(), "skipped": version(), "disabled": version(), "deleted": version(),
			"observations": map[string]interface{}{"type": "array", "items": refSchema("NetworkObservation")}, "pruning_suppressed": boolean(), "reason": text(),
		}),
		"NetworkPoolValidationRequest": networkObject(map[string]interface{}{"node_ids": map[string]interface{}{"type": "array", "maxItems": 10000, "items": text(), "description": "省略时验证全部共享节点，每批最多 1000 个"}}),
		"NetworkBulkProxyRequest": networkObject(map[string]interface{}{
			"node_ids": map[string]interface{}{"type": "array", "minItems": 1, "maxItems": 1000, "items": text()},
			"action":   map[string]interface{}{"type": "string", "enum": []string{"enable", "disable", "delete"}},
		}, "node_ids", "action"),
		"NetworkBulkProxyResult": networkObject(map[string]interface{}{"updated": version(), "skipped": version()}),
		"NetworkSubscriptionImportRequest": networkObject(map[string]interface{}{
			"content": map[string]interface{}{"type": "string", "writeOnly": true, "maxLength": 2 << 20, "description": "与 urls 二选一；支持明文 URI、Base64、Clash YAML 和 V2Ray JSON"},
			"urls":    map[string]interface{}{"type": "array", "maxItems": 20, "writeOnly": true, "items": text(), "description": "订阅地址会保存为来源后同步；响应不返回凭据 URI"},
			"name":    map[string]interface{}{"type": "string", "maxLength": 200},
		}),
		"NetworkSourceSyncRequest": networkObject(map[string]interface{}{"source_ids": map[string]interface{}{"type": "array", "maxItems": 20, "items": text(), "description": "省略时顺序同步全部来源"}}),
		"NetworkSourceSyncResult":  networkObject(map[string]interface{}{"imported": version(), "skipped": version(), "pages": version(), "failed": version(), "source_ids": stringArraySchema(), "unsupported": map[string]interface{}{"type": "object", "additionalProperties": version()}}),
		"NetworkBinding": networkObject(map[string]interface{}{
			"target": text(), "evidence": text(), "excluded": boolean(), "source": text(), "revision": version(), "updated_at": dateTimeSchema(),
			"scope_basis": text(), "scope_context": text(), "scope_origin": map[string]interface{}{"type": "string", "enum": []string{"discovered", "declared"}}, "scope_state": map[string]interface{}{"type": "string", "enum": []string{"active", "excluded", "needs_reassessment", "out_of_scope"}},
		}),
		"NetworkVPNStatus": networkObject(map[string]interface{}{
			"state":  map[string]interface{}{"type": "string", "enum": []string{"stopped", "connecting", "ready", "reconnecting", "failed"}},
			"reason": text(), "environment": text(), "attempts": version(),
		}),
		"NetworkObservation": networkObject(map[string]interface{}{
			"node_id": text(), "target": text(), "context": text(), "reachable": boolean(), "stage": text(), "http_status": version(),
			"latency_ms": version(), "reason": text(), "observed_at": dateTimeSchema(), "expires_at": dateTimeSchema(),
		}),
		"NetworkJobProgress": networkObject(map[string]interface{}{
			"kind": text(), "stage": text(), "total": version(), "completed": version(), "imported": version(), "skipped": version(), "pages": version(), "passed": version(), "failed": version(), "revision": version(),
		}),
		"NetworkJob": networkObject(map[string]interface{}{
			"id": text(), "state": map[string]interface{}{"type": "string", "enum": []string{"running", "pausing", "paused", "completed", "failed"}},
			"pausable": boolean(), "progress": refSchema("NetworkJobProgress"),
			"result": map[string]interface{}{"description": "任务结果：同步计数、诊断观察数组或 VPN 状态；取消可能返回 failed"}, "error": text(),
		}),
		"NetworkProfileUploadRequest": networkObject(map[string]interface{}{
			"config":      map[string]interface{}{"type": "string", "writeOnly": true, "description": "OpenVPN 配置，最多 2 MiB；仅更新已有配置的账号密码时可省略；不在响应或审计中返回"},
			"credentials": map[string]interface{}{"type": "object", "writeOnly": true, "description": "可选 VPN 账号密码，省略时保留本项目已有凭据；提供时必须成对填写，不能跨项目复用", "properties": map[string]interface{}{"username": map[string]interface{}{"type": "string", "maxLength": 1024, "writeOnly": true}, "password": map[string]interface{}{"type": "string", "maxLength": 4096, "writeOnly": true}}, "required": []string{"username", "password"}},
			"files":       map[string]interface{}{"type": "object", "writeOnly": true, "additionalProperties": text(), "description": "无路径文件名到外置证书/私钥正文；单文件最多 1 MiB，总上传最多 4 MiB"},
			"targets":     stringArraySchema(), "dns_servers": stringArraySchema(), "version": map[string]interface{}{"type": "integer", "format": "int64", "minimum": 0, "description": "可选预期策略版本；不匹配返回 409"},
		}),
		"NetworkNodeUpdateRequest": networkObject(map[string]interface{}{
			"enabled": boolean(), "eligible": boolean(), "address": map[string]interface{}{"type": "string", "writeOnly": true, "description": "可选替换代理 URI；可包含更新后的认证信息"},
		}),
		"NetworkDiagnoseRequest": networkObject(map[string]interface{}{
			"target": text(), "node_ids": map[string]interface{}{"type": "array", "maxItems": 8, "items": text()},
		}, "target"),
		"NetworkAssetRequest": networkObject(map[string]interface{}{"target": text(), "evidence": map[string]interface{}{"type": "string", "maxLength": 4096}, "excluded": boolean()}, "target", "evidence"),
	}
}

func networkOpenAPIPaths() map[string]interface{} {
	object := map[string]interface{}{"type": "object"}
	accepted := networkObject(map[string]interface{}{"job_id": map[string]interface{}{"type": "string"}}, "job_id")
	array := func(name string) map[string]interface{} {
		return map[string]interface{}{"type": "array", "items": refSchema(name)}
	}
	type endpoint struct {
		path, method, id, summary, permission, request, code string
		response                                             map[string]interface{}
	}
	endpoints := []endpoint{
		{"/api/network/proxies", "get", "listNetworkProxies", "列出全局代理池或目标候选", "需要 auth:self；pool_observations 与 Agent 目标诊断相互独立。", "", "200", networkObject(map[string]interface{}{"nodes": array("NetworkNode"), "candidates": map[string]interface{}{"type": "array", "items": networkObject(map[string]interface{}{"node": refSchema("NetworkNode"), "observation": refSchema("NetworkObservation")})}, "sources": array("NetworkSource"), "platform": map[string]interface{}{"type": "string"}, "validation_target": map[string]interface{}{"type": "string"}, "pool_observations": map[string]interface{}{"type": "object", "additionalProperties": refSchema("NetworkObservation")}})},
		{"/api/network/proxies", "post", "importNetworkProxies", "导入全局代理", "需要全局 config:write；输入最多 2 MiB，最多导入 10000 个节点，支持订阅格式。", "", "200", object},
		{"/api/network/proxies/bulk", "post", "bulkUpdateNetworkProxies", "批量管理共享代理节点", "需要全局 config:write；单次最多 1000 节点，跳过私有节点，保护项目引用。", "NetworkBulkProxyRequest", "200", refSchema("NetworkBulkProxyResult")},
		{"/api/network/validation", "get", "getNetworkValidationSettings", "读取全池验证配置", "需要全局 config:write。", "", "200", refSchema("NetworkValidationSettings")},
		{"/api/network/validation", "put", "saveNetworkValidationSettings", "保存全池验证配置", "需要全局 config:write；默认失败保留，配置变化会重置失败次数。", "NetworkValidationSettings", "200", refSchema("NetworkValidationSettings")},
		{"/api/network/validate", "post", "validateNetworkPool", "提交全池验证任务", "需要全局 config:write；20 分钟超时，最多 10000 节点，8 个并发探测；HTTP 错误状态和内容不匹配不会触发清理。", "NetworkPoolValidationRequest", "202", accepted},
		{"/api/network/subscriptions/import", "post", "importNetworkSubscriptions", "导入订阅内容或订阅 URL", "需要全局 config:write；内容最多 2 MiB 或最多 20 个 URL，URL 保存为来源；20 分钟任务。", "NetworkSubscriptionImportRequest", "202", accepted},
		{"/api/network/sources/sync", "post", "syncNetworkSources", "提交批量来源同步任务", "需要全局 config:write；省略 ID 时顺序同步全部来源；20 分钟超时，取消保留部分结果。", "NetworkSourceSyncRequest", "202", accepted},
		{"/api/network/proxies/{node}", "put", "updateNetworkProxy", "编辑或停用代理节点", "需要全局 config:write。", "NetworkNodeUpdateRequest", "200", object},
		{"/api/network/proxies/{node}", "delete", "deleteNetworkProxy", "删除代理节点", "需要全局 config:write；被固定策略引用时拒绝删除。", "", "200", object},
		{"/api/network/export", "get", "exportNetworkProxies", "完整导出全局代理", "需要全局 config:write；导出全部共享节点的完整 URI，包含已配置的账号密码；不导出项目私有节点，响应不缓存。", "", "200", nil},
		{"/api/network/events", "get", "listNetworkEvents", "读取网络切换事件", "需要全局 config:write；环境重建、租约变动与节点退役的操作轨迹，仅含资源 ID 与原因，不含地址或凭据，最多 200 条。", "", "200", networkObject(map[string]interface{}{"events": array("NetworkEvent")})},
		{"/api/network/sources", "get", "listNetworkSources", "列出代理来源", "需要全局 config:write；providers 只返回可用性，不返回全局 API 密钥。", "", "200", networkObject(map[string]interface{}{"sources": array("NetworkSource"), "providers": array("NetworkSourceProvider")})},
		{"/api/network/sources", "post", "saveNetworkSource", "新增或更新代理来源", "需要全局 config:write；传 id 更新已有来源。", "NetworkSource", "200", object},
		{"/api/network/sources/{source}", "delete", "deleteNetworkSource", "删除代理来源", "需要全局 config:write；不删除已经导入的节点。", "", "200", object},
		{"/api/network/sources/{source}/sync", "post", "syncNetworkSource", "提交来源同步任务", "需要全局 config:write；按来源 limit 获取最多 10000 条，20 分钟超时。", "", "202", accepted},
		{"/api/network/jobs", "get", "listNetworkJobs", "读取当前用户未完成的代理池任务", "需要 auth:self；仅返回当前用户可暂停的运行或暂停任务。", "", "200", networkObject(map[string]interface{}{"jobs": array("NetworkJob")})},
		{"/api/network/jobs/{job}", "get", "getNetworkJob", "读取当前用户网络任务", "需要 auth:self；仅任务创建者可读取。", "", "200", refSchema("NetworkJob")},
		{"/api/network/jobs/{job}/pause", "post", "pauseNetworkJob", "暂停代理池任务并保留已完成结果", "仅创建者可暂停；等待当前页或验证批次提交后进入 paused。", "", "200", refSchema("NetworkJob")},
		{"/api/network/jobs/{job}/resume", "post", "resumeNetworkJob", "继续已暂停的代理池任务", "仅创建者可继续；写入任务须仍具有全局 config:write 权限；从下一页或批次继续。", "", "200", refSchema("NetworkJob")},
		{"/api/network/jobs/{job}/cancel", "post", "cancelNetworkJob", "取消当前用户网络任务", "需要 auth:self；仅任务创建者可取消。", "", "200", object},
		{"/api/network/diagnose", "post", "diagnoseNetworkTarget", "提交逐节点目标诊断", "需要 auth:self；显式节点最多 8 个，省略时最多 3 个。", "NetworkDiagnoseRequest", "202", accepted},
		{"/api/projects/{id}/network-policy", "get", "getProjectNetworkPolicy", "读取项目网络策略", "需要 project:read 且可访问该项目。", "", "200", networkObject(map[string]interface{}{"policy": refSchema("NetworkPolicy"), "assigned_proxy": refSchema("NetworkNode"), "scope": refSchema("NetworkScope"), "declared_scope": refSchema("NetworkScope"), "bindings": array("NetworkBinding"), "vpn": refSchema("NetworkVPNStatus"), "vpn_has_auth": map[string]interface{}{"type": "boolean", "description": "只表示已配置 VPN 账号密码，不返回账号或密码"}, "platform": map[string]interface{}{"type": "string"}})},
		{"/api/projects/{id}/network-policy", "put", "saveProjectNetworkPolicy", "保存项目网络策略", "需要 project:write 且可访问该项目；version 必须匹配当前版本。", "NetworkPolicyRequest", "200", networkObject(map[string]interface{}{"policy": refSchema("NetworkPolicy")})},
		{"/api/projects/{id}/vpn-profile", "post", "uploadProjectVPNProfile", "上传项目 OpenVPN 配置与证书", "需要 project:write 且可访问该项目；原子保存配置和策略，不返回证书/私钥。", "NetworkProfileUploadRequest", "200", object},
		{"/api/projects/{id}/vpn/connect", "post", "connectProjectVPN", "提交项目 VPN 连接任务", "需要 project:write 且可访问该项目。", "", "202", accepted},
		{"/api/projects/{id}/vpn/disconnect", "post", "disconnectProjectVPN", "断开项目 VPN", "需要 project:write 且可访问该项目。", "", "200", object},
		{"/api/projects/{id}/vpn/status", "get", "getProjectVPNStatus", "读取项目 VPN 状态", "需要 project:read 且可访问该项目。", "", "200", refSchema("NetworkVPNStatus")},
		{"/api/projects/{id}/network-assets", "post", "bindProjectNetworkAsset", "关联或排除项目网络资产", "需要 project:write 且可访问该项目；关联不能扩大测试范围。", "NetworkAssetRequest", "200", refSchema("NetworkBinding")},
	}
	paths := map[string]interface{}{}
	for _, endpoint := range endpoints {
		responses := jsonResponses(endpoint.code, "请求成功", endpoint.response)
		if endpoint.response == nil {
			responses = map[string]interface{}{"200": map[string]interface{}{"description": "完整代理 URI 列表（管理员操作，包含已配置账号密码）", "content": map[string]interface{}{"text/plain": map[string]interface{}{"schema": map[string]interface{}{"type": "string"}}}}}
		}
		for code, description := range map[string]string{"400": "参数或网络配置无效", "401": "未认证", "403": "权限不足或无权访问项目", "404": "资源不存在", "409": "版本冲突或资源仍被引用", "429": "网络后台任务容量已满"} {
			responses[code] = jsonResponses(code, description, refSchema("NetworkError"))[code]
		}
		operation := map[string]interface{}{"tags": []string{"网络出口"}, "operationId": endpoint.id, "summary": endpoint.summary, "description": endpoint.permission, "responses": responses}
		parameters := []interface{}{}
		for _, name := range []string{"node", "source", "job", "id"} {
			if strings.Contains(endpoint.path, "{"+name+"}") {
				parameters = append(parameters, pathParameter(name))
			}
		}
		if endpoint.path == "/api/network/proxies" && endpoint.method == "get" {
			parameters = append(parameters, queryParameter("target", "string"))
		}
		if len(parameters) > 0 {
			operation["parameters"] = parameters
		}
		if endpoint.request != "" {
			operation["requestBody"] = jsonRequestBody(endpoint.request)
		}
		if endpoint.id == "importNetworkProxies" {
			operation["requestBody"] = map[string]interface{}{"required": true, "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": networkObject(map[string]interface{}{"addresses": map[string]interface{}{"type": "string", "writeOnly": true, "maxLength": 2 << 20, "description": "代理 URI 列表、Base64 订阅、Clash YAML 或 V2Ray JSON；可含认证信息，响应只返回脱敏节点"}}, "addresses")}}}
		}
		item, ok := paths[endpoint.path].(map[string]interface{})
		if !ok {
			item = map[string]interface{}{}
			paths[endpoint.path] = item
		}
		item[endpoint.method] = operation
	}
	return paths
}
