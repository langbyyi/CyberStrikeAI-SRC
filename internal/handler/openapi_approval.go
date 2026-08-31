package handler

func mergeUnifiedApprovalOpenAPI(spec map[string]interface{}) {
	components := spec["components"].(map[string]interface{})
	schemas := components["schemas"].(map[string]interface{})
	for name, schema := range unifiedApprovalSchemas() {
		schemas[name] = schema
	}
	paths := spec["paths"].(map[string]interface{})
	for path, item := range unifiedApprovalPaths() {
		paths[path] = item
	}
}

func unifiedApprovalSchemas() map[string]interface{} {
	trigger := map[string]interface{}{
		"type": "object", "required": []string{"enabled"},
		"properties": map[string]interface{}{
			"enabled":       map[string]interface{}{"type": "boolean"},
			"toolWhitelist": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
		},
	}
	matcher := map[string]interface{}{
		"type": "object", "properties": map[string]interface{}{
			"tools":                stringArraySchema(),
			"httpMethods":          stringArraySchema(),
			"pathPatterns":         stringArraySchema(),
			"textPatterns":         stringArraySchema(),
			"argumentPatterns":     map[string]interface{}{"type": "object", "additionalProperties": stringArraySchema()},
			"requireHttpTransport": map[string]interface{}{"type": "boolean"},
		},
	}
	return map[string]interface{}{
		"ApprovalTriggerConfig": trigger,
		"ApprovalConfig": map[string]interface{}{
			"type": "object", "required": []string{"reviewer", "timeoutSeconds", "toolApproval", "dangerousAction"},
			"properties": map[string]interface{}{
				"reviewer":        map[string]interface{}{"type": "string", "enum": []string{"human", "agent"}},
				"timeoutSeconds":  map[string]interface{}{"type": "integer", "minimum": 1},
				"toolApproval":    refSchema("ApprovalTriggerConfig"),
				"dangerousAction": refSchema("ApprovalTriggerConfig"),
			},
		},
		"ApprovalDecision": map[string]interface{}{
			"type": "object", "properties": map[string]interface{}{
				"id": map[string]interface{}{"type": "string"}, "approvalId": map[string]interface{}{"type": "string"},
				"stage": map[string]interface{}{"type": "string"}, "actorType": map[string]interface{}{"type": "string", "enum": []string{"human", "agent", "system"}},
				"actorId": map[string]interface{}{"type": "string"}, "decision": map[string]interface{}{"type": "string", "enum": []string{"approve", "reject"}},
				"comment": map[string]interface{}{"type": "string"}, "createdAt": dateTimeSchema(),
			},
		},
		"ApprovalRequest": map[string]interface{}{
			"type": "object", "properties": map[string]interface{}{
				"id": map[string]interface{}{"type": "string"}, "invocationId": map[string]interface{}{"type": "string"}, "invocationHash": map[string]interface{}{"type": "string"},
				"source": map[string]interface{}{"type": "string"}, "conversationId": map[string]interface{}{"type": "string"},
				"messageId": map[string]interface{}{"type": "string"}, "projectId": map[string]interface{}{"type": "string"}, "requesterUserId": map[string]interface{}{"type": "string"},
				"toolName": map[string]interface{}{"type": "string"}, "toolCallId": map[string]interface{}{"type": "string"},
				"arguments": map[string]interface{}{"type": "object", "additionalProperties": true},
				"riskLevel": map[string]interface{}{"type": "string"}, "triggerSources": stringArraySchema(),
				"matchedPolicies": stringArraySchema(), "reviewer": map[string]interface{}{"type": "string", "enum": []string{"human", "agent"}},
				"stage": map[string]interface{}{"type": "string"}, "status": map[string]interface{}{"type": "string", "enum": []string{"pending_agent", "pending_human", "approved", "rejected", "expired", "cancelled", "executing", "succeeded", "failed"}},
				"expiresAt": dateTimeSchema(), "executionId": map[string]interface{}{"type": "string"},
				"executionSummary": map[string]interface{}{"type": "string"}, "decisions": map[string]interface{}{"type": "array", "items": refSchema("ApprovalDecision")},
				"createdAt": dateTimeSchema(), "updatedAt": dateTimeSchema(),
			},
		},
		"ApprovalDecisionRequest": map[string]interface{}{
			"type": "object", "required": []string{"decision"},
			"properties": map[string]interface{}{
				"decision": map[string]interface{}{"type": "string", "enum": []string{"approve", "reject"}},
				"comment":  map[string]interface{}{"type": "string"},
			},
		},
		"ApprovalRule": map[string]interface{}{
			"type": "object", "required": []string{"id", "enabled", "priority", "riskLevel", "matcher"},
			"properties": map[string]interface{}{
				"id":      map[string]interface{}{"type": "string"},
				"enabled": map[string]interface{}{"type": "boolean"}, "priority": map[string]interface{}{"type": "integer"},
				"riskLevel": map[string]interface{}{"type": "string", "enum": []string{"low", "medium", "high", "critical", "prohibited"}},
				"matcher":   matcher,
			},
		},
		"ApprovalLedgerEvent": map[string]interface{}{
			"type": "object", "properties": map[string]interface{}{
				"id": map[string]interface{}{"type": "string"}, "eventType": map[string]interface{}{"type": "string", "enum": []string{"decision", "execution"}},
				"invocationId": map[string]interface{}{"type": "string"}, "approvalId": map[string]interface{}{"type": "string"},
				"source": map[string]interface{}{"type": "string"}, "conversationId": map[string]interface{}{"type": "string"},
				"projectId": map[string]interface{}{"type": "string"}, "requesterUserId": map[string]interface{}{"type": "string"},
				"toolName": map[string]interface{}{"type": "string"}, "toolCallId": map[string]interface{}{"type": "string"},
				"enforcement": map[string]interface{}{"type": "string", "enum": []string{"allow", "deny"}},
				"reviewer":    map[string]interface{}{"type": "string"}, "riskLevel": map[string]interface{}{"type": "string"},
				"argsHash": map[string]interface{}{"type": "string"}, "actorType": map[string]interface{}{"type": "string"},
				"actorId": map[string]interface{}{"type": "string"}, "matchedRules": stringArraySchema(),
				"comment": map[string]interface{}{"type": "string"}, "success": map[string]interface{}{"type": "boolean"},
				"summary": map[string]interface{}{"type": "string"}, "createdAt": dateTimeSchema(),
			},
		},
	}
}

func unifiedApprovalPaths() map[string]interface{} {
	readDescription := "需要 approval:read 权限。"
	policyDescription := "需要 approval:policy:write 权限。"
	return map[string]interface{}{
		"/api/approvals": map[string]interface{}{"get": map[string]interface{}{
			"tags": []string{"人机协同"}, "summary": "分页查询统一审批单", "description": readDescription,
			"parameters": approvalListParameters(), "responses": jsonResponses("200", "查询成功", map[string]interface{}{"type": "object", "properties": map[string]interface{}{"items": map[string]interface{}{"type": "array", "items": refSchema("ApprovalRequest")}, "total": map[string]interface{}{"type": "integer"}, "limit": map[string]interface{}{"type": "integer"}, "offset": map[string]interface{}{"type": "integer"}}}),
		}},
		"/api/approvals/ledger": map[string]interface{}{"get": map[string]interface{}{
			"tags": []string{"人机协同"}, "summary": "查询审批台账", "description": readDescription,
			"parameters": []interface{}{queryParameter("invocationId", "string"), queryParameter("from", "string"), queryParameter("to", "string"), queryParameter("limit", "integer")},
			"responses": jsonResponses("200", "查询成功", map[string]interface{}{"type": "object", "properties": map[string]interface{}{
				"items": map[string]interface{}{"type": "array", "items": refSchema("ApprovalLedgerEvent")},
				"total": map[string]interface{}{"type": "integer"}, "limit": map[string]interface{}{"type": "integer"},
			}}),
		}},
		"/api/approvals/{id}": map[string]interface{}{"get": map[string]interface{}{
			"tags": []string{"人机协同"}, "summary": "获取审批单详情", "description": readDescription,
			"parameters": []interface{}{pathParameter("id")}, "responses": jsonResponses("200", "查询成功", refSchema("ApprovalRequest")),
		}},
		"/api/approvals/{id}/decision": map[string]interface{}{"post": map[string]interface{}{
			"tags": []string{"人机协同"}, "summary": "人工批准或拒绝审批单", "description": "需要 approval:decide 权限；仅在线的 pending_human 审批单可裁决。",
			"parameters": []interface{}{pathParameter("id")}, "requestBody": jsonRequestBody("ApprovalDecisionRequest"),
			"responses": map[string]interface{}{"200": map[string]interface{}{"description": "裁决已提交"}, "400": map[string]interface{}{"description": "决策格式错误"}, "409": map[string]interface{}{"description": "审批已结束、过期或运行时不可用"}},
		}},
		"/api/approval-config": map[string]interface{}{
			"get": map[string]interface{}{"tags": []string{"人机协同"}, "summary": "读取全局审批配置", "description": readDescription, "responses": jsonResponses("200", "查询成功", refSchema("ApprovalConfig"))},
			"put": map[string]interface{}{"tags": []string{"人机协同"}, "summary": "更新全局审批配置", "description": policyDescription, "requestBody": jsonRequestBody("ApprovalConfig"), "responses": jsonResponses("200", "更新成功", refSchema("ApprovalConfig"))},
		},
		"/api/approval-rules": map[string]interface{}{
			"get":    map[string]interface{}{"tags": []string{"人机协同"}, "summary": "列出危险操作规则", "description": readDescription, "responses": jsonResponses("200", "查询成功", map[string]interface{}{"type": "object", "properties": map[string]interface{}{"items": map[string]interface{}{"type": "array", "items": refSchema("ApprovalRule")}}})},
			"post":   map[string]interface{}{"tags": []string{"人机协同"}, "summary": "发布危险操作规则", "description": policyDescription, "requestBody": jsonRequestBody("ApprovalRule"), "responses": jsonResponses("201", "发布成功", refSchema("ApprovalRule"))},
			"delete": map[string]interface{}{"tags": []string{"人机协同"}, "summary": "删除危险操作规则", "description": policyDescription, "requestBody": map[string]interface{}{"required": true, "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": map[string]interface{}{"type": "object", "required": []string{"id"}, "properties": map[string]interface{}{"id": map[string]interface{}{"type": "string"}}}}}}, "responses": map[string]interface{}{"200": map[string]interface{}{"description": "删除成功"}, "404": map[string]interface{}{"description": "规则不存在"}}},
		},
	}
}

func approvalListParameters() []interface{} {
	parameters := []interface{}{}
	for _, name := range []string{"conversationId", "projectId", "requesterUserId", "status", "q", "decision", "actorType", "terminal", "limit", "offset"} {
		typeName := "string"
		if name == "limit" || name == "offset" {
			typeName = "integer"
		}
		parameters = append(parameters, queryParameter(name, typeName))
	}
	return parameters
}

func refSchema(name string) map[string]interface{} {
	return map[string]interface{}{"$ref": "#/components/schemas/" + name}
}
func stringArraySchema() map[string]interface{} {
	return map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}
}
func dateTimeSchema() map[string]interface{} {
	return map[string]interface{}{"type": "string", "format": "date-time"}
}
func pathParameter(name string) map[string]interface{} {
	return map[string]interface{}{"name": name, "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}}
}
func queryParameter(name, kind string) map[string]interface{} {
	return map[string]interface{}{"name": name, "in": "query", "schema": map[string]interface{}{"type": kind}}
}
func jsonRequestBody(schema string) map[string]interface{} {
	return map[string]interface{}{"required": true, "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": refSchema(schema)}}}
}
func jsonResponses(code, description string, schema map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{code: map[string]interface{}{"description": description, "content": map[string]interface{}{"application/json": map[string]interface{}{"schema": schema}}}}
}
