package audit

// RetentionDays returns configured retention; 0 means keep forever.
func (s *Service) RetentionDays() int {
	if s == nil || s.cfg == nil {
		return 0
	}
	return s.cfg.Audit.RetentionDaysEffective()
}

// NetworkMutationMeta deliberately accepts route templates, never request bodies or URLs.
// Proxy credentials and VPN material must not enter the platform audit log.
func NetworkMutationMeta(method, route, resourceID string) (Entry, bool) {
	type metadata struct{ action, resource, message string }
	var meta metadata
	switch method + " " + route {
	case "GET /api/network/export":
		meta = metadata{"proxy_export", "network_proxy", "导出全局代理列表"}
	case "POST /api/network/proxies":
		meta = metadata{"proxy_import", "network_proxy", "导入代理节点"}
	case "POST /api/network/proxies/bulk":
		meta = metadata{"proxy_bulk_update", "network_proxy", "批量更新代理节点"}
	case "PUT /api/network/validation":
		meta = metadata{"validation_update", "network_proxy", "更新代理池验证配置"}
	case "POST /api/network/validate":
		meta = metadata{"pool_validate", "network_job", "提交代理池验证任务"}
	case "POST /api/network/subscriptions/import":
		meta = metadata{"subscription_import", "network_source", "提交订阅导入任务"}
	case "POST /api/network/sources/sync":
		meta = metadata{"sources_sync", "network_source", "提交批量来源同步任务"}
	case "PUT /api/network/proxies/:node":
		meta = metadata{"proxy_update", "network_proxy", "更新代理节点"}
	case "DELETE /api/network/proxies/:node":
		meta = metadata{"proxy_delete", "network_proxy", "删除代理节点"}
	case "POST /api/network/sources":
		meta = metadata{"source_save", "network_source", "保存代理来源"}
	case "DELETE /api/network/sources/:source":
		meta = metadata{"source_delete", "network_source", "删除代理来源"}
	case "POST /api/network/sources/:source/sync":
		meta = metadata{"source_sync", "network_source", "提交代理来源同步任务"}
	case "POST /api/network/jobs/:job/pause":
		meta = metadata{"job_pause", "network_job", "请求暂停网络任务"}
	case "POST /api/network/jobs/:job/resume":
		meta = metadata{"job_resume", "network_job", "继续网络任务"}
	case "POST /api/network/jobs/:job/cancel":
		meta = metadata{"job_cancel", "network_job", "请求取消网络任务"}
	case "POST /api/network/diagnose":
		meta = metadata{"diagnose", "network_job", "提交网络诊断任务"}
	case "PUT /api/projects/:id/network-policy":
		meta = metadata{"policy_update", "project", "更新项目网络策略"}
	case "POST /api/projects/:id/vpn-profile":
		meta = metadata{"profile_upload", "project", "上传项目 VPN 配置"}
	case "POST /api/projects/:id/vpn/connect":
		meta = metadata{"vpn_connect", "project", "提交项目 VPN 连接任务"}
	case "POST /api/projects/:id/vpn/disconnect":
		meta = metadata{"vpn_disconnect", "project", "断开项目 VPN"}
	case "POST /api/projects/:id/network-assets":
		meta = metadata{"asset_bind", "project", "更新项目网络资产关联"}
	default:
		return Entry{}, false
	}
	return Entry{Category: "network", Action: meta.action, ResourceType: meta.resource, ResourceID: resourceID,
		Message: meta.message, Detail: map[string]interface{}{"method": method, "route": route}}, true
}
