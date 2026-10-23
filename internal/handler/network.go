package handler

import (
	"context"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"cyberstrike-ai/internal/audit"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/network"
	projectctx "cyberstrike-ai/internal/project"
	"cyberstrike-ai/internal/security"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const networkDeclaredScopeKey = "cyberstrike.network.declaredScope"
const networkScopeContextKey = "cyberstrike.network.scopeContext"

type networkJob struct {
	Control  *network.JobControl  `json:"-"`
	Progress *network.JobProgress `json:"progress,omitempty"`
	Pausable bool                 `json:"pausable"`
	Writes   bool                 `json:"-"`
	ID       string               `json:"id"`
	State    string               `json:"state"`
	Result   interface{}          `json:"result,omitempty"`
	Error    string               `json:"error,omitempty"`
	Owner    string               `json:"-"`
	Cancel   context.CancelFunc   `json:"-"`
}
type NetworkHandler struct {
	Service   *network.Service
	db        *database.DB
	Fetcher   network.SourceFetch
	Providers func() []network.SourceProvider
	mu        sync.Mutex
	jobs      map[string]*networkJob
	audit     *audit.Service
}

func (h *NetworkHandler) SetAudit(service *audit.Service) { h.audit = service }

func NewNetworkHandler(s *network.Service, db *database.DB) *NetworkHandler {
	return &NetworkHandler{Service: s, db: db, jobs: map[string]*networkJob{}}
}
func (h *NetworkHandler) Register(g *gin.RouterGroup) {
	g = g.Group("", func(c *gin.Context) {
		c.Next()
		if h.audit == nil {
			return
		}
		resourceID := c.Param("id")
		for _, key := range []string{"node", "source", "job"} {
			if resourceID == "" {
				resourceID = c.Param(key)
			}
		}
		if entry, ok := audit.NetworkMutationMeta(c.Request.Method, c.FullPath(), resourceID); ok {
			if c.Writer.Status() >= 400 {
				entry.Result = "failure"
			}
			if session, ok := security.CurrentSession(c); ok {
				entry.Actor = session.Username
				if entry.Actor == "" {
					entry.Actor = session.UserID
				}
			}
			h.audit.Record(c, entry)
		}
	})
	g.GET("/network/proxies", h.list)
	g.POST("/network/proxies", h.importNodes)
	g.POST("/network/proxies/bulk", h.bulkProxies)
	g.GET("/network/validation", h.getValidation)
	g.PUT("/network/validation", h.putValidation)
	g.POST("/network/validate", h.validatePool)
	g.POST("/network/subscriptions/import", h.importSubscriptions)
	g.POST("/network/sources/sync", h.syncSources)
	g.PUT("/network/proxies/:node", h.updateNode)
	g.DELETE("/network/proxies/:node", h.deleteNode)
	g.GET("/network/export", h.export)
	g.GET("/network/events", h.events)
	g.GET("/network/sources", h.sources)
	g.POST("/network/sources", h.saveSource)
	g.DELETE("/network/sources/:source", h.deleteSource)
	g.POST("/network/sources/:source/sync", h.syncSource)
	g.GET("/network/jobs", h.listJobs)
	g.GET("/network/jobs/:job", h.getJob)
	g.POST("/network/jobs/:job/pause", h.pauseJob)
	g.POST("/network/jobs/:job/resume", h.resumeJob)
	g.POST("/network/jobs/:job/cancel", h.cancelJob)
	g.POST("/network/diagnose", h.diagnose)
	g.GET("/projects/:id/network-policy", h.getPolicy)
	g.PUT("/projects/:id/network-policy", h.putPolicy)
	g.POST("/projects/:id/vpn-profile", h.uploadProfile)
	g.POST("/projects/:id/vpn/connect", h.connect)
	g.POST("/projects/:id/vpn/disconnect", h.disconnect)
	g.GET("/projects/:id/vpn/status", h.status)
	g.POST("/projects/:id/network-assets", h.bindAsset)
}
func networkError(c *gin.Context, err error) {
	if strings.Contains(err.Error(), "still referenced") {
		networkFailure(c, http.StatusConflict, err.Error())
		return
	}
	networkFailure(c, http.StatusBadRequest, err.Error())
}
func networkFailure(c *gin.Context, status int, message string) {
	code := map[int]string{
		400: "network_invalid_request", 401: "network_unauthenticated", 403: "network_forbidden",
		404: "network_not_found", 409: "network_conflict", 429: "network_capacity_reached",
	}[status]
	c.AbortWithStatusJSON(status, gin.H{"error": code, "message": message})
}
func networkJSON(c *gin.Context, v interface{}) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 6<<20)
	if err := c.ShouldBindJSON(v); err != nil {
		networkFailure(c, 400, "invalid network request or request exceeds 6 MiB")
		return false
	}
	return true
}
func (h *NetworkHandler) user(c *gin.Context) (security.Session, bool) {
	session, ok := security.CurrentSession(c)
	if !ok {
		networkFailure(c, 401, "authentication required")
	}
	return session, ok
}
func (h *NetworkHandler) admin(c *gin.Context) bool {
	session, ok := h.user(c)
	if !ok {
		return false
	}
	scope := session.PermissionScopes["config:write"]
	if scope == "" {
		scope = session.Scope
	}
	if !session.Permissions["config:write"] || scope != database.RBACScopeAll {
		networkFailure(c, 403, "shared proxy configuration requires global config:write permission")
		return false
	}
	return true
}
func (h *NetworkHandler) project(c *gin.Context, write bool) (network.Scope, bool) {
	session, ok := h.user(c)
	if !ok {
		return network.Scope{}, false
	}
	permission := "project:read"
	if write {
		permission = "project:write"
	}
	scope := session.PermissionScopes[permission]
	if scope == "" {
		scope = session.Scope
	}
	id := c.Param("id")
	if h.db == nil || !session.Permissions[permission] || !h.db.UserCanAccessResource(session.UserID, scope, "project", id) {
		networkFailure(c, 403, "no access to project network")
		return network.Scope{}, false
	}
	project, err := h.db.GetProject(id)
	if err != nil {
		networkFailure(c, 404, "project not found")
		return network.Scope{}, false
	}
	base, key, err := projectctx.DeclaredNetworkScope(project, h.Service, h.db)
	if err != nil {
		networkFailure(c, 400, err.Error())
		return base, false
	}
	c.Set(networkDeclaredScopeKey, base)
	c.Set(networkScopeContextKey, key)
	return h.Service.AssessedScope(id, base, key), true
}
func (h *NetworkHandler) list(c *gin.Context) {
	if _, ok := h.user(c); !ok {
		return
	}
	target := c.Query("target")
	session, _ := h.user(c)
	if target != "" {
		nodes, err := h.Service.Candidates(network.Identity{UserID: session.UserID, RunnerID: "local"}, target)
		if err != nil {
			networkError(c, err)
			return
		}
		c.JSON(200, gin.H{"candidates": nodes, "platform": runtime.GOOS, "validation_target": h.Service.ValidationSettings().Target, "pool_observations": h.Service.PoolObservations()})
		return
	}
	c.JSON(200, gin.H{"nodes": h.Service.Nodes(), "sources": h.Service.Sources(), "platform": runtime.GOOS, "validation_target": h.Service.ValidationSettings().Target, "pool_observations": h.Service.PoolObservations()})
}
func (h *NetworkHandler) importNodes(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	var req struct {
		Addresses string `json:"addresses"`
	}
	if !networkJSON(c, &req) {
		return
	}
	result, err := h.Service.ImportProxyText(req.Addresses, "manual")
	if err != nil {
		networkError(c, err)
		return
	}
	c.JSON(200, result)
}
func (h *NetworkHandler) updateNode(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	var req struct {
		Enabled *bool  `json:"enabled"`
		Address string `json:"address"`
	}
	if !networkJSON(c, &req) {
		return
	}
	old, err := h.Service.ProjectProxy("", c.Param("node"))
	if err != nil {
		networkError(c, err)
		return
	}
	if req.Enabled != nil {
		old.Enabled = *req.Enabled
	}
	updated, err := h.Service.UpdateProxy(old.ID, req.Address, old.Enabled)
	if err != nil {
		networkError(c, err)
		return
	}
	c.JSON(200, gin.H{"node": updated})
}
func (h *NetworkHandler) deleteNode(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	if _, err := h.Service.ProjectProxy("", c.Param("node")); err != nil {
		networkError(c, err)
		return
	}
	if err := h.Service.DeleteProxy(c.Param("node")); err != nil {
		networkError(c, err)
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func (h *NetworkHandler) deleteSource(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	if err := h.Service.DeleteSource(c.Param("source")); err != nil {
		networkError(c, err)
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func (h *NetworkHandler) export(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	lines, err := h.Service.ExportProxies()
	if err != nil {
		networkError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition", "attachment; filename=proxies.txt")
	c.Data(200, "text/plain; charset=utf-8", []byte(strings.Join(lines, "\n")))
}
func (h *NetworkHandler) events(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	c.JSON(200, gin.H{"events": h.Service.Events()})
}
func (h *NetworkHandler) sources(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	providers := []network.SourceProvider{}
	if h.Providers != nil {
		providers = h.Providers()
	}
	c.JSON(200, gin.H{"sources": h.Service.Sources(), "providers": providers})
}
func (h *NetworkHandler) saveSource(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	var source network.Source
	if !networkJSON(c, &source) {
		return
	}
	saved, err := h.Service.SaveSource(source)
	if err != nil {
		networkError(c, err)
		return
	}
	c.JSON(200, gin.H{"id": saved.ID})
}
func (h *NetworkHandler) startJob(c *gin.Context, run func(context.Context) (interface{}, error)) {
	h.startJobWithTimeout(c, 90*time.Second, run)
}
func (h *NetworkHandler) startJobWithTimeout(c *gin.Context, timeout time.Duration, run func(context.Context) (interface{}, error)) {
	h.startManagedJob(c, timeout, false, false, run)
}
func (h *NetworkHandler) startPoolJob(c *gin.Context, timeout time.Duration, writes bool, run func(context.Context) (interface{}, error)) {
	h.startManagedJob(c, timeout, true, writes, run)
}
func (h *NetworkHandler) startManagedJob(c *gin.Context, timeout time.Duration, pausable, writes bool, run func(context.Context) (interface{}, error)) {
	session, ok := h.user(c)
	if !ok {
		return
	}
	h.mu.Lock()
	if len(h.jobs) >= 128 {
		for id, job := range h.jobs {
			if job.State != "running" {
				delete(h.jobs, id)
			}
		}
	}
	active := 0
	for _, job := range h.jobs {
		if job.State == "running" {
			active++
		}
	}
	if active >= 4 {
		h.mu.Unlock()
		networkFailure(c, 429, "network job capacity reached")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	job := &networkJob{ID: uuid.NewString(), State: "running", Owner: session.UserID, Cancel: cancel, Pausable: pausable, Writes: writes}
	if pausable {
		cancel()
		ctx, cancel = context.WithCancel(context.Background())
		job.Cancel = cancel
		job.Control = network.NewJobControl()
		ctx = network.WithJobControl(ctx, job.Control)
		go job.Control.WatchBudget(ctx, timeout, cancel)
	}
	h.jobs[job.ID] = job
	h.mu.Unlock()
	go func() {
		result, err := run(ctx)
		cancel()
		h.mu.Lock()
		defer h.mu.Unlock()
		job.Result = result
		if err != nil {
			job.State = "failed"
			job.Error = err.Error()
		} else {
			job.State = "completed"
		}
	}()
	c.JSON(202, gin.H{"job_id": job.ID})
}
func (h *NetworkHandler) syncSource(c *gin.Context) {
	if !h.admin(c) {
		return
	}
	id := c.Param("source")
	h.startPoolJob(c, 20*time.Minute, true, func(ctx context.Context) (interface{}, error) { return h.Service.SyncSource(ctx, id, h.Fetcher) })
}
func (h *NetworkHandler) getJob(c *gin.Context) {
	session, ok := h.user(c)
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	job := h.jobs[c.Param("job")]
	if job == nil || job.Owner != session.UserID {
		networkFailure(c, 404, "network job not found")
		return
	}
	c.JSON(200, networkJobView(job))
}
func networkJobView(job *networkJob) networkJob {
	view := *job
	if job.Control != nil {
		state, progress := job.Control.Snapshot()
		view.Progress = &progress
		if view.State == "running" {
			view.State = state
		}
	}
	return view
}
func (h *NetworkHandler) listJobs(c *gin.Context) {
	session, ok := h.user(c)
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	jobs := []networkJob{}
	for _, job := range h.jobs {
		if job.Owner == session.UserID && job.Control != nil && job.State == "running" {
			jobs = append(jobs, networkJobView(job))
		}
	}
	c.JSON(200, gin.H{"jobs": jobs})
}
func (h *NetworkHandler) pauseJob(c *gin.Context)  { h.changeJobPause(c, true) }
func (h *NetworkHandler) resumeJob(c *gin.Context) { h.changeJobPause(c, false) }
func (h *NetworkHandler) changeJobPause(c *gin.Context, paused bool) {
	session, ok := h.user(c)
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	job := h.jobs[c.Param("job")]
	if job == nil || job.Owner != session.UserID {
		networkFailure(c, 404, "network job not found")
		return
	}
	if job.Control == nil || job.State != "running" {
		networkFailure(c, 409, "network job cannot be paused or resumed")
		return
	}
	if !paused && job.Writes && !h.admin(c) {
		return
	}
	if paused {
		job.Control.Pause()
	} else {
		job.Control.Resume()
	}
	c.JSON(200, networkJobView(job))
}
func (h *NetworkHandler) cancelJob(c *gin.Context) {
	session, ok := h.user(c)
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	job := h.jobs[c.Param("job")]
	if job == nil || job.Owner != session.UserID {
		networkFailure(c, 404, "network job not found")
		return
	}
	job.Cancel()
	c.JSON(200, gin.H{"ok": true})
}
func (h *NetworkHandler) diagnose(c *gin.Context) {
	session, ok := h.user(c)
	if !ok {
		return
	}
	var req struct {
		Target  string   `json:"target"`
		NodeIDs []string `json:"node_ids"`
	}
	if !networkJSON(c, &req) {
		return
	}
	h.startPoolJob(c, 90*time.Second, false, func(ctx context.Context) (interface{}, error) {
		return h.Service.Diagnose(ctx, network.Identity{UserID: session.UserID, RunnerID: "local"}, network.Scope{}, req.Target, req.NodeIDs)
	})
}
func (h *NetworkHandler) getPolicy(c *gin.Context) {
	scope, ok := h.project(c, false)
	if !ok {
		return
	}
	id := c.Param("id")
	p := h.Service.Policy(id)
	assigned, _ := h.Service.ProjectProxy(id, p.ProxyID)
	declared, _ := c.Get(networkDeclaredScopeKey)
	c.JSON(200, gin.H{"policy": p, "assigned_proxy": assigned, "scope": scope, "declared_scope": declared, "bindings": h.Service.BindingViews(id, scope, c.GetString(networkScopeContextKey)), "vpn": h.Service.VPNStatus(id), "vpn_has_auth": h.Service.ProfileHasAuth(id), "platform": runtime.GOOS})
}
func (h *NetworkHandler) putPolicy(c *gin.Context) {
	scope, ok := h.project(c, true)
	if !ok {
		return
	}
	var req struct {
		network.Policy
		ProxyAddress string `json:"proxy_address"`
	}
	if !networkJSON(c, &req) {
		return
	}
	p := req.Policy
	if err := scope.ValidateSubset(p.Targets); err != nil {
		networkError(c, err)
		return
	}
	if p.Mode == "fixed_proxy" {
		if strings.TrimSpace(req.ProxyAddress) != "" {
			node, err := h.Service.AddProjectProxy(c.Param("id"), req.ProxyAddress)
			if err != nil {
				networkError(c, err)
				return
			}
			p.ProxyID = node.ID
		}
		if _, err := h.Service.ProjectProxy(c.Param("id"), p.ProxyID); err != nil {
			networkError(c, err)
			return
		}
	}
	saved, err := h.Service.SavePolicy(c.Param("id"), p, p.Version)
	if err != nil {
		if strings.Contains(err.Error(), "conflict") {
			networkFailure(c, 409, err.Error())
		} else {
			networkError(c, err)
		}
		return
	}
	c.JSON(200, gin.H{"policy": saved})
}
func (h *NetworkHandler) uploadProfile(c *gin.Context) {
	scope, ok := h.project(c, true)
	if !ok {
		return
	}
	var req struct {
		Config      string                  `json:"config"`
		Files       map[string]string       `json:"files"`
		Targets     []string                `json:"targets"`
		DNSServers  []string                `json:"dns_servers"`
		Version     *int64                  `json:"version"`
		Credentials *network.VPNCredentials `json:"credentials"`
	}
	if !networkJSON(c, &req) {
		return
	}
	if err := scope.ValidateSubset(req.Targets); err != nil {
		networkError(c, err)
		return
	}
	id := c.Param("id")
	version := h.Service.Policy(id).Version
	if req.Version != nil {
		version = *req.Version
	}
	var credentials []network.VPNCredentials
	if req.Credentials != nil {
		credentials = append(credentials, *req.Credentials)
	}
	profile, err := h.Service.SaveProjectProfile(id, req.Config, req.Files, req.Targets, req.DNSServers, version, credentials...)
	if err != nil {
		if strings.Contains(err.Error(), "conflict") {
			networkFailure(c, 409, err.Error())
			return
		}
		networkError(c, err)
		return
	}
	c.JSON(200, gin.H{"id": profile.ID, "project_id": id, "version": version + 1})
}
func (h *NetworkHandler) connect(c *gin.Context) {
	_, ok := h.project(c, true)
	if !ok {
		return
	}
	id := c.Param("id")
	h.startJob(c, func(ctx context.Context) (interface{}, error) {
		project, err := h.db.GetProject(id)
		if err != nil {
			return nil, err
		}
		scope, _, err := projectctx.NetworkScope(project, h.Service, h.db)
		if err != nil {
			return nil, err
		}
		state := h.Service.VPNStatus(id)
		if state.State == "failed" || state.State == "stopped" {
			_ = h.Service.DisconnectVPN(id)
		}
		return h.Service.ConnectVPN(ctx, id, scope)
	})
}
func (h *NetworkHandler) disconnect(c *gin.Context) {
	if _, ok := h.project(c, true); !ok {
		return
	}
	if err := h.Service.DisconnectVPN(c.Param("id")); err != nil {
		networkError(c, err)
		return
	}
	c.JSON(200, gin.H{"ok": true})
}
func (h *NetworkHandler) status(c *gin.Context) {
	if _, ok := h.project(c, false); !ok {
		return
	}
	c.JSON(200, h.Service.VPNStatus(c.Param("id")))
}
func (h *NetworkHandler) bindAsset(c *gin.Context) {
	scope, ok := h.project(c, true)
	if !ok {
		return
	}
	var req struct {
		Target   string `json:"target"`
		Evidence string `json:"evidence"`
		Excluded bool   `json:"excluded"`
	}
	if !networkJSON(c, &req) {
		return
	}
	if !req.Excluded {
		if declared, exists := c.Get(networkDeclaredScopeKey); exists {
			if base, valid := declared.(network.Scope); valid {
				scope = base
			}
		}
	}
	binding, err := h.Service.BindAsset(c.Request.Context(), c.Param("id"), req.Target, req.Evidence, req.Excluded, "user", scope)
	if err != nil {
		networkError(c, err)
		return
	}
	c.JSON(200, binding)
}
func (h *NetworkHandler) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, job := range h.jobs {
		job.Cancel()
	}
}
