package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"cyberstrike-ai/internal/authctx"
	"cyberstrike-ai/internal/database"
	"go.uber.org/zap"
)

type webshellTargetClientSetter interface {
	SetTargetHTTPClient(func(context.Context, string, *http.Client) (*http.Client, error))
}

func setWebshellTargetClient(t *testing.T, h *WebShellHandler, provider func(context.Context, string, *http.Client) (*http.Client, error)) {
	t.Helper()
	setter, ok := interface{}(h).(webshellTargetClientSetter)
	if !ok {
		t.Fatal("WebShell handler has no target HTTP network provider")
	}
	setter.SetTargetHTTPClient(provider)
}

func TestWebshellNetworkRejectsEveryTargetRequest(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); _, _ = w.Write([]byte(":OSPROBE_%OS%:END")) }))
	defer target.Close()
	db, user, conn, _ := setupWebshellRBACTest(t)
	conn.URL = target.URL
	conn.ProjectID = "trusted-project"
	if err := db.UpdateWebshellConnection(conn); err != nil {
		t.Fatal(err)
	}
	h := NewWebShellHandler(zap.NewNop(), db)
	var calls int
	setWebshellTargetClient(t, h, func(ctx context.Context, project string, base *http.Client) (*http.Client, error) {
		calls++
		if project != "trusted-project" {
			t.Errorf("project=%q, want saved connection project", project)
		}
		if base.Timeout != h.client.Timeout {
			t.Error("lost base timeout")
		}
		return nil, errors.New("synthetic network unavailable")
	})
	for _, test := range []struct {
		name string
		run  func()
	}{
		{"HTTP exec", func() {
			result := performWebshellJSON(user, http.MethodPost, "/api/webshell/exec", map[string]interface{}{"url": target.URL, "connection_id": conn.ID, "project_id": "attacker-project", "command": "id"}, h.Exec)
			if !strings.Contains(result.Body.String(), "synthetic network unavailable") {
				t.Errorf("exec: %s", result.Body.String())
			}
		}},
		{"HTTP file including OS probe", func() {
			result := performWebshellJSON(user, http.MethodPost, "/api/webshell/file", map[string]interface{}{"url": target.URL, "connection_id": conn.ID, "project_id": "attacker-project", "action": "list"}, h.FileOp)
			if !strings.Contains(result.Body.String(), "synthetic network unavailable") {
				t.Errorf("file: %s", result.Body.String())
			}
		}},
		{"MCP exec", func() {
			_, ok, errMsg := h.ExecWithConnection(conn, "id")
			if ok || !strings.Contains(errMsg, "synthetic network unavailable") {
				t.Errorf("exec ok=%v err=%s", ok, errMsg)
			}
		}},
		{"MCP file including OS probe", func() {
			_, ok, errMsg := h.FileOpWithConnection(conn, "list", ".", "", "")
			if ok || !strings.Contains(errMsg, "synthetic network unavailable") {
				t.Errorf("file ok=%v err=%s", ok, errMsg)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) { test.run() })
	}
	if hits.Load() != 0 {
		t.Fatalf("unrouted target received %d requests", hits.Load())
	}
	if calls != 6 {
		t.Fatalf("provider calls=%d, want 6 including both probes", calls)
	}
}

func TestWebshellNetworkForwardsGinPrincipal(t *testing.T) {
	db, user, conn, _ := setupWebshellRBACTest(t)
	conn.ProjectID = "saved-project"
	if err := db.UpdateWebshellConnection(conn); err != nil {
		t.Fatal(err)
	}
	h := NewWebShellHandler(zap.NewNop(), db)
	setWebshellTargetClient(t, h, func(ctx context.Context, project string, base *http.Client) (*http.Client, error) {
		principal, ok := authctx.PrincipalFromContext(ctx)
		if !ok || principal.UserID != user.ID || !principal.HasPermission("webshell:write") {
			t.Errorf("missing Gin principal: %#v", principal)
		}
		if project != conn.ProjectID {
			t.Errorf("project=%q", project)
		}
		return nil, errors.New("synthetic blocked")
	})
	performWebshellJSON(user, http.MethodPost, "/api/webshell/exec", map[string]interface{}{"url": conn.URL, "connection_id": conn.ID, "command": "id"}, h.Exec)
}

func TestWebshellNetworkRejectsUnauthorizedAdHocProject(t *testing.T) {
	db, user, _, _ := setupWebshellRBACTest(t)
	project, err := db.CreateProject(&database.Project{Name: "synthetic project"})
	if err != nil {
		t.Fatal(err)
	}
	h := NewWebShellHandler(zap.NewNop(), db)
	setWebshellTargetClient(t, h, func(context.Context, string, *http.Client) (*http.Client, error) {
		t.Error("provider called before project authorization")
		return nil, errors.New("blocked")
	})
	for _, handler := range []func(){
		func() {
			result := performWebshellJSON(user, http.MethodPost, "/api/webshell/exec", map[string]interface{}{"url": "http://127.0.0.1:1", "project_id": project.ID, "command": "id"}, h.Exec)
			if result.Code != http.StatusForbidden {
				t.Errorf("exec status=%d", result.Code)
			}
		},
		func() {
			result := performWebshellJSON(user, http.MethodPost, "/api/webshell/file", map[string]interface{}{"url": "http://127.0.0.1:1", "project_id": project.ID, "action": "list"}, h.FileOp)
			if result.Code != http.StatusForbidden {
				t.Errorf("file status=%d", result.Code)
			}
		},
	} {
		handler()
	}
}
