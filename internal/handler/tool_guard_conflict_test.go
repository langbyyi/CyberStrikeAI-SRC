package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/toolguard"

	"github.com/gin-gonic/gin"
)

func toolGuardVersionRequest(t *testing.T, h *ConfigHandler, body interface{}, etag string) *httptest.ResponseRecorder {
	t.Helper()
	return toolGuardRequest(t, func(c *gin.Context) {
		c.Request.Header.Set("If-Match", etag)
		h.UpdateToolGuard(c)
	}, body)
}

func toolGuardUpdateRequest(t *testing.T, h *ConfigHandler, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	etag := toolGuardRequest(t, h.GetToolGuard, nil).Header().Get("ETag")
	return toolGuardVersionRequest(t, h, body, etag)
}

func TestToolGuardConcurrentSameVersionHasOneWinner(t *testing.T) {
	h := newToolGuardTestHandler(t)
	read := toolGuardRequest(t, h.GetToolGuard, nil)
	etag := read.Header().Get("ETag")
	if etag == "" || read.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("GET omitted version or cache protection")
	}
	const users = 12
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, users)
	for i := 0; i < users; i++ {
		go func(i int) {
			cfg := toolguard.DefaultConfig()
			cfg.Rules[0].Message = fmt.Sprintf("user-%d", i)
			<-start
			results <- toolGuardVersionRequest(t, h, cfg, etag)
		}(i)
	}
	close(start)
	var winner toolguard.Config
	var winnerVersion string
	wins := 0
	for i := 0; i < users; i++ {
		w := <-results
		switch w.Code {
		case http.StatusOK:
			wins++
			if err := json.Unmarshal(w.Body.Bytes(), &winner); err != nil {
				t.Fatal(err)
			}
			winnerVersion = w.Header().Get("ETag")
			if winnerVersion == "" || winnerVersion == etag {
				t.Fatal("successful save did not advance the version")
			}
		case http.StatusConflict:
			if !strings.Contains(w.Body.String(), "tool_guard_conflict") {
				t.Fatal(w.Body.String())
			}
		default:
			t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
		}
	}
	if wins != 1 {
		t.Fatalf("got %d successful saves", wins)
	}
	loaded, err := config.Load(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(winner, loaded.EffectiveToolGuard()) || !reflect.DeepEqual(winner, h.toolGuard.Config()) {
		t.Fatal("a losing request overwrote the winner")
	}
	if read := toolGuardRequest(t, h.GetToolGuard, nil); read.Header().Get("ETag") != winnerVersion {
		t.Fatal("save receipt and GET version differ")
	}
	// An old draft still fails even when its HTTP request is no longer concurrent.
	winner.Enabled = false
	if w := toolGuardVersionRequest(t, h, winner, etag); w.Code != http.StatusConflict {
		t.Fatal("sequential stale draft was accepted")
	}
	if w := toolGuardVersionRequest(t, h, winner, winnerVersion); w.Code != http.StatusOK {
		t.Fatal("fresh version could not save", w.Body.String())
	}
}

func TestToolGuardPreconditionsAndNoOpFence(t *testing.T) {
	h := newToolGuardTestHandler(t)
	cfg := toolguard.DefaultConfig()
	before, _ := os.ReadFile(h.configPath)
	for _, etag := range []string{"", "*", `W/"old"`, `"unknown"`} {
		w := toolGuardVersionRequest(t, h, cfg, etag)
		want := http.StatusConflict
		if etag == "" {
			want = http.StatusPreconditionRequired
		}
		if w.Code != want {
			t.Fatalf("got %d, want %d", w.Code, want)
		}
	}
	after, _ := os.ReadFile(h.configPath)
	if !bytes.Equal(before, after) || h.config.ToolGuard != nil || !reflect.DeepEqual(cfg, h.toolGuard.Config()) {
		t.Fatal("rejected request changed file or runtime")
	}
	etag := toolGuardRequest(t, h.GetToolGuard, nil).Header().Get("ETag")
	if w := toolGuardVersionRequest(t, h, cfg, etag); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	if w := toolGuardVersionRequest(t, h, cfg, etag); w.Code != http.StatusConflict {
		t.Fatal("no-op save left old version valid")
	}
}

func TestToolGuardFailedPersistenceRetainsVersion(t *testing.T) {
	h := newToolGuardTestHandler(t)
	etag := toolGuardRequest(t, h.GetToolGuard, nil).Header().Get("ETag")
	path := h.configPath
	h.configPath = path + "/missing.yaml"
	cfg := toolguard.DefaultConfig()
	cfg.Enabled = false
	if w := toolGuardVersionRequest(t, h, cfg, etag); w.Code != http.StatusInternalServerError {
		t.Fatal(w.Code, w.Body.String())
	}
	if toolGuardRequest(t, h.GetToolGuard, nil).Header().Get("ETag") != etag || !h.toolGuard.Config().Enabled {
		t.Fatal("failed persistence advanced version or changed policy")
	}
	h.configPath = path
	if w := toolGuardVersionRequest(t, h, cfg, etag); w.Code != http.StatusOK {
		t.Fatal("safe retry failed", w.Body.String())
	}
}

func TestToolGuardManagerUpdateInvalidatesVersion(t *testing.T) {
	h := newToolGuardTestHandler(t)
	etag := toolGuardRequest(t, h.GetToolGuard, nil).Header().Get("ETag")
	cfg := toolguard.DefaultConfig()
	cfg.Enabled = false
	if err := h.toolGuard.Update(cfg); err != nil {
		t.Fatal(err)
	}
	if w := toolGuardVersionRequest(t, h, toolguard.DefaultConfig(), etag); w.Code != http.StatusConflict || h.toolGuard.Config().Enabled {
		t.Fatal("direct policy update was overwritten")
	}
}
