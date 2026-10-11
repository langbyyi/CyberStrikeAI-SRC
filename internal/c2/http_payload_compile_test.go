package c2

import (
	"go.uber.org/zap"
	"path/filepath"
	"testing"
)

func TestHTTPBeaconSessionCredentialTemplateCompiles(t *testing.T) {
	t.Setenv("GO111MODULE", "off")
	manager, db := terminalTestManager(t)
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE c2_listeners SET type=?,encryption_key=?,implant_token=? WHERE id=?`, string(ListenerTypeHTTPBeacon), key, "test-only-token", "listener"); err != nil {
		t.Fatal(err)
	}
	// Build artifacts remain temporary; generated clients are never executed.
	templateDir, err := filepath.Abs("payload_templates")
	if err != nil {
		t.Fatal(err)
	}
	builder := NewPayloadBuilder(manager, zap.NewNop(), templateDir, t.TempDir())
	for _, platform := range []struct{ os, arch string }{{"linux", "amd64"}, {"windows", "amd64"}, {"darwin", "arm64"}} {
		t.Run(platform.os, func(t *testing.T) {
			result, err := builder.BuildBeacon(PayloadBuilderInput{ListenerID: "listener", OS: platform.os, Arch: platform.arch, Host: "127.0.0.1"})
			if err != nil {
				t.Fatal(err)
			}
			if result.SizeBytes <= 0 {
				t.Fatal("empty client")
			}
		})
	}
}
