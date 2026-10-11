package update

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRollbackKeepsOperatorEditsToProtectedFiles pins the promise docs make - a rollback
// undoes the update, not the operator's content. reset --hard discards every local change
// to tracked files, not just the update's, so both an edit made before the update and one
// made after it have to be put back on top of the old commit.
func TestRollbackKeepsOperatorEditsToProtectedFiles(t *testing.T) {
	requireGit(t)
	tr := newTree(t)

	// Edited before the update: Apply itself keeps this one (its stash covers it), which is
	// exactly the shape the rollback then used to wipe.
	writeFile(t, filepath.Join(tr.install, "roles", "shipped.yaml"), "name: shipped\ndescription: mine before\n")
	tr.upstreamCommit(t, "upstream moves code and rewrites roles", map[string]string{
		"internal_service.go": "package service\n\nconst Version = \"2\"\n",
		"roles/shipped.yaml":  "name: shipped\ndescription: upstream rewrite\n",
		"roles/extra.yaml":    "name: extra\ndescription: upstream copy\n",
	})
	if _, err := Apply(context.Background(), opts(tr), nil); err != nil {
		t.Fatal(err)
	}
	// Edited after the update: no stash ever saw this one.
	writeFile(t, filepath.Join(tr.install, "roles", "extra.yaml"), "name: extra\ndescription: mine after\n")

	// The binary pair a swap leaves behind, so the rollback has one to restore.
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "new binary bytes")
	writeFile(t, bin+".prev", "old binary bytes")

	res, err := Rollback(context.Background(), Options{Root: tr.install})
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if got := readFile(t, filepath.Join(tr.install, "internal_service.go")); !strings.Contains(got, "Version = \"1\"") {
		t.Errorf("code after rollback = %q, want the old version back", got)
	}
	if got := readFile(t, filepath.Join(tr.install, "roles", "shipped.yaml")); !strings.Contains(got, "mine before") {
		t.Errorf("an edit made before the update was wiped by the rollback: %q", got)
	}
	if got := readFile(t, filepath.Join(tr.install, "roles", "extra.yaml")); !strings.Contains(got, "mine after") {
		t.Errorf("an edit made after the update was wiped by the rollback: %q", got)
	}
	want := "roles/extra.yaml,roles/shipped.yaml"
	if got := strings.Join(res.KeptContent, ","); got != want {
		t.Errorf("keptContent = %v, want %s", res.KeptContent, want)
	}
}

// TestRollbackKeepsAHandDeletionOfAProtectedFile: a deletion is a local change like any
// other. reset --hard would bring the old commit's copy back; the rollback has to re-apply
// the deletion instead.
func TestRollbackKeepsAHandDeletionOfAProtectedFile(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	tr.upstreamCommit(t, "upstream moves", map[string]string{"internal_service.go": "package service\n\nconst Version = \"2\"\n"})
	if _, err := Apply(context.Background(), opts(tr), nil); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(tr.install, "roles", "shipped.yaml")
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "new binary bytes")
	writeFile(t, bin+".prev", "old binary bytes")

	res, err := Rollback(context.Background(), Options{Root: tr.install})
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Errorf("a file deleted by hand was resurrected by the rollback (%v); result %+v", err, res)
	}
}

func TestRollbackKeepsProtectedFileRecreatedAfterUpstreamDeletedIt(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	if err := os.Remove(filepath.Join(tr.upstream, "roles", "shipped.yaml")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tr.upstream, "internal_service.go"), "package service\n\nconst Version = \"2\"\n")
	mustGit(t, tr.upstream, "add", "-A")
	mustGit(t, tr.upstream, "-c", "user.email=t@example.com", "-c", "user.name=T", "commit", "-q", "-m", "upstream deletes the shipped role")
	if _, err := Apply(context.Background(), opts(tr), nil); err != nil {
		t.Fatal(err)
	}

	recreated := filepath.Join(tr.install, "roles", "shipped.yaml")
	writeFile(t, recreated, "name: shipped\ndescription: mine after upstream deleted it\n")
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "new binary bytes")
	writeFile(t, bin+".prev", "old binary bytes")

	res, err := Rollback(context.Background(), Options{Root: tr.install})
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if got := readFile(t, recreated); !strings.Contains(got, "mine after upstream deleted it") {
		t.Fatalf("rollback overwrote the operator's recreated role: %q", got)
	}
	if got := strings.Join(res.KeptContent, ","); got != "roles/shipped.yaml" {
		t.Fatalf("keptContent = %v, want the recreated role named", res.KeptContent)
	}
}
