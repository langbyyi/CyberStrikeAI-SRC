package update

import (
	"context"
	"cyberstrike-ai/internal/config"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests drive real git repositories in temporary directories. A fake would let the
// thing this package exists for - "git says no because your files would be overwritten" -
// pass silently.

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

type tree struct {
	upstream string
	install  string
}

// newTree builds an upstream repository with one code file and one shipped role, then
// clones it the way an operator would (the clone's origin is the user's own fork, not a
// fixed third-party repository).
func newTree(t *testing.T) *tree {
	t.Helper()
	root := t.TempDir()
	up := filepath.Join(root, "fork")
	install := filepath.Join(root, "install")
	mustGit(t, root, "init", "-q", "-b", "main", up)

	writeFile(t, filepath.Join(up, "internal_service.go"), "package service\n\nconst Version = \"1\"\n")
	writeFile(t, filepath.Join(up, "roles", "shipped.yaml"), "name: shipped\ndescription: upstream copy\n")
	writeFile(t, filepath.Join(up, "run.sh"), "#!/bin/sh\necho old\n")
	mustGit(t, up, "add", ".")
	mustGit(t, up, "-c", "user.email=t@example.com", "-c", "user.name=T", "commit", "-q", "-m", "first")

	mustGit(t, root, "clone", "-q", up, install)
	mustGit(t, install, "-c", "user.email=t@example.com", "-c", "user.name=T", "commit", "--allow-empty", "-m", "clone marker")
	// The clone's own commit makes HEAD and origin/main differ only by the operator's
	// history; drop it so the tree starts exactly level with its remote.
	mustGit(t, install, "reset", "--hard", "--quiet", "origin/main")

	// The live config file is operator data that is never in the repository.
	writeFile(t, filepath.Join(install, "config.yaml"), "server:\n  port: 8088\n")
	return &tree{upstream: up, install: install}
}

func (t *tree) upstreamCommit(t2 *testing.T, message string, files map[string]string) {
	t2.Helper()
	for path, content := range files {
		writeFile(t2, filepath.Join(t.upstream, path), content)
	}
	mustGit(t2, t.upstream, "add", ".")
	mustGit(t2, t.upstream, "-c", "user.email=t@example.com", "-c", "user.name=T", "commit", "-q", "-m", message)
}

// opts points an update at the tree's own source repository: the explicit address is
// now the whole configuration, so tests name it the way an operator would.
func opts(tr *tree) Options {
	return Options{Root: tr.install, Repo: tr.upstream, BinaryName: "none"}
}

func TestStatusWithoutNetworkDescribesTheTree(t *testing.T) {
	requireGit(t)
	tr := newTree(t)

	snap, err := Status(context.Background(), opts(tr))
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Installed {
		t.Fatal("a clone must be reported as an installable tree")
	}
	if snap.Branch != "main" {
		t.Errorf("local branch = %q, want main", snap.Branch)
	}
	if snap.Repo != tr.upstream || !snap.RepoConfigured {
		t.Errorf("repo = %q configured=%v, want the configured source %q", snap.Repo, snap.RepoConfigured, tr.upstream)
	}
	if snap.Commit == "" {
		t.Error("commit is empty")
	}
	// config.yaml is operator data and is untracked, so it is not a blocking change.
	if len(snap.BlockingChanges) != 0 {
		t.Errorf("untracked config.yaml must not block an update: %+v", snap.BlockingChanges)
	}
}

func TestStatusReportsTheInstallRootInAbsoluteForm(t *testing.T) {
	requireGit(t)
	tr := newTree(t)

	// A relative config path gives filepath.Dir as "."; the page must still be able to say
	// which directory is being updated.
	t.Chdir(tr.install)
	snap, err := Status(context.Background(), Options{Root: ".", Repo: tr.upstream, BinaryName: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(snap.Root) || filepath.Base(snap.Root) != "install" {
		t.Errorf("root = %q, want the absolute install directory", snap.Root)
	}

	if _, err := Status(context.Background(), Options{Root: "  "}); err == nil {
		t.Error("an empty install root must be an error, not a scan of the process CWD")
	}
	if _, err := Rollback(context.Background(), Options{Root: ""}); err == nil {
		t.Error("rollback must refuse an empty install root for the same reason")
	}
}

func TestStatusOnNonGitTreeIsAStateNotAnError(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	snap, err := Status(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatalf("a tarball install is a readable state, not a fault: %v", err)
	}
	if snap.Installed || snap.CheckError == "" {
		t.Errorf("installed=%v checkError=%q, want false with a reason", snap.Installed, snap.CheckError)
	}
	if snap.Repo != DefaultRepoURL || snap.RepoConfigured {
		t.Errorf("repo = %q configured=%v, want the official repository by default", snap.Repo, snap.RepoConfigured)
	}
}

func TestCheckFetchesAndListsIncoming(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	tr.upstreamCommit(t, "second: bump service", map[string]string{"internal_service.go": "package service\n\nconst Version = \"2\"\n"})
	tr.upstreamCommit(t, "third: new role", map[string]string{"roles/extra.yaml": "name: extra\n"})

	snap, err := Check(context.Background(), opts(tr))
	if err != nil {
		t.Fatal(err)
	}
	if snap.CheckError != "" {
		t.Fatalf("check failed: %s", snap.CheckError)
	}
	if !snap.UpdateAvailable || snap.Behind != 2 || snap.Ahead != 0 || snap.Diverged {
		t.Errorf("behind=%d ahead=%d available=%v diverged=%v, want 2/0/true/false", snap.Behind, snap.Ahead, snap.UpdateAvailable, snap.Diverged)
	}
	if len(snap.Incoming) != 2 || snap.Incoming[0].Subject != "third: new role" {
		t.Errorf("incoming = %+v, want the two new commits newest first", snap.Incoming)
	}
	if snap.IncomingTotal != 2 {
		t.Errorf("incomingTotal = %d, want 2", snap.IncomingTotal)
	}
}

// TestApplyKeepsOperatorContentIsThePointOfTheWholePackage: an update moves code and does
// not destroy the roles, skills or tools the operator made or edited from the console.
func TestApplyKeepsOperatorContentAndMovesCode(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	// The operator edits a shipped role and adds their own; upstream later rewrites that
	// same role and takes the untracked file's name for itself.
	writeFile(t, filepath.Join(tr.install, "roles", "shipped.yaml"), "name: shipped\ndescription: mine, do not touch\n")
	writeFile(t, filepath.Join(tr.install, "roles", "mine.yaml"), "name: mine\n")

	tr.upstreamCommit(t, "upstream rewrites roles and code", map[string]string{
		"roles/shipped.yaml":  "name: shipped\ndescription: upstream rewrite\n",
		"roles/mine.yaml":     "name: mine\ndescription: upstream stole the name\n",
		"internal_service.go": "package service\n\nconst Version = \"3\"\n",
	})

	res, err := Apply(context.Background(), opts(tr), nil)
	if err != nil {
		t.Fatalf("apply failed: %v\nresult: %+v", err, res)
	}
	if res.Commits == 0 || res.FromCommit == res.ToCommit {
		t.Errorf("nothing moved: %+v", res)
	}

	if got := readFile(t, filepath.Join(tr.install, "internal_service.go")); !strings.Contains(got, "Version = \"3\"") {
		t.Errorf("code was not updated, got %q", got)
	}
	if got := readFile(t, filepath.Join(tr.install, "roles", "shipped.yaml")); !strings.Contains(got, "mine, do not touch") {
		t.Errorf("the operator's role was overwritten by upstream: %q", got)
	}
	if _, err := os.Stat(filepath.Join(tr.install, "roles", "mine.yaml")); err != nil {
		t.Errorf("the operator's own role must survive: %v", err)
	}
	if got := readFile(t, filepath.Join(tr.install, "config.yaml")); !strings.Contains(got, "8088") {
		t.Errorf("config.yaml was disturbed: %q", got)
	}
	if len(res.KeptContent) == 0 {
		t.Error("keptContent must name the files that were protected, not silently drop them")
	}
	found := false
	for _, p := range res.KeptContent {
		if p == "roles/shipped.yaml" {
			found = true
		}
	}
	if !found {
		t.Errorf("keptContent = %v, want roles/shipped.yaml in it", res.KeptContent)
	}
	if res.BinaryBuilt {
		t.Error("BinaryName none must not claim a build")
	}
	if !res.NeedsRestart {
		t.Error("an update that moved code reports that a restart is needed")
	}
	if _, ok := readState(tr.install); !ok {
		t.Error("state file missing: rollback would be unavailable")
	}
}

func TestApplyRefusesLocalSourceEdits(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	tr.upstreamCommit(t, "new upstream", map[string]string{"internal_service.go": "package service\n\nconst Version = \"9\"\n"})
	writeFile(t, filepath.Join(tr.install, "internal_service.go"), "package service\n\nconst Version = \"local hand edit\"\n")

	_, err := Apply(context.Background(), opts(tr), nil)
	ue, ok := err.(*Error)
	if !ok {
		t.Fatalf("want *Error, got %v", err)
	}
	if ue.Reason != "local_source_edits" {
		t.Errorf("reason = %q, want local_source_edits", ue.Reason)
	}
	if !strings.Contains(strings.Join(ue.Items, " "), "internal_service.go") {
		t.Errorf("the refusal must name the file, got %v", ue.Items)
	}
	if got := readFile(t, filepath.Join(tr.install, "internal_service.go")); !strings.Contains(got, "local hand edit") {
		t.Errorf("a refused update must not touch anything, got %q", got)
	}
}

func TestApplyRefusesDivergedBranch(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	tr.upstreamCommit(t, "upstream moves", map[string]string{"internal_service.go": "package service\n\nconst Version = \"9\"\n"})
	writeFile(t, filepath.Join(tr.install, "my_patch.go"), "package service\n")
	mustGit(t, tr.install, "add", "my_patch.go")
	mustGit(t, tr.install, "-c", "user.email=t@example.com", "-c", "user.name=T", "commit", "-q", "-m", "my own commit")

	_, err := Apply(context.Background(), opts(tr), nil)
	ue, ok := err.(*Error)
	if !ok || ue.Reason != "diverged" {
		t.Fatalf("a branch with its own commits is a merge decision, not a download; got %v", err)
	}
}

func TestApplyWhenAlreadyUpToDateIsANoOp(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	res, err := Apply(context.Background(), opts(tr), nil)
	if err != nil {
		t.Fatalf("up to date must not be an error: %v", err)
	}
	if res.Commits != 0 || res.ToCommit != res.FromCommit {
		t.Errorf("res = %+v, want zero movement", res)
	}
	if _, err := os.Stat(statePath(tr.install)); !os.IsNotExist(err) {
		t.Error("a no-op update must not write a rollback state")
	}
}

func TestRollbackMovesBackToTheRecordedCommit(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	before := mustGit(t, tr.install, "rev-parse", "HEAD")
	tr.upstreamCommit(t, "upstream new", map[string]string{"internal_service.go": "package service\n\nconst Version = \"7\"\n"})
	if _, err := Apply(context.Background(), opts(tr), nil); err != nil {
		t.Fatal(err)
	}
	// Rollback restores the binary kept before a swap; stand one up the way installBinary
	// would have left it.
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "new binary bytes")
	writeFile(t, bin+".prev", "old binary bytes")

	res, err := Rollback(context.Background(), Options{Root: tr.install})
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if got := mustGit(t, tr.install, "rev-parse", "HEAD"); got != strings.TrimSpace(before) {
		t.Errorf("HEAD after rollback = %s, want %s", got, before)
	}
	if got := readFile(t, bin); !strings.Contains(got, "old binary") {
		t.Errorf("binary after rollback = %q, want the kept previous one", got)
	}
	if res.ToCommit == "" {
		t.Error("rollback must report where it went")
	}
	if _, err := os.Stat(statePath(tr.install)); !os.IsNotExist(err) {
		t.Error("a completed rollback must clear the state file")
	}
}

func TestRollbackRefusesWhenHeadMoved(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	tr.upstreamCommit(t, "upstream new", map[string]string{"internal_service.go": "package service\n\nconst Version = \"7\"\n"})
	if _, err := Apply(context.Background(), opts(tr), nil); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "new")
	writeFile(t, bin+".prev", "old")
	// Somebody else moved the tree after the update.
	writeFile(t, filepath.Join(tr.install, "extra.go"), "package service\n")
	mustGit(t, tr.install, "add", "extra.go")
	mustGit(t, tr.install, "-c", "user.email=t@example.com", "-c", "user.name=T", "commit", "-q", "-m", "later work")

	_, err := Rollback(context.Background(), Options{Root: tr.install})
	ue, ok := err.(*Error)
	if !ok || ue.Reason != "moved_since_update" {
		t.Fatalf("rollback must refuse rather than discard work done after the update, got %v", err)
	}
	if _, err := os.Stat(bin + ".prev"); err != nil {
		t.Error("a refused rollback must leave the .prev binary where it was")
	}
}

func TestProtectedCoversOperatorDataAndNotCode(t *testing.T) {
	yes := []string{"roles/CTF.yaml", "skills/x/SKILL.md", "tools/semgrep.yaml", "agents/a.md", "bundles/pack/bundle.yaml",
		"knowledge_base/note.md", "data/conversations.db", "log/server.log", "config.yaml", ".env", "venv/bin/python"}
	no := []string{"internal/handler/plugin.go", "web/static/js/plugins.js", "cmd/server/main.go", "Makefile", "docs/zh-CN/c2.md"}
	for _, p := range yes {
		if !Protected(p) {
			t.Errorf("%s must be protected from an update", p)
		}
	}
	for _, p := range no {
		if Protected(p) {
			t.Errorf("%s is product source and must be updated", p)
		}
	}
}

func TestValidNameRejectsArgumentInjection(t *testing.T) {
	for _, bad := range []string{"", "-C", "--upload-pack=touch /tmp/x", "a b", "a;b", "a\nb", "-x/y", "/abs/path", "../evil"} {
		if ValidName(bad) {
			t.Errorf("%q must be rejected before it reaches git's argv", bad)
		}
	}
	for _, good := range []string{"origin", "mine", "main", "feature/docker", "v1.2.3"} {
		if !ValidName(good) {
			t.Errorf("%q is a legitimate remote or branch name", good)
		}
	}
}

func TestInstallBinaryKeepsPrevAndRestoresOnFailedSwap(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "cyberstrike-ai")
	src := filepath.Join(dir, "new")
	writeFile(t, dst, "old")
	writeFile(t, src, "new")

	prev, err := installBinary(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, dst) != "new" || readFile(t, prev) != "old" {
		t.Errorf("swap result: dst=%q prev=%q", readFile(t, dst), readFile(t, prev))
	}
	if err := restorePrevBinary(dst); err != nil {
		t.Fatal(err)
	}
	if readFile(t, dst) != "old" {
		t.Errorf("rollback binary = %q, want old", readFile(t, dst))
	}
	if fileExists(dst + ".prev") {
		t.Error("restoring the previous binary must consume the .prev file")
	}
}

func TestTailKeepsTheEndOfABuildLog(t *testing.T) {
	long := strings.Repeat("download\n", 500) + "vet: real error at the end"
	got := tail(long, 200)
	if !strings.Contains(got, "real error at the end") {
		t.Error("tail must keep the compiler's actual error")
	}
	if len(got) > 260 {
		t.Errorf("tail did not truncate: %d bytes", len(got))
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// The release version rides with the code: after an update the live config has to say the
// version of the code now on disk (the header badge reads it), and a rollback has to put
// the old number back next to the old code.
func TestApplySyncsTheReleaseVersionIntoTheLiveConfig(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	writeFile(t, filepath.Join(tr.install, "config.yaml"), "version: \"v1.0.0\"\nserver:\n  port: 8088\n")
	tr.upstreamCommit(t, "release: bump version", map[string]string{
		"config.example.yaml": "version: \"v1.1.0\"\nserver:\n  port: 8088\n",
		"internal_service.go": "package service\n\nconst Version = \"2\"\n",
	})

	res, err := Apply(context.Background(), opts(tr), nil)
	if err != nil {
		t.Fatalf("apply failed: %v\nresult: %+v", err, res)
	}
	live := readFile(t, filepath.Join(tr.install, "config.yaml"))
	if !strings.Contains(live, `version: "v1.1.0"`) || !strings.Contains(live, "port: 8088") {
		t.Fatalf("live config after update = %q, want the new version with everything else untouched", live)
	}
	st, ok := readState(tr.install)
	if !ok || st.VersionBefore != "v1.0.0" || st.VersionAfter != "v1.1.0" {
		t.Fatalf("state = %+v, want the version change recorded for the rollback", st)
	}

	// Rollback puts the number back with the code.
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "new binary bytes")
	writeFile(t, bin+".prev", "old binary bytes")
	if _, err := Rollback(context.Background(), Options{Root: tr.install}); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	live = readFile(t, filepath.Join(tr.install, "config.yaml"))
	if !strings.Contains(live, `version: "v1.0.0"`) {
		t.Fatalf("live config after rollback = %q, want the old version back", live)
	}
}

// The same sync end to end, with the key spelled the way issue #4 was filed about: a legal
// quoted key must be replaced in place (not appended next to), and the rollback must still
// find a config it can read.
func TestApplySyncsTheReleaseVersionIntoAQuotedKeyConfig(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	live := filepath.Join(tr.install, "config.yaml")
	writeFile(t, live, "\"version\": \"v1.0.0\"\nserver:\n  port: 8088\n")
	tr.upstreamCommit(t, "release: bump version", map[string]string{
		"config.example.yaml": "version: \"v1.1.0\"\n",
		"internal_service.go": "package service\n\nconst Version = \"2\"\n",
	})

	if _, err := Apply(context.Background(), opts(tr), nil); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	got := readFile(t, live)
	if strings.Count(got, "version") != 1 {
		t.Fatalf("live config gained a duplicate version key:\n%q", got)
	}
	if v, err := config.FileVersion(live); err != nil || v != "v1.1.0" {
		t.Fatalf("live config after apply reads %q (%v), want v1.1.0:\n%q", v, err, got)
	}
	if !strings.Contains(got, "port: 8088") {
		t.Fatalf("the rest of the config must stay:\n%q", got)
	}

	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "new binary bytes")
	writeFile(t, bin+".prev", "old binary bytes")
	if _, err := Rollback(context.Background(), Options{Root: tr.install}); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	got = readFile(t, live)
	if strings.Count(got, "version") != 1 {
		t.Fatalf("rollback left a broken config:\n%q", got)
	}
	if v, err := config.FileVersion(live); err != nil || v != "v1.0.0" {
		t.Fatalf("live config after rollback reads %q (%v), want v1.0.0:\n%q", v, err, got)
	}
}

func TestRollbackDoesNotClobberAManuallyChangedVersion(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	writeFile(t, filepath.Join(tr.install, "config.yaml"), "version: \"v1.0.0\"\nserver:\n  port: 8088\n")
	tr.upstreamCommit(t, "release: bump version", map[string]string{
		"config.example.yaml": "version: \"v1.1.0\"\n",
	})
	if _, err := Apply(context.Background(), opts(tr), nil); err != nil {
		t.Fatal(err)
	}
	// Somebody pins their own version after the update; a rollback is not theirs to undo.
	writeFile(t, filepath.Join(tr.install, "config.yaml"), "version: \"v9.9.9-mine\"\nserver:\n  port: 8088\n")
	bin := filepath.Join(tr.install, Binary)
	writeFile(t, bin, "new")
	writeFile(t, bin+".prev", "old")
	if _, err := Rollback(context.Background(), Options{Root: tr.install}); err != nil {
		t.Fatal(err)
	}
	if live := readFile(t, filepath.Join(tr.install, "config.yaml")); !strings.Contains(live, "v9.9.9-mine") {
		t.Fatalf("a hand-set version must survive a rollback, got %q", live)
	}
}

func TestApplyLeavesTheVersionAloneWhenTheTreeCarriesNone(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	// The fixture's upstream has no config.example.yaml at all: nothing to sync, and the
	// live config must not be rewritten with a guess.
	writeFile(t, filepath.Join(tr.install, "config.yaml"), "version: \"v1.0.0\"\nserver:\n  port: 8088\n")
	tr.upstreamCommit(t, "second: bump service", map[string]string{
		"internal_service.go": "package service\n\nconst Version = \"2\"\n",
	})
	if _, err := Apply(context.Background(), opts(tr), nil); err != nil {
		t.Fatal(err)
	}
	if live := readFile(t, filepath.Join(tr.install, "config.yaml")); !strings.Contains(live, "v1.0.0") {
		t.Fatalf("live config = %q, want it untouched", live)
	}
	if st, _ := readState(tr.install); st.VersionAfter != "" || st.VersionBefore != "" {
		t.Fatalf("state = %+v, want no version fields when nothing changed", st)
	}
}

func TestAdoptSyncsTheReleaseVersionIntoTheLiveConfig(t *testing.T) {
	requireGit(t)
	tr, dir := newAdoptFixture(t)
	writeFile(t, filepath.Join(dir, "config.yaml"), "version: \"v0.9.0\"\nserver:\n  port: 8088\n")
	tr.upstreamCommit(t, "release: bump version", map[string]string{
		"config.example.yaml": "version: \"v1.1.0\"\n",
	})

	res, err := Adopt(context.Background(), Options{Root: dir, Repo: tr.upstream, BinaryName: "none"}, nil)
	if err != nil {
		t.Fatalf("adopt failed: %v\nresult: %+v", err, res)
	}
	live := readFile(t, filepath.Join(dir, "config.yaml"))
	if !strings.Contains(live, `version: "v1.1.0"`) || !strings.Contains(live, "port: 8088") {
		t.Fatalf("live config after adopt = %q, want the connected code's version with the rest untouched", live)
	}
}

// A tree that is already current still gets its bookkeeping aligned: the version field is
// the one thing an update may correct with no commits to move (that is exactly the state a
// pre-feature installation is in).
func TestApplyAlignsTheVersionEvenWithNothingToPull(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	writeFile(t, filepath.Join(tr.install, "config.yaml"), "version: \"v0.9.0\"\nserver:\n  port: 8088\n")
	writeFile(t, filepath.Join(tr.install, "config.example.yaml"), "version: \"v1.1.0\"\n")

	res, err := Apply(context.Background(), opts(tr), nil)
	if err != nil {
		t.Fatalf("no-op apply failed: %v", err)
	}
	if res.Commits != 0 {
		t.Fatalf("res = %+v, want zero movement", res)
	}
	if live := readFile(t, filepath.Join(tr.install, "config.yaml")); !strings.Contains(live, `version: "v1.1.0"`) {
		t.Fatalf("live config = %q, want the version aligned even though nothing moved", live)
	}
	// Bookkeeping only: a version-only correction writes no rollback state.
	if _, ok := readState(tr.install); ok {
		t.Fatal("a version-only alignment must not claim to be a rollback point")
	}
}
