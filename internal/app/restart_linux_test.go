//go:build linux

package app

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The restart's own shape needs three processes to observe: this test starts a copy of itself
// in the role the update handler plays (call restartInto), and the process that copy becomes
// prints the marker. A plain in-process test cannot see an image replacement.
const (
	restartStageEnv  = "CSAI_TEST_RESTART_STAGE"
	restartMarkerEnv = "CSAI_TEST_RESTART_MARKER"
)

func TestRestartIntoReplacesTheProcessImage(t *testing.T) {
	if os.Getenv(restartStageEnv) == "caller" {
		// Stand in for the update's restart hook. The stage is cleared and the marker set
		// before the handover, so the process this becomes prints the marker instead of
		// calling restartInto again.
		os.Unsetenv(restartStageEnv)
		os.Setenv(restartMarkerEnv, "1")
		restartInto(func() { fmt.Println("shutdown-ran") }, os.Args[0])
		t.Fatal("restartInto returned instead of replacing this process image")
	}
	if os.Getenv(restartMarkerEnv) == "1" {
		fmt.Println("re-executed")
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestRestartIntoReplacesTheProcessImage$")
	cmd.Env = append(os.Environ(), restartStageEnv+"=caller")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the restarting process failed: %v\n%s", err, out)
	}
	got := string(out)
	shutdownAt, reexecAt := strings.Index(got, "shutdown-ran"), strings.Index(got, "re-executed")
	if shutdownAt < 0 {
		t.Fatalf("the graceful shutdown never ran:\n%s", got)
	}
	if reexecAt < 0 {
		t.Fatalf("the process did not become the binary on disk:\n%s", got)
	}
	if shutdownAt > reexecAt {
		t.Fatalf("the new process printed before the old one shut down:\n%s", got)
	}
}
