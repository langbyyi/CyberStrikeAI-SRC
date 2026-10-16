package update

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// hangingSource is an update source that accepts a connection and never answers it. That is
// the shape of 网络不通 on this feature's worst days: nothing is refused, nothing arrives,
// and git has no deadline of its own to give up on.
type hangingSource struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func startHangingSource(t *testing.T) *hangingSource {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no local listener: %v", err)
	}
	s := &hangingSource{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, conn)
			s.mu.Unlock()
		}
	}()
	t.Cleanup(s.stop)
	return s
}

func (s *hangingSource) url() string { return "http://" + s.ln.Addr().String() + "/never-answers.git" }

// stop lets go of the connections it is holding. A git killed on a deadline leaves its
// transport helper behind, and that helper keeps the working directory open.
func (s *hangingSource) stop() {
	s.ln.Close()
	s.mu.Lock()
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// TestCheckGivesUpOnASourceThatNeverAnswers: a check holds the installation lock for as
// long as it is on the network. If a source that never answers could keep it, every later
// click would be refused with "已有更新、检查或回滚正在执行", and the operation behind that
// refusal would be invisible and unstoppable from the console - the feature reading as
// broken for good. The check has to end by itself, say it timed out, and hand the lock back.
func TestCheckGivesUpOnASourceThatNeverAnswers(t *testing.T) {
	requireGit(t)
	tr := newTree(t)
	source := startHangingSource(t)

	oldTimeout, oldDelay := networkTimeout, execWaitDelay
	networkTimeout, execWaitDelay = 500*time.Millisecond, 500*time.Millisecond
	t.Cleanup(func() { networkTimeout, execWaitDelay = oldTimeout, oldDelay })

	o := opts(tr)
	o.Repo = source.url()

	start := time.Now()
	snap, err := Check(context.Background(), o)
	if err != nil {
		t.Fatalf("a network failure is an answer, not an error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("check waited %s on a source that never answers", elapsed)
	}
	if !strings.Contains(snap.CheckError, "超时") {
		t.Fatalf("checkError = %q, want a timeout the operator can read", snap.CheckError)
	}

	release, err := LockInstall(o)
	if err != nil {
		t.Fatalf("the timed-out check kept the installation locked: %v", err)
	}
	release()

	source.stop()
	// The orphaned helper holds the working directory until it notices its socket is gone;
	// on Windows the tree cannot be removed before that.
	time.Sleep(time.Second)
}

// TestNetworkFailureNamesATimeout: when the deadline fires, git dies with "signal: killed",
// which says nothing about the network the operator has to look at.
func TestNetworkFailureNamesATimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()

	got := networkFailure(ctx, "https://example.com/fork.git", errors.New("git fetch: signal: killed"))
	if !strings.Contains(got, "超时") || strings.Contains(got, "signal: killed") {
		t.Fatalf("timeout surfaced as %q", got)
	}
	plain := networkFailure(context.Background(), "https://example.com/fork.git", errors.New("无法访问更新源仓库：连接被拒绝"))
	if !strings.Contains(plain, "连接被拒绝") {
		t.Fatalf("a live failure was not passed through: %q", plain)
	}
}

// TestInstallLockRefusalSaysHowLongTheWaitIs: the holder is normally another check that is
// still on the network, so the refusal has to read as "wait a moment" rather than as a lock
// nobody will ever release.
func TestInstallLockRefusalSaysHowLongTheWaitIs(t *testing.T) {
	root := t.TempDir()
	release, err := LockInstall(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	_, err = LockInstall(Options{Root: root})
	ue, ok := err.(*Error)
	if !ok || ue.Reason != "update_busy" {
		t.Fatalf("second lock = %v, want update_busy", err)
	}
	if !strings.Contains(ue.Message, "分钟") {
		t.Fatalf("refusal does not say how long the wait is: %q", ue.Message)
	}
}
