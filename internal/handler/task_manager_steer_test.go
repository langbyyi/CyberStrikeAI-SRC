package handler

import (
	"context"
	"testing"
)

// TestSteerRunningTaskRoutesToBoundTurnLoopHook 引导三态：无任务 / 未挂载 TurnLoop / 已受理。
// 未挂载时必须明确拒绝（SteerUnsupported），不能退化为取消任务。
func TestSteerRunningTaskRoutesToBoundTurnLoopHook(t *testing.T) {
	tm := NewAgentTaskManager()

	if got := tm.SteerRunningTask("conv-steer", "只测 443"); got != SteerNoActiveTask {
		t.Fatalf("idle conversation outcome = %v, want SteerNoActiveTask", got)
	}

	_, cancel := context.WithCancelCause(context.Background())
	if _, err := tm.StartTask("conv-steer", "运行中", cancel); err != nil {
		t.Fatalf("StartTask: %v", err)
	}

	if got := tm.SteerRunningTask("conv-steer", "只测 443"); got != SteerUnsupported {
		t.Fatalf("outcome without turn loop = %v, want SteerUnsupported", got)
	}

	var pushed []string
	unregister := tm.BindAgentTurnLoopSteer("conv-steer", func(message string) bool {
		pushed = append(pushed, message)
		return true
	})
	if got := tm.SteerRunningTask("conv-steer", "  只测 443  "); got != SteerAccepted {
		t.Fatalf("outcome with turn loop = %v, want SteerAccepted", got)
	}
	if len(pushed) != 1 || pushed[0] != "只测 443" {
		t.Fatalf("pushed = %#v, want trimmed steer message", pushed)
	}
	if cause := context.Cause(context.Background()); cause != nil {
		t.Fatalf("unexpected context cause: %v", cause)
	}

	// TurnLoop 已停止：入队失败按不支持返回，调用方回退提示而不是当成功。
	unregister()
	if got := tm.SteerRunningTask("conv-steer", "再补一句"); got != SteerUnsupported {
		t.Fatalf("outcome after unregister = %v, want SteerUnsupported", got)
	}
	if len(pushed) != 1 {
		t.Fatalf("pushed = %#v, want no extra push after unregister", pushed)
	}
}

// TestBindAgentTurnLoopSteerIgnoresStaleUnregister 分段续跑会重复绑定 hook：
// 旧运行段的 unregister 不得清掉新运行段刚绑定的 hook，否则引导会静默失效。
func TestBindAgentTurnLoopSteerIgnoresStaleUnregister(t *testing.T) {
	tm := NewAgentTaskManager()
	_, cancel := context.WithCancelCause(context.Background())
	if _, err := tm.StartTask("conv-steer-restart", "运行中", cancel); err != nil {
		t.Fatalf("StartTask: %v", err)
	}

	var first, second []string
	unregisterFirst := tm.BindAgentTurnLoopSteer("conv-steer-restart", func(message string) bool {
		first = append(first, message)
		return true
	})
	tm.BindAgentTurnLoopSteer("conv-steer-restart", func(message string) bool {
		second = append(second, message)
		return true
	})

	unregisterFirst()

	if got := tm.SteerRunningTask("conv-steer-restart", "补充指示"); got != SteerAccepted {
		t.Fatalf("outcome = %v, want SteerAccepted for the newer hook", got)
	}
	if len(second) != 1 || len(first) != 0 {
		t.Fatalf("first=%#v second=%#v, want only the newer hook to receive the steer", first, second)
	}
}

// TestSteerRunningTaskRejectsHookRejection TurnLoop 收尾中入队失败：不得报告成功，
// 否则前端会清空输入却什么都没生效。
func TestSteerRunningTaskRejectsHookRejection(t *testing.T) {
	tm := NewAgentTaskManager()
	_, cancel := context.WithCancelCause(context.Background())
	if _, err := tm.StartTask("conv-steer-closing", "运行中", cancel); err != nil {
		t.Fatalf("StartTask: %v", err)
	}
	unregister := tm.BindAgentTurnLoopSteer("conv-steer-closing", func(string) bool { return false })
	defer unregister()

	if got := tm.SteerRunningTask("conv-steer-closing", "补充指示"); got != SteerUnsupported {
		t.Fatalf("outcome = %v, want SteerUnsupported when the loop rejects", got)
	}
}

// TestSteerRunningTaskWithoutTaskLeavesTaskTableClean 引导不得创建任务或改状态：
// 未挂载 hook 时拒绝引导后，任务仍应处于 running 且可被正常取消。
func TestSteerRunningTaskWithoutTurnLoopKeepsTaskRunning(t *testing.T) {
	tm := NewAgentTaskManager()
	_, cancel := context.WithCancelCause(context.Background())
	task, err := tm.StartTask("conv-steer-keep", "运行中", cancel)
	if err != nil {
		t.Fatalf("StartTask: %v", err)
	}

	if got := tm.SteerRunningTask("conv-steer-keep", "补充指示"); got != SteerUnsupported {
		t.Fatalf("outcome = %v, want SteerUnsupported", got)
	}
	if snapshot := tm.GetTaskSnapshot("conv-steer-keep"); snapshot == nil || snapshot.Status != "running" {
		t.Fatalf("task snapshot = %+v, want running task", snapshot)
	}
	if ok, cancelErr := tm.CancelTask("conv-steer-keep", ErrTaskCancelled); !ok || cancelErr != nil {
		t.Fatalf("CancelTask: ok=%v err=%v", ok, cancelErr)
	}
	_ = tm.FinishTaskRun("conv-steer-keep", task.RunID, "cancelled")
}
