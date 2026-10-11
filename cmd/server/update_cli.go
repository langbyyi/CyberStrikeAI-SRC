package main

import (
	"context"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/update"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The same one-click update the console page drives, for the two cases a page cannot
// serve: the process is not running at all, and somebody is ssh'd in with a keyboard.
// Keeping it in the binary rather than only in a shell script means one implementation of
// "fetch, fast-forward, rebuild, swap" instead of two that can disagree. The update
// source is read from the same config.yaml field the page saves to, so the keyboard and
// the button can never update from different repositories.
func updateCommandIfNeeded(configPath string, check, apply, rollback bool) (bool, int) {
	if !check && !apply && !rollback {
		return false, 0
	}
	root := filepath.Dir(configPath)
	repo, err := config.LoadUpdateRepo(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取更新源失败: %v\n", err)
		return true, 1
	}
	opts := update.Options{Root: root, Repo: repo}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	source := strings.TrimSpace(repo)
	if source == "" {
		source = update.DefaultRepoURL + "（官方仓库默认）"
	}
	fmt.Printf("安装目录：%s\n", root)
	fmt.Printf("更新源：%s\n", source)
	switch {
	case check:
		snap, err := update.Check(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "检查更新失败: %v\n", err)
			return true, 1
		}
		printSnapshot(snap)
		if !snap.Installed || snap.CheckError != "" {
			return true, 1
		}
		return true, 0
	case apply:
		res, err := update.Apply(ctx, opts, func(s update.Step) {
			fmt.Printf("[%s] %s\n", s.Phase, s.Message)
		})
		if res != nil {
			printResult(res)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "更新未完成: %v\n", err)
			return true, 1
		}
		fmt.Println("源码与二进制已就位；重启服务后新代码生效。")
		return true, 0
	case rollback:
		res, err := update.Rollback(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "回滚未完成: %v\n", err)
			return true, 1
		}
		printResult(res)
		return true, 0
	}
	return true, 0
}

func printSnapshot(s *update.Snapshot) {
	if !s.Installed {
		fmt.Printf("这个目录不是 git 工作树（%s），无法自动更新\n", s.Root)
		return
	}
	target := s.TargetBranch
	if target == "" {
		target = "?"
	}
	fmt.Printf("本机分支 %s / 提交 %s (%s)，更新源默认分支 %s\n", s.Branch, s.Commit, s.Subject, target)
	if s.CheckError != "" {
		fmt.Printf("检查失败：%s\n", s.CheckError)
		return
	}
	fmt.Printf("更新源最新 %s (%s)，落后 %d 个提交，本地领先 %d 个提交\n", s.RemoteCommit, s.RemoteSubject, s.Behind, s.Ahead)
	for _, c := range s.Incoming {
		fmt.Printf("  ○ %s %s\n", c.Commit, c.Subject)
	}
	if s.Behind > len(s.Incoming) {
		fmt.Printf("  …（共 %d 个，只列出 %d 个）\n", s.Behind, len(s.Incoming))
	}
	if len(s.BlockingChanges) > 0 {
		fmt.Printf("本机改过 %d 个源码文件，更新会拒绝执行：\n", len(s.BlockingChanges))
		for _, c := range s.BlockingChanges {
			fmt.Printf("  ! %s (%s)\n", c.Path, c.Status)
		}
	}
	if !s.CanBuild {
		fmt.Println("本机没有 Go 工具链：更新只搬源码，不会重编译")
	}
	if s.BuildPending {
		fmt.Println("上一次更新留下了未完成的编译（源码已就位、二进制还是旧的）：装好工具链后重跑更新即可补上")
	}
	if s.HasRollback {
		fmt.Printf("可回滚到 %s\n", s.RollbackTo)
	}
}

func printResult(r *update.Result) {
	moved := r.Commits > 0 || r.ToCommit != r.FromCommit
	if !moved && !r.BinaryBuilt {
		fmt.Println("已经是最新，没有改动")
		return
	}
	if moved {
		fmt.Printf("%s → %s（%d 个提交，涉及 %d 个文件，用时 %s）\n", r.FromCommit, r.ToCommit, r.Commits, r.FilesTouched, r.Duration)
	} else {
		// commits == 0 but a binary was built: a retry that finished a build the previous
		// attempt could not. Saying "已经是最新，没有改动" here would bury the one thing
		// that did happen.
		fmt.Printf("源码已经是最新（%s），本次补上了二进制\n", r.ToCommit)
	}
	if len(r.KeptContent) > 0 {
		fmt.Printf("保留了 %d 个本机内容文件（roles/skills/tools 等，没有被上游覆盖）：\n", len(r.KeptContent))
		for _, p := range r.KeptContent {
			fmt.Printf("  = %s\n", p)
		}
	}
	if r.BinaryBuilt {
		fmt.Printf("二进制已换新：%s（旧版本留在 %s 以便回滚）\n", r.BinaryPath, r.PrevBinary)
	}
}
