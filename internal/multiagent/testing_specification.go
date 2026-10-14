package multiagent

import (
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/project"
	"fmt"
	"strings"
)

func taskSpecificationContext(db *database.DB, conversationID, extra string) (string, string, error) {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return extra, "", nil
	}
	block, err := db.ConversationTestingSpecificationBlock(conversationID)
	if err != nil {
		return "", "", fmt.Errorf("读取任务测试规范失败: %w", err)
	}
	if block != "" && !strings.Contains(extra, block) {
		extra = project.AppendSystemPromptBlock(extra, block)
	}
	return extra, block, nil
}
