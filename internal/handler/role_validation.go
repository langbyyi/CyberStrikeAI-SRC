package handler

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"cyberstrike-ai/internal/config"
)

func validateRoleName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("角色名称不能为空")
	}
	if name != strings.TrimSpace(name) || utf8.RuneCountInString(name) > 64 {
		return fmt.Errorf("角色名称不能包含首尾空格，长度不能超过 64 个字符")
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\:*?"<>|`) {
		return fmt.Errorf("角色名称不能包含路径或文件名特殊字符")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("角色名称不能包含控制字符")
		}
	}
	return nil
}

func (h *RoleHandler) validateRole(role config.RoleConfig) error {
	if err := validateRoleName(role.Name); err != nil {
		return err
	}
	// Spaces are kept in display names but mapped to underscores on disk.
	for key, existing := range h.config.Roles {
		name := existing.Name
		if name == "" {
			name = key
		}
		if name != role.Name && strings.EqualFold(sanitizeFileName(name), sanitizeFileName(role.Name)) {
			return fmt.Errorf("角色名称与已有角色的文件名冲突")
		}
	}
	if strings.TrimSpace(role.WorkflowID) != "" {
		if h.db == nil {
			return fmt.Errorf("工作流存储不可用，无法验证绑定")
		}
		wf, err := h.db.GetWorkflowDefinition(role.WorkflowID)
		if err != nil {
			return fmt.Errorf("无法验证工作流绑定: %w", err)
		}
		if wf == nil {
			return fmt.Errorf("角色绑定的工作流不存在")
		}
	}
	return nil
}
