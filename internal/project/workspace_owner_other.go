//go:build !linux

package project

func setWorkspaceOwner(string) error { return nil }
