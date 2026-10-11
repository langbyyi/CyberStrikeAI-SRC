package handler

import "cyberstrike-ai/internal/database"

func publicWebshellConnection(conn *database.WebShellConnection) *database.WebShellConnection {
	if conn == nil {
		return nil
	}
	public := *conn
	if public.Password != "" {
		public.Password = maskedSecret
	}
	return &public
}
