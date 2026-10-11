package app

import (
	"bytes"
	"html/template"
	"path/filepath"
	"testing"
)

func TestFrontendTemplatesRender(t *testing.T) {
	templates, err := template.ParseGlob(filepath.Join("..", "..", "web", "templates", "*"))
	if err != nil {
		t.Fatalf("server template initialization fails: %v", err)
	}
	var output bytes.Buffer
	if err = templates.ExecuteTemplate(&output, "index.html", map[string]interface{}{"Version": "test"}); err != nil {
		t.Fatal(err)
	}
}
