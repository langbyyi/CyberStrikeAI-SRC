package c2

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

// Execute only the shell helpers from the template, never its transport loop.
func TestBeaconShellTemplateSeparatesCwdAndPreservesExitStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell regression")
	}
	raw, err := os.ReadFile("payload_templates/beacon.go.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	raw = regexp.MustCompile(`\{\{\.(SleepSeconds|JitterPercent)\}\}`).ReplaceAll(raw, []byte("5"))
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "template.go", raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	var code bytes.Buffer
	code.WriteString(`package main
import("crypto/rand";"fmt";"os";"os/exec";"path/filepath";"runtime";"strings";"sync";"time")
var cwdMu sync.Mutex
var currentCwd string
func prepareHiddenCmd(cmd *exec.Cmd) {}
`)
	needed := map[string]bool{"taskShell": true, "runWithTimeout": true, "getTimeoutFromPayload": true, "shellByOS": true, "shellFlag": true}
	for _, declaration := range file.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok && needed[fn.Name.Name] {
			if err := format.Node(&code, fset, fn); err != nil {
				t.Fatal(err)
			}
			code.WriteByte('\n')
			delete(needed, fn.Name.Name)
		}
	}
	if len(needed) != 0 {
		t.Fatal("missing template helpers")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":   "module shellregression\ngo 1.23\n",
		"shell.go": code.String(),
		"shell_test.go": `package main
import("os";"path/filepath";"testing")
func TestShell(t *testing.T) {
 currentCwd=t.TempDir()
 cases:=[]struct{cmd,want string; failed bool}{
  {"printf hello","hello",false},
  {"printf 'hello\\n'","hello\n",false},
  {"printf hello;","hello",false},
  {"sleep 0.01;","",false},
  {"printf hello; false;","hello",true},
  {"printf hello # comment","hello",false},
 }
 for _, c:=range cases {out,_,_,failure:=taskShell(map[string]interface{}{"command":c.cmd}); if out!=c.want || (failure!="")!=c.failed {t.Fatalf("%q output=%q failure=%q",c.cmd,out,failure)} }
 target:=filepath.Join(currentCwd,"directory with spaces")
 if err:=os.Mkdir(target,0700);err!=nil{t.Fatal(err)}
 out,_,_,failure:=taskShell(map[string]interface{}{"command":"cd '"+target+"'; printf OK"})
 if out!="OK" || failure!="" || currentCwd!=target {t.Fatalf("cwd/output failure: %q %q",out,failure)}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "test", "-count=1", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell regression: %v\n%s", err, output)
	}
}
