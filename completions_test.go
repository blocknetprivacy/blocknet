package main

import (
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

// dispatchedCommands reads the command names from the switch in main.go,
// taking the first name of each case (so "version", not "--version").
func dispatchedCommands(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "switch args[0] {")
	end := strings.Index(body[start:], "default:")
	if start < 0 || end < 0 {
		t.Fatal("dispatch switch not found in main.go")
	}
	var cmds []string
	for _, m := range regexp.MustCompile(`case "([a-z]+)"`).FindAllStringSubmatch(body[start:start+end], -1) {
		cmds = append(cmds, m[1])
	}
	return cmds
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestCompletionsListEveryDispatchedCommand(t *testing.T) {
	cmds := dispatchedCommands(t)
	if len(cmds) < 15 {
		t.Fatalf("found only %d commands in main.go: %v", len(cmds), cmds)
	}
	scripts := map[string]string{
		"bash": captureStdout(t, printBashCompletion),
		"zsh":  captureStdout(t, printZshCompletion),
		"fish": captureStdout(t, printFishCompletion),
	}
	bashList := regexp.MustCompile(`commands="([^"]+)"`).FindStringSubmatch(scripts["bash"])
	if bashList == nil {
		t.Fatal("bash command list not found")
	}
	bashCmds := strings.Fields(bashList[1])
	if len(bashCmds) != len(cmds) {
		t.Errorf("bash lists %d commands, main.go dispatches %d", len(bashCmds), len(cmds))
	}
	for _, c := range cmds {
		if !strings.Contains(" "+bashList[1]+" ", " "+c+" ") {
			t.Errorf("bash: missing %s", c)
		}
		if !strings.Contains(scripts["zsh"], "'"+c+":") {
			t.Errorf("zsh: missing %s", c)
		}
		if !strings.Contains(scripts["fish"], "-a "+c+" -d") {
			t.Errorf("fish: missing %s", c)
		}
	}
	if !strings.Contains(scripts["zsh"], "compdef _blocknet blocknet bnt") {
		t.Error("zsh script does not register itself with compdef")
	}
}
