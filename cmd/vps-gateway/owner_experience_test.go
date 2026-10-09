package main

// Owner Experience Gate: exercise only CLI paths that reject their input
// BEFORE discovery, apply, service management or any system mutation.
// The built binary is invoked as a separate process so both human-readable
// messages and exit codes are validated.
import (
    "errors"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "testing"
)

func TestOwnerExperienceCLI(t *testing.T) {
    binary := filepath.Join(t.TempDir(), "vps-gateway")
    if runtime.GOOS == "windows" { binary += ".exe" }
    build := exec.Command("go", "build", "-o", binary, ".")
    if out, err := build.CombinedOutput(); err != nil {
        t.Fatalf("compile CLI fixture: %v\n%s", err, out)
    }

    cases := []struct {
        name string
        args []string
        want []string
    }{
        {"missing command", nil, []string{"usage: vps-gateway", "commands:", "doctor", "validate"}},
        {"unknown command", []string{"not-a-command"}, []string{"usage: vps-gateway", "commands:"}},
        {"doctor unsupported flag", []string{"doctor", "--unexpected"}, []string{"unknown doctor flag", "usage: vps-gateway doctor"}},
        {"validate unsupported flag", []string{"validate", "--unexpected"}, []string{"unknown validate flag", "usage: vps-gateway validate"}},
        {"discover unsupported flag", []string{"discover", "--unexpected"}, []string{"unknown discover flag", "usage: vps-gateway"}},
        {"install missing config argument", []string{"install", "--config"}, []string{"--config requires a file path"}},
        {"apply missing config argument", []string{"apply", "--config"}, []string{"--config requires a file path"}},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            cmd := exec.Command(binary, tc.args...)
            cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb")
            output, err := cmd.CombinedOutput()
            var exitErr *exec.ExitError
            if !errors.As(err, &exitErr) {
                t.Fatalf("expected explicit refusal exit 2, got %v; output: %s", err, output)
            }
            if code := exitErr.ExitCode(); code != 2 {
                t.Fatalf("expected exit 2, got %d; output: %s", code, output)
            }
            text := string(output)
            for _, phrase := range tc.want {
                if !strings.Contains(text, phrase) {
                    t.Errorf("missing actionable text %q in %q", phrase, text)
                }
            }
            if strings.Contains(text, "\x1b[") {
                t.Errorf("unexpected ANSI in NO_COLOR refusal: %q", text)
            }
        })
    }
}
