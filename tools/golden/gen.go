// Command gen regenerates the golden vectors in tools/golden/out.
//
// The vectors must come from the reference implementation (kcp-go), not from this port: that is the
// whole point of having them. Several of them (FEC framing) need unexported symbols, so the emitter
// lives in tools/golden/ref and is injected into the kcp-go package with `go test -overlay`. This
// driver wires that up, then checks the outputs exist.
//
// Usage:
//
//	go run gen.go
//
// Environment:
//
//	KCP_GO_DIR   path to the kcp-go checkout (default D:/work/kcp-go)
//	GO           go executable (default: `go` on PATH, else C:/Program Files/Go/bin/go.exe)
//	GOPROXY      honoured as-is; defaults to https://goproxy.cn,direct when unset
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	overlayTarget = "zz_kcp_cpp_golden_test.go"
	injectedFile  = "ref/golden_ref.go.txt"
	testName      = "TestEmitGoldenVectors"
	vectorFiles   = "crypt.json,rs.json,fec.json,kcp.json,frame.json"
)

type overlay struct {
	Replace map[string]string `json:"Replace"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gen: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	here, err := os.Getwd()
	if err != nil {
		return err
	}
	repoRoot := filepath.Dir(filepath.Dir(here)) // tools/golden -> repo root
	outDir := filepath.Join(repoRoot, "tools", "golden", "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	kcpGo := os.Getenv("KCP_GO_DIR")
	if kcpGo == "" {
		kcpGo = `D:\work\kcp-go`
	}
	kcpGo, err = filepath.Abs(kcpGo)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(kcpGo, "go.mod")); err != nil {
		return fmt.Errorf("KCP_GO_DIR=%s does not look like the kcp-go checkout: %w", kcpGo, err)
	}

	source := filepath.Join(here, filepath.FromSlash(injectedFile))
	if _, err := os.Stat(source); err != nil {
		return fmt.Errorf("emitter source missing: %w", err)
	}

	// The overlay key is a path that does not exist on disk; `go test` treats the replacement as
	// that file's contents. This keeps kcp-go untouched (no temp file inside the reference repo).
	overlayPath := filepath.Join(here, "overlay.json")
	payload, err := json.MarshalIndent(overlay{
		Replace: map[string]string{
			filepath.Join(kcpGo, overlayTarget): source,
		},
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(overlayPath, append(payload, '\n'), 0o644); err != nil {
		return err
	}
	defer os.Remove(overlayPath)

	goBin := os.Getenv("GO")
	if goBin == "" {
		if found, lookErr := exec.LookPath("go"); lookErr == nil {
			goBin = found
		} else {
			goBin = `C:\Program Files\Go\bin\go.exe`
		}
	}

	args := []string{
		"test",
		"-count=1",
		"-overlay=" + overlayPath,
		"-run", "^" + testName + "$",
		"-v",
		".",
	}
	cmd := exec.Command(goBin, args...)
	cmd.Dir = kcpGo
	cmd.Env = append(os.Environ(), "KCP_GOLDEN_OUT="+outDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if os.Getenv("GOPROXY") == "" {
		cmd.Env = append(cmd.Env, "GOPROXY=https://goproxy.cn,direct")
	}
	fmt.Printf("gen: emitting vectors from %s\n", kcpGo)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go test failed: %w", err)
	}

	for _, name := range strings.Split(vectorFiles, ",") {
		path := filepath.Join(outDir, name)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("missing output %s: %w", path, err)
		}
		if info.Size() < 100 {
			return fmt.Errorf("output %s is suspiciously small (%d bytes)", path, info.Size())
		}
		fmt.Printf("gen: %-11s %8d bytes\n", name, info.Size())
	}
	fmt.Println("gen: OK")
	return nil
}
