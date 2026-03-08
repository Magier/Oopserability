package main

// exec_helper.go — os/exec helpers shared across platform builds.

import (
	"io"
	"os/exec"
)

// newCmd constructs an *exec.Cmd with the given path, argv, stdout, and stderr.
// Stdin is always nil (no interactive input).
func newCmd(path string, argv []string, stdout, stderr io.Writer) *exec.Cmd {
	cmd := &exec.Cmd{
		Path:   path,
		Args:   argv,
		Stdout: stdout,
		Stderr: stderr,
	}
	return cmd
}
