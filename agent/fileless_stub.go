//go:build !linux

package main

// fileless_stub.go — non-Linux stub for execFileless.
// memfd_create is Linux-only; this stub allows the package to compile on
// macOS and Windows for local development.

import (
	"fmt"
	"io"
)

func execFileless(data []byte, args []string, stdout, stderr io.Writer) error {
	return fmt.Errorf("fileless execution is only supported on Linux (requires memfd_create syscall)")
}
