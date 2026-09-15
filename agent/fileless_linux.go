//go:build linux

package main

// fileless_linux.go — fileless binary execution via memfd_create(2).
//
// How it works:
//
//  1. memfd_create(2) creates an anonymous file backed only by RAM — no
//     filesystem path, no inode in /tmp or anywhere else.
//
//  2. The ELF binary is written into this anonymous fd.
//
//  3. The kernel exposes the fd at /proc/self/fd/<n>.  This path CAN be
//     passed to execve(2) as if it were a regular file path.
//
//  4. We exec the binary by running /proc/self/fd/<n>.  The binary runs
//     in memory only.  No file creation event is emitted.  `ls /tmp`
//     will not show it.
//
// Detection signals to discuss in the tutorial:
//   - execve() where the path starts with "/proc/self/fd/" or "/memfd:"
//   - process with no backing file on disk (Falco rule: spawned_process_without_backing_file)
//   - Tetragon ProcessExec event where binary.path is empty string
//   - auditd: SYSCALL execve + EXECVE arg0 ~ /proc/*/fd/*

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// execFileless writes data to an anonymous memfd and executes it.
// stdout and stderr from the child process are written to the provided writers.
func execFileless(data []byte, args []string, stdout, stderr io.Writer) error {
	// Create anonymous in-memory file.
	// MFD_CLOEXEC is intentionally NOT set so the fd is inherited across
	// the fork+exec boundary.
	fd, err := unix.MemfdCreate("kworker", 0)
	if err != nil {
		return fmt.Errorf("memfd_create: %w", err)
	}

	// Wrap in *os.File for convenient Write.
	memFile := os.NewFile(uintptr(fd), "kworker")

	if _, err := memFile.Write(data); err != nil {
		_ = memFile.Close()
		return fmt.Errorf("write to memfd: %w", err)
	}

	// /proc/self/fd/<n> resolves to our anonymous in-memory binary.
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)

	argv := append([]string{procPath}, args...)

	// os/exec will fork+exec; because fd is not CLOEXEC it remains open in
	// the child and /proc/self/fd/<n> is still valid at execve time.
	cmd := newCmd(procPath, argv, stdout, stderr)

	// Keep memFile alive until the child has exec'd (cmd.Run closes it after).
	err = cmd.Run()
	_ = memFile.Close()
	return err
}
