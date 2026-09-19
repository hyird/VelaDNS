//go:build windows

package main

import (
	"os"
	"os/exec"
)

func configureProcess(_ *exec.Cmd) {}

func terminateProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func killProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func terminationSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
