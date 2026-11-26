//go:build !windows

package server

import (
	"errors"
	"fmt"
	"os"
)

// The Windows agent account (execaccount_windows.go) does not apply here: on Linux
// agent processes run as the -exec-uid executor.

func resolveExecAccount(name, keyDir string, explicit bool) (ExecPrivilege, error) {
	if explicit && name != "-" {
		return ExecPrivilege{}, errors.New("-exec-account applies to Windows only: elsewhere agent processes run as -exec-uid")
	}
	return ExecPrivilege{}, nil
}

// RunExecAccountCommand answers "artex exec-account": a Windows command.
func RunExecAccountCommand(args []string) int {
	fmt.Fprintln(os.Stderr, "artex exec-account: the agent account is a Windows feature; on Linux agent processes run as -exec-uid")
	return 2
}

// execToolCommand returns the command line and environment of a custom tool. Here
// the process ARTEX starts is the tool itself; applyExecCredential sets its identity.
func execToolCommand(p ExecPrivilege, name string, args, env []string) (string, []string, []string, error) {
	return name, args, env, nil
}

// LongPath returns path unchanged: short names are a Windows matter.
func LongPath(path string) string { return path }
