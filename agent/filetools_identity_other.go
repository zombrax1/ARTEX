//go:build !linux && !windows

package agent

import "errors"

const fileIdentitySupported = false

// runWithFileIdentity: per-thread file system ids exist on Linux only. The server
// sets no identity where FileToolIdentitySupported is false; one set anyway fails
// closed.
func runWithFileIdentity(FileToolIdentity, func()) error {
	return errors.New("the file tools cannot run as another identity on this platform")
}

const workRootAncestorsAsServer = false
