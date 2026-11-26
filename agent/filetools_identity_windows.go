//go:build windows

package agent

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const fileIdentitySupported = true

// runWithFileIdentity runs fn on a thread of its own that impersonates the agent
// account: SetThreadToken puts the account's impersonation token on that thread
// only, so every open, create and directory read in fn is checked against the
// account's rights, the rights of the agent's shell, on top of the os.Root
// confinement. The thread is locked to its goroutine and never unlocked, so the Go
// runtime ends it when the goroutine returns, on a panic or runtime.Goexit in fn too:
// no other goroutine ever runs with the token. A panic in fn is raised again in the
// caller.
//
// The token covers fn's own goroutine only: a goroutine fn starts runs on another
// thread with the server's identity, and a process fn would start gets the server's
// primary token. fn must open everything itself, and start nothing.
func runWithFileIdentity(id FileToolIdentity, fn func()) error {
	if id.Token == 0 {
		return errors.New("file tool identity: no agent account token")
	}
	done := make(chan error, 1)
	var panicked any
	go func() {
		runtime.LockOSThread()
		if err := enterFileIdentity(windows.Token(id.Token)); err != nil {
			done <- err
			return
		}
		defer func() {
			panicked = recover()
			done <- nil
		}()
		fn()
	}()
	err := <-done
	if panicked != nil {
		panic(panicked)
	}
	return err
}

// enterFileIdentity impersonates tok on the calling thread and checks that the
// thread token is in place at impersonation level: Windows can quietly lower an
// impersonation it does not allow to identification level, where every open fails.
func enterFileIdentity(tok windows.Token) error {
	if err := windows.SetThreadToken(nil, tok); err != nil {
		return fmt.Errorf("file tool identity: SetThreadToken: %w", err)
	}
	var cur windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &cur); err != nil {
		return fmt.Errorf("file tool identity: the thread token did not take effect: %w", err)
	}
	defer cur.Close()
	var level, n uint32
	if err := windows.GetTokenInformation(cur, windows.TokenImpersonationLevel, (*byte)(unsafe.Pointer(&level)), 4, &n); err != nil {
		return fmt.Errorf("file tool identity: read the impersonation level: %w", err)
	}
	if level < windows.SecurityImpersonation {
		return fmt.Errorf("file tool identity: impersonation level %d, want impersonation (%d)", level, windows.SecurityImpersonation)
	}
	return nil
}

// workRootAncestorsAsServer: see openWorkRoot.
const workRootAncestorsAsServer = true
