//go:build windows

package server

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Win32 calls the Windows agent account needs that golang.org/x/sys/windows does
// not wrap, and the ACL and DPAPI helpers built on it. See execpriv_windows.go.

var (
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modnetapi32 = windows.NewLazySystemDLL("netapi32.dll")
	moduser32   = windows.NewLazySystemDLL("user32.dll")

	procLogonUserW               = modadvapi32.NewProc("LogonUserW")
	procCreateProcessWithLogonW  = modadvapi32.NewProc("CreateProcessWithLogonW")
	procNetUserAdd               = modnetapi32.NewProc("NetUserAdd")
	procNetUserSetInfo           = modnetapi32.NewProc("NetUserSetInfo")
	procNetUserDel               = modnetapi32.NewProc("NetUserDel")
	procCreateWindowStationW     = moduser32.NewProc("CreateWindowStationW")
	procSetProcessWindowStation  = moduser32.NewProc("SetProcessWindowStation")
	procCloseWindowStation       = moduser32.NewProc("CloseWindowStation")
	procCreateDesktopW           = moduser32.NewProc("CreateDesktopW")
	procCloseDesktop             = moduser32.NewProc("CloseDesktop")
	procGetProcessWindowStation  = moduser32.NewProc("GetProcessWindowStation")
	procGetUserObjectInformation = moduser32.NewProc("GetUserObjectInformationW")
)

const (
	logon32LogonInteractive = 2
	logon32LogonNetwork     = 3
	logon32ProviderDefault  = 0

	logonWithProfile = 0x00000001

	// File access rights (winnt.h).
	fileReadData        = 0x0001 // FILE_LIST_DIRECTORY on a directory
	fileWriteData       = 0x0002 // FILE_ADD_FILE on a directory
	fileAppendData      = 0x0004 // FILE_ADD_SUBDIRECTORY on a directory
	fileReadEA          = 0x0008
	fileWriteEA         = 0x0010
	fileExecute         = 0x0020 // FILE_TRAVERSE on a directory
	fileDeleteChild     = 0x0040
	fileReadAttributes  = 0x0080
	fileWriteAttributes = 0x0100
	accessDelete        = 0x00010000
	accessReadControl   = 0x00020000
	accessWriteDAC      = 0x00040000
	accessWriteOwner    = 0x00080000
	accessSynchronize   = 0x00100000

	// What the agent account is granted or denied.
	aclRead      = fileReadData | fileReadEA | fileReadAttributes | accessReadControl | accessSynchronize
	aclReadExec  = aclRead | fileExecute
	aclWrite     = fileWriteData | fileAppendData | fileWriteEA | fileWriteAttributes | accessReadControl | accessSynchronize
	aclModify    = aclReadExec | aclWrite | fileDeleteChild | accessDelete
	aclDenyWrite = fileWriteData | fileAppendData | fileWriteEA | fileWriteAttributes | fileDeleteChild |
		accessDelete | accessWriteDAC | accessWriteOwner
	aclDenyAll = 0x001F01FF // FILE_ALL_ACCESS

	// User-object rights for the agent's window station and desktop.
	winstaAllAccess  = 0x037F
	desktopAllAccess = 0x01FF
	genericAll       = 0x10000000

	// Job object UI restrictions (winnt.h): every JOB_OBJECT_UILIMIT_* bit.
	jobUILimitAll = 0x00FF

	// NetUserAdd / NetUserSetInfo.
	userPrivUser         = 1
	ufScript             = 0x0001
	ufPasswdCantChange   = 0x0040
	ufDontExpirePasswd   = 0x10000
	nerrUserExists       = 2224
	nerrUserNotFound     = 2221
	nerrPasswordTooShort = 2245
)

// logonUser logs the account on with its password and returns the token.
func logonUser(account, password string, logonType uint32) (windows.Token, error) {
	u, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return 0, err
	}
	d, err := windows.UTF16PtrFromString(".")
	if err != nil {
		return 0, err
	}
	p, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return 0, err
	}
	var tok windows.Token
	r, _, e := procLogonUserW.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(p)),
		uintptr(logonType), logon32ProviderDefault, uintptr(unsafe.Pointer(&tok)))
	if r == 0 {
		return 0, fmt.Errorf("LogonUser %s: %w", account, e)
	}
	return tok, nil
}

// createProcessWithLogon starts app with cmdLine as the account. It needs no
// privilege: the Secondary Logon service creates the process.
func createProcessWithLogon(account, password, app, cmdLine string, flags uint32, env *uint16, dir string, si *windows.StartupInfo, pi *windows.ProcessInformation) error {
	u, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return err
	}
	d, err := windows.UTF16PtrFromString(".")
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	a, err := windows.UTF16PtrFromString(app)
	if err != nil {
		return err
	}
	// The command line buffer must be writable.
	cl, err := windows.UTF16FromString(cmdLine)
	if err != nil {
		return err
	}
	var cwd *uint16
	if dir != "" {
		if cwd, err = windows.UTF16PtrFromString(dir); err != nil {
			return err
		}
	}
	r, _, e := procCreateProcessWithLogonW.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(p)),
		logonWithProfile, uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(&cl[0])), uintptr(flags),
		uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(cwd)), uintptr(unsafe.Pointer(si)), uintptr(unsafe.Pointer(pi)))
	if r == 0 {
		return fmt.Errorf("CreateProcessWithLogonW: %w", e)
	}
	return nil
}

// userSID returns the user SID of a token as a string.
func tokenUserSID(t windows.Token) (string, error) {
	u, err := t.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// adminsSID is BUILTIN\Administrators.
const adminsSID = "S-1-5-32-544"

// tokenHasAdmins reports whether the token holds the Administrators group in any
// state: enabled, or deny-only as in a filtered (UAC) token.
func tokenHasAdmins(t windows.Token) (bool, error) {
	groups, err := t.GetTokenGroups()
	if err != nil {
		return false, err
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.String() == adminsSID {
			return true, nil
		}
	}
	return false, nil
}

// fileACE is one ACE that addACEs puts on a path for the agent account.
type fileACE struct {
	mode    windows.ACCESS_MODE // windows.GRANT_ACCESS or windows.DENY_ACCESS
	mask    uint32
	inherit uint32 // windows.NO_INHERITANCE, SUB_CONTAINERS_AND_OBJECTS_INHERIT, ...
}

// aceFlags maps the inheritance of EXPLICIT_ACCESS to the flags of the ACE it makes.
func aceFlags(inherit uint32) uint8 {
	var f uint8
	if inherit&windows.OBJECT_INHERIT_ACE != 0 {
		f |= windows.OBJECT_INHERIT_ACE
	}
	if inherit&windows.CONTAINER_INHERIT_ACE != 0 {
		f |= windows.CONTAINER_INHERIT_ACE
	}
	if inherit&windows.INHERIT_ONLY_ACE != 0 {
		f |= windows.INHERIT_ONLY_ACE
	}
	return f
}

// hasExplicitACE reports whether dacl already holds an explicit (not inherited) ACE
// of the type for sid that covers mask with the inheritance flags.
func hasExplicitACE(dacl *windows.ACL, sid *windows.SID, aceType uint8, mask uint32, flags uint8) bool {
	if dacl == nil {
		return false
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false
		}
		if ace.Header.AceType != aceType || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			continue
		}
		if ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE|windows.INHERIT_ONLY_ACE) != flags {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if aceSID.Equals(sid) && uint32(ace.Mask)&mask == mask {
			return true
		}
	}
	return false
}

// addACEs adds the ACEs for sid to the DACL of path, keeping what is there and its
// inheritance. ACEs already present are not added again, so a restart does not
// rewrite (and re-propagate) the DACL of a large tree. A path that is a reparse
// point (symlink or junction) is refused: its ACL would land on the target.
func addACEs(path string, sid *windows.SID, aces []fileACE) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("%s is a link or junction: refusing to change its permissions", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the permissions of %s: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return fmt.Errorf("read the permissions of %s: %w", path, err)
	}
	var entries []windows.EXPLICIT_ACCESS
	for _, a := range aces {
		inherit := a.inherit
		if !fi.IsDir() {
			inherit = windows.NO_INHERITANCE
		}
		aceType := uint8(windows.ACCESS_ALLOWED_ACE_TYPE)
		if a.mode == windows.DENY_ACCESS {
			aceType = windows.ACCESS_DENIED_ACE_TYPE
		}
		if hasExplicitACE(dacl, sid, aceType, a.mask, aceFlags(inherit)) {
			continue
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.ACCESS_MASK(a.mask),
			AccessMode:        a.mode,
			Inheritance:       inherit,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	if len(entries) == 0 {
		return nil
	}
	acl, err := windows.ACLFromEntries(entries, dacl)
	if err != nil {
		return fmt.Errorf("build the permissions of %s: %w", path, err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("set the permissions of %s: %w", path, err)
	}
	return nil
}

// protectFileForOwner gives path a protected DACL: full control for the user sid,
// SYSTEM and Administrators, nothing inherited. Used for the credential file.
func protectFileForOwner(path, ownerSID string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + ownerSID + ")")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// dpapiEntropy binds the credential blob to its use.
var dpapiEntropy = []byte("artex-exec-account-v1")

// dpapiProtect encrypts data for the current Windows user.
func dpapiProtect(data []byte) ([]byte, error) {
	return dpapiCall(data, true)
}

// dpapiUnprotect decrypts what dpapiProtect encrypted, as the same Windows user.
func dpapiUnprotect(data []byte) ([]byte, error) {
	return dpapiCall(data, false)
}

func dpapiCall(data []byte, protect bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty DPAPI input")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	ent := windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]}
	var out windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// newAgentWindowStation creates a window station and desktop that only the server's
// user and the agent account can use, and makes them the process's own, so that a
// process started on them cannot see or drive the interactive desktop, its windows
// or its clipboard. It returns the "station\desktop" name for STARTUPINFO and a
// function that closes both once the process has ended.
func newAgentWindowStation(name, serverSID, agentSID string) (string, func(), error) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;" + serverSID + ")(A;;GA;;;" + agentSID + ")")
	if err != nil {
		return "", nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	wn, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", nil, err
	}
	ws, _, e := procCreateWindowStationW.Call(uintptr(unsafe.Pointer(wn)), 0, winstaAllAccess, uintptr(unsafe.Pointer(sa)))
	if ws == 0 {
		return "", nil, fmt.Errorf("CreateWindowStation: %w", e)
	}
	prev, _, _ := procGetProcessWindowStation.Call()
	if r, _, e := procSetProcessWindowStation.Call(ws); r == 0 {
		procCloseWindowStation.Call(ws)
		return "", nil, fmt.Errorf("SetProcessWindowStation: %w", e)
	}
	dn, err := windows.UTF16PtrFromString("default")
	if err != nil {
		return "", nil, err
	}
	desk, _, e := procCreateDesktopW.Call(uintptr(unsafe.Pointer(dn)), 0, 0, 0, desktopAllAccess|genericAll, uintptr(unsafe.Pointer(sa)))
	if prev != 0 {
		procSetProcessWindowStation.Call(prev)
	}
	if desk == 0 {
		procCloseWindowStation.Call(ws)
		return "", nil, fmt.Errorf("CreateDesktop: %w", e)
	}
	closeFn := func() {
		procCloseDesktop.Call(desk)
		procCloseWindowStation.Call(ws)
	}
	return name + `\default`, closeFn, nil
}

// envBlockToList splits a Windows environment block into NAME=value entries.
func envBlockToList(block *uint16) []string {
	var out []string
	if block == nil {
		return out
	}
	for p := unsafe.Pointer(block); ; {
		s := windows.UTF16PtrToString((*uint16)(p))
		if s == "" {
			break
		}
		out = append(out, s)
		p = unsafe.Add(p, (len(windows.StringToUTF16(s)))*2)
	}
	return out
}

// envListToBlock builds a CREATE_UNICODE_ENVIRONMENT block from NAME=value entries.
func envListToBlock(env []string) (*uint16, error) {
	var b []uint16
	for _, kv := range env {
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			return nil, err
		}
		b = append(b, u...) // includes the terminating NUL
	}
	b = append(b, 0)
	if len(b) == 1 {
		b = append(b, 0)
	}
	return &b[0], nil
}
