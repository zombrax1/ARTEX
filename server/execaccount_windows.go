//go:build windows

package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Autumn-27/artex/config"
)

// The Windows agent account: a separate, non-admin local account that every agent
// process runs as (execpriv_windows.go). "artex exec-account setup", run once from
// an elevated prompt by the Windows user that runs ARTEX, creates it with a random
// password and stores the credential in the key directory, encrypted with DPAPI for
// that user: only that user's processes can decrypt it, and the agent account is
// denied the file.

// DefaultExecAccount is the account name setup creates when -account is not given.
const DefaultExecAccount = "artex-agent"

// execCredName is the credential file in the key directory.
const execCredName = "exec-account.dpapi"

// execAccountComment marks an account setup created, so that setup never takes over
// an account it did not create unless the operator says so (-reuse).
const execAccountComment = "ARTEX agent tools (created by artex exec-account setup)"

type execCred struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

func execCredPath(keyDir string) string { return filepath.Join(keyDir, execCredName) }

// loadExecCred reads and decrypts the credential file. An absent file returns an
// error that wraps fs.ErrNotExist.
func loadExecCred(path string) (execCred, error) {
	var c execCred
	blob, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	plain, err := dpapiUnprotect(blob)
	if err != nil {
		return c, fmt.Errorf("decrypt %s: %w (it can only be read by the Windows user that ran \"artex exec-account setup\")", path, err)
	}
	if err := json.Unmarshal(plain, &c); err != nil || c.Account == "" || c.Password == "" {
		return execCred{}, fmt.Errorf("%s holds no agent account credential", path)
	}
	return c, nil
}

// saveExecCred encrypts c for the current user and writes it to path, readable only
// by ownerSID, SYSTEM and Administrators.
func saveExecCred(path string, c execCred, ownerSID string) error {
	plain, err := json.Marshal(c)
	if err != nil {
		return err
	}
	blob, err := dpapiProtect(plain)
	if err != nil {
		return fmt.Errorf("encrypt the credential: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	if err := protectFileForOwner(tmp, ownerSID); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("restrict %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// logonExecAccount logs the agent account on and returns its token: a network logon
// first, which needs no "log on locally" right and loads no profile, then an
// interactive one for hosts whose policy denies local accounts network logons.
func logonExecAccount(c execCred) (windows.Token, error) {
	tok, err := logonUser(c.Account, c.Password, logon32LogonNetwork)
	if err == nil {
		return tok, nil
	}
	tok, err2 := logonUser(c.Account, c.Password, logon32LogonInteractive)
	if err2 == nil {
		return tok, nil
	}
	return 0, fmt.Errorf("log on the agent account %s: %v; %v", c.Account, err, err2)
}

// lookupLocalUser returns the SID of the local user account name.
func lookupLocalUser(name string) (*windows.SID, error) {
	sid, _, accType, err := windows.LookupSID("", name)
	if err != nil {
		return nil, err
	}
	if accType != windows.SidTypeUser {
		return nil, fmt.Errorf("%s is not a user account", name)
	}
	return sid, nil
}

// currentUserSID is the user SID of this process.
func currentUserSID() (string, error) {
	return tokenUserSID(windows.GetCurrentProcessToken())
}

func resolveExecAccount(name, keyDir string, explicit bool) (ExecPrivilege, error) {
	if name == "-" {
		logExecOnce("[exec] -exec-account=-: agent processes keep the server's identity")
		return ExecPrivilege{}, nil
	}
	path := execCredPath(keyDir)
	cred, err := loadExecCred(path)
	if errors.Is(err, fs.ErrNotExist) {
		if explicit {
			return ExecPrivilege{}, fmt.Errorf("-exec-account=%s: no credential at %s; run \"artex exec-account setup -account %s\" from an elevated prompt as the Windows user that runs ARTEX", name, path, name)
		}
		logExecOnce("[exec] no agent account is set up (\"artex exec-account setup\", see docs/windows-agent-isolation.md): agent processes run with the server's identity")
		return ExecPrivilege{}, nil
	}
	if err != nil {
		// The operator set an account up: never fall back to the server's identity.
		return ExecPrivilege{}, fmt.Errorf("agent account: %w", err)
	}
	if name != "" && !strings.EqualFold(name, cred.Account) {
		return ExecPrivilege{}, fmt.Errorf("-exec-account=%s, but %s holds the credential of %s", name, path, cred.Account)
	}
	sid, err := lookupLocalUser(cred.Account)
	if err != nil {
		return ExecPrivilege{}, fmt.Errorf("agent account %s: %w", cred.Account, err)
	}
	self, err := currentUserSID()
	if err != nil {
		return ExecPrivilege{}, err
	}
	if sid.String() == self {
		return ExecPrivilege{}, fmt.Errorf("agent account %s is the Windows user ARTEX runs as: it must be a separate account", cred.Account)
	}
	return ExecPrivilege{Enabled: true, Account: cred.Account, SID: sid.String(), cred: path}, nil
}

// RunExecAccountCommand runs "artex exec-account <setup|status|remove>".
func RunExecAccountCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: artex exec-account setup|status|remove [-account name] [-key-dir dir]")
		return 2
	}
	fsFlags := flag.NewFlagSet("exec-account "+args[0], flag.ContinueOnError)
	account := fsFlags.String("account", DefaultExecAccount, "name of the local account agent processes run as")
	keyDir := fsFlags.String("key-dir", config.KeyDir(), "ARTEX key directory (holds jwt.key and the account credential)")
	reuse := fsFlags.Bool("reuse", false, "setup: use an account of that name that already exists, resetting its password")
	hide := fsFlags.Bool("hide", true, "setup: hide the account from the sign-in screen")
	if err := fsFlags.Parse(args[1:]); err != nil {
		return 2
	}
	var err error
	switch args[0] {
	case "setup":
		err = execAccountSetup(*account, *keyDir, *reuse, *hide)
	case "status":
		err = execAccountStatus(*keyDir)
	case "remove":
		err = execAccountRemove(*account, *keyDir)
	default:
		fmt.Fprintf(os.Stderr, "artex exec-account: unknown command %q\n", args[0])
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "artex exec-account %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

// userInfo1 is USER_INFO_1 (lmaccess.h).
type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

func netStatus(r uintptr, what string) error {
	if r == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", what, windows.Errno(r))
}

// randomPassword returns a 32-character password with upper and lower case letters,
// digits and symbols, which every Windows complexity policy accepts.
func randomPassword() (string, error) {
	classes := []string{"ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!#%+-.:=?@_~"}
	all := strings.Join(classes, "")
	pick := func(set string) (byte, error) {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return 0, err
		}
		return set[n.Int64()], nil
	}
	b := make([]byte, 32)
	for i := range b {
		set := all
		if i < len(classes) {
			set = classes[i]
		}
		c, err := pick(set)
		if err != nil {
			return "", err
		}
		b[i] = c
	}
	// Shuffle so the class-guaranteed characters are not always first.
	for i := len(b) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := n.Int64()
		b[i], b[j] = b[j], b[i]
	}
	return string(b), nil
}

// accountComment returns the comment of an existing local account.
func accountComment(name string) (string, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var buf *byte
	if err := windows.NetUserGetInfo(nil, n, 1, &buf); err != nil {
		return "", err
	}
	defer windows.NetApiBufferFree(buf)
	ui := (*userInfo1)(unsafe.Pointer(buf))
	if ui.Comment == nil {
		return "", nil
	}
	return windows.UTF16PtrToString(ui.Comment), nil
}

func execAccountSetup(account, keyDir string, reuse, hide bool) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("run this from an elevated prompt (Run as administrator), signed in as the Windows user that runs ARTEX: creating a local account needs administrator rights, and the credential is encrypted for that user")
	}
	if account == "" || strings.ContainsAny(account, `\/"[]:|<>+=;,?*@`) {
		return fmt.Errorf("invalid account name %q", account)
	}
	self, err := currentUserSID()
	if err != nil {
		return err
	}
	password, err := randomPassword()
	if err != nil {
		return err
	}
	name, _ := windows.UTF16PtrFromString(account)
	pw, _ := windows.UTF16PtrFromString(password)
	comment, _ := windows.UTF16PtrFromString(execAccountComment)
	ui := userInfo1{Name: name, Password: pw, Priv: userPrivUser, Comment: comment,
		Flags: ufScript | ufDontExpirePasswd | ufPasswdCantChange}
	var parmErr uint32
	r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&ui)), uintptr(unsafe.Pointer(&parmErr)))
	switch {
	case r == 0:
		fmt.Printf("Created the local account %s.\n", account)
	case r == nerrUserExists:
		// Never reset the password of the operator's own account.
		if sid, err := lookupLocalUser(account); err != nil {
			return fmt.Errorf("look up the existing account %s: %w", account, err)
		} else if sid.String() == self {
			return fmt.Errorf("%s is the Windows user you are signed in as: the agent account must be a separate account", account)
		}
		c, err := accountComment(account)
		if err != nil {
			return fmt.Errorf("read the existing account %s: %w", account, err)
		}
		if c != execAccountComment && !reuse {
			return fmt.Errorf("an account named %s already exists and was not created by this command; choose another -account, or pass -reuse to reset its password and use it", account)
		}
		info := struct{ Password *uint16 }{pw} // USER_INFO_1003
		r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(name)), 1003, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parmErr)))
		if err := netStatus(r, "reset the password of "+account); err != nil {
			return err
		}
		fmt.Printf("Reset the password of the existing account %s.\n", account)
	default:
		return netStatus(r, "create the account "+account)
	}
	sid, err := lookupLocalUser(account)
	if err != nil {
		return err
	}
	if sid.String() == self {
		return fmt.Errorf("%s is the Windows user you are signed in as: the agent account must be a separate account", account)
	}
	cred := execCred{Account: account, Password: password}
	tok, err := logonExecAccount(cred)
	if err != nil {
		return err
	}
	admin, err := tokenHasAdmins(tok)
	tok.Close()
	if err != nil {
		return err
	}
	if admin {
		return fmt.Errorf("%s is a member of Administrators: remove it from that group, the agent account must be a standard user", account)
	}
	if hide {
		if err := hideFromSignIn(account); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not hide %s from the sign-in screen: %v\n", account, err)
		}
	}
	path := execCredPath(keyDir)
	if err := saveExecCred(path, cred, self); err != nil {
		return fmt.Errorf("store the credential in %s: %w", path, err)
	}
	if err := createAgentProfile(cred); err != nil {
		fmt.Fprintf(os.Stderr, "warning: the first sign-in of %s failed (%v); ARTEX will retry at its first agent command\n", account, err)
	}
	fmt.Printf("Stored the credential in %s (encrypted for the current Windows user).\n", path)
	fmt.Println("Restart ARTEX as this same Windows user, without elevation. Agent shells, custom tools and MCP")
	fmt.Println("servers then run as " + account + "; the startup self-test checks the isolation and the dashboard")
	fmt.Println("warning goes away once it passes.")
	return nil
}

// hideFromSignIn keeps the account off the Windows sign-in screen.
func hideFromSignIn(account string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(account, 0)
}

// createAgentProfile signs the account in once with its profile, so that Windows
// creates the profile now rather than on the first agent command.
func createAgentProfile(c execCred) error {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	cmd := filepath.Join(sysRoot, "System32", "cmd.exe")
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_HIDE}
	var pi windows.ProcessInformation
	if err := createProcessWithLogon(c.Account, c.Password, cmd, `cmd.exe /d /c exit 0`, 0, nil, sysRoot, &si, &pi); err != nil {
		return err
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	_, err := windows.WaitForSingleObject(pi.Process, 60_000)
	return err
}

func execAccountStatus(keyDir string) error {
	path := execCredPath(keyDir)
	cred, err := loadExecCred(path)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Printf("No agent account is set up (%s does not exist). Agent processes run with the server's identity.\n", path)
		return nil
	}
	if err != nil {
		return err
	}
	tok, err := logonExecAccount(cred)
	if err != nil {
		return err
	}
	defer tok.Close()
	admin, err := tokenHasAdmins(tok)
	if err != nil {
		return err
	}
	if admin {
		return fmt.Errorf("the agent account %s is a member of Administrators", cred.Account)
	}
	fmt.Printf("Agent account %s is set up and signs in. The ARTEX startup self-test reports whether the isolation holds.\n", cred.Account)
	return nil
}

func execAccountRemove(account, keyDir string) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("run this from an elevated prompt (Run as administrator)")
	}
	path := execCredPath(keyDir)
	if cred, err := loadExecCred(path); err == nil && account == DefaultExecAccount {
		account = cred.Account
	}
	c, err := accountComment(account)
	if err != nil {
		return fmt.Errorf("read the account %s: %w", account, err)
	}
	if c != execAccountComment {
		return fmt.Errorf("%s was not created by \"artex exec-account setup\": remove it yourself if you mean to", account)
	}
	name, _ := windows.UTF16PtrFromString(account)
	r, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(name)))
	if err := netStatus(r, "delete the account "+account); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(account)
		k.Close()
	}
	fmt.Printf("Deleted the account %s and its credential. Its profile folder under C:\\Users stays; delete it in System Properties > User Profiles.\n", account)
	return nil
}
