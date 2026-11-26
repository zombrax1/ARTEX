# Agent isolation on Windows

On Linux in the Docker image, everything an agent can run (its shell, custom tools, stdio MCP
servers) runs as a separate executor uid, and a startup self-test proves it cannot reach the
server's secrets. Run natively on Windows, ARTEX has no such boundary by default: agent processes
run as your Windows user and can read the JWT key, `secret.key`, `config.json` (database password,
LLM keys) and everything else in your profile. The dashboard says so ("Agent isolation is
degraded"), and binding to loopback does not change that: the problem is the identity agent tools
run under, not the network.

The Windows fix is the same design as Linux: a separate, non-admin local account that every agent
process runs as.

## Set it up

Once, from an elevated prompt (**Run as administrator**), signed in as the Windows user that runs
ARTEX, in the ARTEX folder:

```
artex.exe exec-account setup
```

This creates a standard local account (`artex-agent`; choose another name with `-account`), gives it
a random 32-character password that never expires, hides it from the sign-in screen (`-hide=false`
to keep it visible), creates its profile, and stores the credential in the key directory as
`exec-account.dpapi`, encrypted with DPAPI for your Windows user. Only your user can decrypt it.

Then restart ARTEX normally, **not** elevated. At start it finds the credential and:

- denies the agent account all access to `jwt.key`, `secret.key`, `config.json`, the credential and
  the MITM CA key, and writes to the data, key, config, skill and program directories (ACL entries
  for that account only; nothing changes for other users);
- shares the task run directories with the account (read and write inside, no delete or replace of
  the directory itself), and the spill, script and shim directories read-only;
- starts every agent process as the account through a shim (`data\exec-bin`): a copy of
  `artex.exe` named `powershell.exe` placed first on `PATH`, which is what the agent shell runs. The
  shim signs the account in with `CreateProcessWithLogonW`, on a private window station and desktop
  (no access to your windows, keyboard or clipboard), inside a Job Object that ends the whole process
  tree when the command ends or is cancelled. The process gets the account's own environment plus an
  allowlist (`PATH`, locale, proxy and CA variables, a tool's own parameters); none of the server's
  other variables cross;
- runs the file tools (reading, writing and searching files) impersonating the account;
- runs the self-test as the account and shows the dashboard as isolated only when it passes.

With an agent account set up, a failing self-test stops the start, as on Linux, and names what the
account can still reach. Fix it, or run `artex.exe -exec-account=- ...` to start without the account
(degraded, with the warning).

`artex.exe exec-account status` checks the credential and the sign-in. `artex.exe exec-account
remove` (elevated) deletes the account and the credential.

## Options

| Option | Effect |
| --- | --- |
| `-exec-account=<name>` | Require that account: the start fails if its credential is missing or does not match. |
| `-exec-account=-` | Do not use an agent account, even if one is set up. |
| `exec-account setup -account <name>` | Name of the account to create. |
| `exec-account setup -reuse` | Use an existing account of that name, resetting its password. Without it, setup refuses an account it did not create. |
| `exec-account setup -key-dir <dir>` | Where the credential goes (default: the ARTEX key directory, `ARTEX_JWT_KEY_DIR` or the program folder). |

## What to expect

- **Tools must be installed for all users.** The agent account cannot read your profile, so tools
  installed only for your user (for example under `%LOCALAPPDATA%`) are invisible to agents. Install
  Python, Node, nmap and the like for all users, or into a folder the account can read.
- **Background programs end with their command.** A process an agent command leaves running ends when
  that command ends (the Job Object). Long scans should run in the foreground or as a background task.
- **The Secondary Logon service** (`seclogon`) must not be disabled: `CreateProcessWithLogonW` uses it.
- **Policy.** Hosts that deny local accounts the "Access this computer from the network" right fall
  back to an interactive sign-in; if both are denied, the start says so.
- **The database.** The self-test also checks that the account cannot open a PostgreSQL session
  without the server's password. A local PostgreSQL that trusts loopback connections (`trust` in
  `pg_hba.conf`) fails it, correctly: use `scram-sha-256`.
- **Machine-wide environment variables** are readable by every Windows user, so a secret stored as a
  system variable reaches the agent account too. Keep secrets in `config.json` or in your user's
  variables.
