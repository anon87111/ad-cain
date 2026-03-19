# AD-Cain

Active Directory lab state snapshot & restore tool. Export the logical structure of an AD environment to a JSON file, then import it onto a fresh Domain Controller to replicate the lab.

Built for home lab use — snapshot a configured AD lab and spin up identical copies on Proxmox/KVM infrastructure without manually recreating every object.

## What It Captures

- **Organizational Units** — full OU hierarchy with descriptions and metadata
- **Users** — accounts, attributes, group memberships, password policies (not passwords)
- **Groups** — security & distribution groups with members, scope, and nesting
- **Computers** — machine accounts, OS info, DNS names, managed-by references
- **Group Policy Objects** — GPC containers from LDAP + GPT files from SYSVOL
- **Domain Trusts** — trust relationships with direction, type, and filtering settings

## Installation

```bash
git clone https://github.com/anon87111/ad-cain.git
cd ad-cain
pip install -e .
```

Or install dependencies directly:

```bash
pip install -r requirements.txt
```

Requires Python 3.10+.

## Usage

### Export

Snapshot an AD environment to a JSON state file:

```bash
ad-cain export \
  -s dc01.lab.local \
  -u administrator@lab.local \
  -o lab_state.json
```

With GPO file export (requires mounted SYSVOL):

```bash
ad-cain export \
  -s dc01.lab.local \
  -u administrator@lab.local \
  -o lab_state.json \
  --sysvol /mnt/sysvol/lab.local
```

### Restore

Recreate the AD structure on a fresh DC:

```bash
ad-cain restore \
  -s homelab-dc.home.local \
  -u administrator@home.local \
  -f lab_state.json
```

Preview what would be created without making changes:

```bash
ad-cain restore \
  -s homelab-dc.home.local \
  -u administrator@home.local \
  -f lab_state.json \
  --dry-run
```

Selectively skip object types:

```bash
ad-cain restore -s dc01 -u admin@home.local -f lab_state.json \
  --skip-gpos \
  --skip-trusts
```

### Validate

Check a state file for schema correctness and dangling references:

```bash
ad-cain validate -f lab_state.json
```

### Info

Display a summary of a state file:

```bash
ad-cain info -f lab_state.json
```

## State File

The export produces a single JSON file containing all captured AD objects. The format is human-readable and diffable — useful for versioning lab configurations in Git.

A sample state file is included at `examples/sample_state.json`.

## Restore Order

Objects are created in strict dependency order to ensure references resolve correctly:

1. Organizational Units (sorted root-to-leaf)
2. Users
3. Computers
4. Groups (created first, then memberships populated)
5. GPOs (GPC in LDAP + GPT files to SYSVOL + links)
6. Trusts (logged for manual recreation — trusts require shared secrets)

## CLI Reference

| Command | Description |
|---------|-------------|
| `ad-cain export` | Export AD state to JSON |
| `ad-cain restore` | Restore AD state from JSON |
| `ad-cain validate` | Validate a state file |
| `ad-cain info` | Display state file summary |

Common flags:

- `-s, --server` — DC hostname or IP
- `-P, --port` — LDAP port (default: 389)
- `-u, --username` — bind username (UPN or `DOMAIN\user`)
- `-p, --password` — bind password (prompts if omitted)
- `--ssl` — use LDAPS (port 636)
- `-v, --verbose` — debug logging

## Notes

- **Passwords are never exported.** Restored users are created with a default password (`ChangeMe123!` or set via `--default-password`) and can be configured to require a password change at first logon.
- **Password setting requires LDAPS.** The restore command needs an SSL connection to set user passwords on the target DC.
- **Trusts require manual setup.** Trust relationships need shared secrets and bidirectional configuration, so AD-Cain logs the trust details for you to recreate manually.
- **DN rebasing is automatic.** If the source domain is `lab.example.com` and the target is `home.local`, all Distinguished Names are rewritten during restore.

## Project Structure

```
ad_cain/
├── cli.py              # Click CLI entry point
├── config.py           # Configuration management
├── logger.py           # Logging setup
├── core/
│   ├── connection.py   # LDAP connection manager
│   ├── exporter.py     # Export orchestration
│   ├── importer.py     # Import orchestration
│   └── validator.py    # State file validation
├── models/             # Pydantic data models
├── extraction/         # Per-object-type export logic
├── restoration/        # Per-object-type import logic
├── sysvol/             # GPO file read/write
└── utils/              # DN parsing, errors, encoders
```