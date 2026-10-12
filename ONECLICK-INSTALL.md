# Gideon Rx OneClick · Gideon Rx 6.3.4-rc30 · Agent 2.4.56 · Gateway 2.4.3

The installer selects the supported guacd backend from the target operating
system. The operator does not promote an appliance or choose a virtualization
backend manually.

## Windows

Run:

```text
installers\WINDOWS\INSTALL_GIDEON_MASTER_WINDOWS.cmd
```

This is a **fresh installation** by default. It never imports `payload/data`,
database files, PKI material, service secrets, or machine environment values
from the bundle. The target creates its own PKI, tokens, Fernet key and empty
runtime state locally. A rerun preserves state that already belongs to that
same target server.

An operator may import a controlled production clone only by explicitly using
the clone mode with a bundle built for that purpose:

```text
installers\WINDOWS\INSTALL_GIDEON_MASTER_WINDOWS.cmd -InstallMode clone
```

Clone mode fails closed unless `payload/data` and the corresponding manifest
declarations are present. It sanitizes machine-specific agent/session state
before services start; it is not a shortcut for normal installation.

The launcher requests elevation automatically and applies this policy:

| Target | Automatic backend | OneClick actions |
|---|---|---|
| Windows Home / Core | Docker Desktop with WSL 2 | Enables `VirtualMachinePlatform` and WSL, schedules resume after a required reboot, starts the Linux Docker engine, verifies the pinned offline archive, and runs guacd only on `127.0.0.1`. |
| Windows Pro / Enterprise / Education / Server | Hyper-V Generation 2 | Enables Hyper-V, schedules resume after a required reboot, boots and validates the candidate, requires Secure Boot/cloud-init/offline Docker/TCP PASS evidence, promotes that exact SHA-256, and provisions the production VM. |

Docker Desktop itself must already be installed on Windows Home. OneClick does
not silently download it or accept its license. Once installed, rerunning the
same file completes the remaining configuration automatically.

The selected platform is recorded in:

```text
C:\ProgramData\GIDEON Remote Control\diagnostics\platform-selection.json
```

`master.config.json` uses `windows.guacd_backend: "auto"`. The explicit values
`hyperv` and `docker-desktop` are available for controlled deployments, but an
incompatible choice fails closed.

## Linux

Run:

```bash
bash installers/LINUX/INSTALL_GIDEON_MASTER_LINUX.sh
```

The launcher requests `sudo`, detects Debian/Ubuntu or RHEL-compatible package
management, installs missing packages from the offline cache first, and falls
back to the signed OS repositories. Set `GIDEON_ALLOW_ONLINE_INSTALL=0` to enforce
strict offline-only installation.

Linux runs the pinned guacd container bound to `127.0.0.1` and does not modify
the Docker daemon configuration or prune third-party images, networks, or
containers.

## First-login credentials and new Agents

On a new server, OneClick creates or rotates two WebAdmin accounts with distinct
random temporary passwords:

| User | Initial role | First-login policy |
|---|---|---|
| `dchaskypp` | `SUPERADMIN` | Password change and new MFA enrollment required. |
| `damautapp` | `ADMIN` | Password change and new MFA enrollment required. |

Passwords are never written to installer or diagnostic logs. Windows stores
them in
`C:\ProgramData\GIDEON Remote Control\secrets\bootstrap-credentials.txt`, whose
ACL grants access only to Administrators and SYSTEM. Linux stores them in
`/var/lib/gideon-remote-control/secrets/bootstrap-credentials.txt` with mode
`0600` and root ownership. The final screen shows the users and protected file
location. Delete the file after both passwords and MFA registrations have been
changed.

When deployment detects a different machine identity, it also rejects cloned
Agent authorization: old Agent records, enrollment grants, queued jobs and
per-Agent configuration are removed, while signed Agent release catalogs stay
available. New Agent installers can then be generated from WebAdmin and every
endpoint enrolls with a newly issued grant. A rerun on the same machine
preserves its users and enrolled Agents.

## Adaptive resource profiles

The portable launcher and native installer select an effective profile from
the host capacity. Set `GIDEON_RESOURCE_PROFILE` to `compact`, `standard`, or
`performance` only when an explicit override is required; the default is
`auto`.

| Profile | Automatic selection | Hyper-V memory (minimum/startup/maximum) | guacd limit |
|---|---|---|---|
| `compact` | 8–15 GiB RAM | 768/1536/1536 MiB, dynamic | 768 MiB / 1 CPU |
| `standard` | 16–31 GiB RAM | 1024/1536/2048 MiB, dynamic | 1024 MiB / 1 CPU |
| `performance` | 32+ GiB RAM and 8+ logical CPU | 1536/2048/4096 MiB, dynamic | 1536 MiB / 2 CPU |

On Windows, Backup remains an isolated SCM service but uses a native daily
scheduler at 03:17 and starts Python only while the backup is running. Updater
uses a native filesystem watcher for `updates\inbox\*.ready` and starts Python
only when an update arrives. Gateway, WebAdmin, Diagnostics, Coordinator, and
Agent remain continuously available. Linux already uses a systemd timer and
path unit for the same maintenance workloads.

The selected profile and effective limits are recorded in
`diagnostics/resource-profile.json`. The optimization reduces idle memory and
polling without reducing the product's logical connection, job, RDP, SSH, or
agent limits.

## Ubuntu external HTTPS and certificates

For Ubuntu external HTTPS and certificates, see
[Ubuntu external access and certificates](installers/LINUX/EXTERNAL-ACCESS-AND-CERTIFICATES.md).
The final Linux wizard can generate a private laboratory CA certificate, request
Let's Encrypt certificates after explicit consent, or validate/import PEM/PFX.
It publishes GIDEON directly on separate HTTPS ports (9443 admin, 443 agents by
default), restricts WebAdmin by source CIDR, preserves agent mTLS, and rolls
back configuration on a failed local HTTPS check. Google/DNS/firewall setup and
an actual remote functional test are still required. Use `GIDEON_EXTERNAL_ACCESS=later`
to keep the initial deployment private and complete publication later.

After installation, **Infrastructure → TLS y acceso externo** exposes the same
certificate workflow to SuperAdmin with fresh password + MFA. A socket-activated
Ubuntu broker handles the privileged changes; WebAdmin remains unprivileged.
Prepared requests expire after 30 minutes. Applied changes require confirmation
through the new HTTPS URL within five minutes, otherwise configuration is
restored. The installer registers the broker and boot-recovery units automatically.

## Reboots and recovery

When a Windows feature needs a reboot, OneClick registers a highest-privilege
task containing only the current installer path and options. Hyper-V resumes as
`SYSTEM` at startup; Docker Desktop resumes in the same administrator session
at the next logon so its WSL2 engine is available. The task removes itself when
installation resumes. The interactive launcher offers to restart immediately;
declining is safe because the next normal restart/logon resumes the same
installation.

All branches keep diagnostics and fail without promoting the Hyper-V candidate
when a required integrity or boot test does not pass.

## Portable OS-specific kits

For transport to another physical or virtual machine, use the generated kits
instead of compressing and extracting the complete 17,000-file source tree:

| Kit | Target | Modules transported |
|---|---|---|
| `GIDEON-WINDOWS-HOME-ONECLICK` | Windows 10/11 Home or Core | Common + Windows; automatically uses Docker Desktop/WSL 2. |
| `GIDEON-WINDOWS-HYPERV-ONECLICK` | Windows Pro/Enterprise/Education or Windows Server | Common + Windows + validated Hyper-V candidate. |
| `GIDEON-LINUX-ONECLICK` | Debian/Ubuntu or RHEL-compatible Linux | Common + Linux. |
| `GIDEON-UNIVERSAL-ONECLICK` | Any supported target | Contains all profiles and selects the Windows backend automatically. |

Each kit contains only a few large `.tar.gz` module files. Do not extract them
manually. Run `INSTALL_GIDEON_ONECLICK.cmd` on Windows or
`bash INSTALL_GIDEON_ONECLICK.sh` on the Linux-specific kit. The universal kit
uses `bash INSTALL_GIDEON_ONECLICK_LINUX.sh`. The portable bootstrap verifies every
module with SHA-256, extracts it once to a short local cache under
`C:\ProgramData\GIDEON\PackageCache` or `/var/cache/gideon-oneclick`, and then runs
the original OS installer. Reruns reuse the verified cache.

The Hyper-V deploy kit intentionally excludes the 595 MiB Ubuntu source image
because `dependency-lock.json` marks it `build_only` and `required: false`; it
does include the finished candidate VHDX and its offline bootstrap. The kits
contain protected bootstrap material needed by the product, so transport media
must be encrypted and access-controlled. Portable kits are clean by default:
they exclude `payload/data`, cloned databases, PKI and secrets. Linux defaults
to `GIDEON_INSTALL_MODE=fresh`; Windows defaults to `-InstallMode fresh`.

To create a controlled clone kit, use the explicit opt-in below and then start
the Windows installer with `-InstallMode clone` (or Linux with
`GIDEON_INSTALL_MODE=clone`). Keep that kit encrypted and access-controlled:

```text
installers\tools\BUILD_GIDEON_PORTABLE_KITS.cmd --include-clone-state
```

To rebuild all kits, run:

```text
installers\tools\BUILD_GIDEON_PORTABLE_KITS.cmd
```

The default output is a sibling directory named
`<bundle>-PORTABLE`. The module store uses hard links when the filesystem
supports them, so keeping all four generated kits locally does not duplicate
the large archives. When copying to the destination, copy only the required kit.

For a thin network installer, keep the launcher and `profiles` directory, host
the named module files on HTTP/HTTPS, and set `GIDEON_PACKAGE_BASE_URL` before
launching. Windows downloads through BITS and Linux uses resumable `curl`.

## Cross-platform fail-closed checks

The portable and native installers now reject incompatible hosts before the
main application deployment:

| Target | Checks performed before deployment |
|---|---|
| All Windows | Windows x64, supported client/server build, at least 8 GiB RAM and 4 logical processors, adaptive resource profile, event-driven maintenance, available disk space, Windows Time automatically enabled/started when required, matching package/profile/module hashes, relocated private Python venv binding, and a freshly compiled canonical service host. |
| Windows Home / Docker | Docker Desktop must already be installed and licensed; WSL 2 features must exist; VT-x/AMD-V, firmware virtualization and SLAT are checked before enabling missing features. |
| Windows Pro/Enterprise/Server / Hyper-V | Hyper-V edition support, VT-x/AMD-V, firmware virtualization and SLAT are checked before enabling the role. A virtual machine without nested virtualization fails with an explicit host-hypervisor message. |
| Linux | Linux x86_64/amd64 only, supported Debian/RHEL family, active systemd, at least 8 GiB RAM, 4 logical processors and 8 GiB free, Python 3.11+ with `venv`, `iproute2`, synchronized time and working container tooling. Missing OS packages are installed offline first or from configured signed repositories when allowed. |

The root `package.modules.sha256` is the canonical transport lock. Windows and
Linux rebuild a missing or stale profile from that package metadata. A module
whose bytes do not match the canonical lock is treated as a mixed-version kit
and is never extracted. macOS is supported only where the product provides an
agent workflow; it is not a supported Gideon Rx Master server target.
