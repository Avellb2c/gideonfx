# GIDEON-GUACD Hyper-V appliance contract

`GIDEON-GUACD-UBUNTU.vhdx` is not an arbitrary Ubuntu disk. The Master Builder
treats it as a versioned, security-sensitive prerequisite.

The validated appliance must provide:

- Ubuntu Server minimal, Generation 2 / UEFI compatible.
- Secure Boot compatible with the Hyper-V
  `MicrosoftUEFICertificateAuthority` template.
- No graphical desktop.
- `cloud-init` with NoCloud support enabled.
- Primary Hyper-V NIC uses the `hv_netvsc` driver and is deterministically
  renamed to `eth0` by the NoCloud network configuration.
- Ability to run the SHA-256-pinned Docker Engine static bundle copied from
  `offline-cache/hyperv/bootstrap`; no network installation is allowed.
- NTFS read support for the attached `GIDEONDATA` VHDX.
- No default interactive password.
- SSH disabled by default unless an explicit GIDEON break-glass policy enables it.
- No Docker images need to be embedded; the installer loads the exact image
  captured from the working GIDEON production installation.
- Automatic security updates should be controlled by the GIDEON appliance release
  process so deployments remain reproducible.
- The appliance must never expose guacd outside its Hyper-V Internal vSwitch.
- The physical Windows NIC may remain DHCP. The private `/28` is exclusively
  Host <-> GIDEON-GUACD VM.

The dependency must be pinned in the GIDEON dependency lock by version and SHA-256.
The production installer refuses to invent or silently download an unpinned VHDX.
It also refuses a candidate whose lock entry is not marked
`VALIDATED_HYPERV_BOOT` and backed by a validation report.

## Build and promotion flow

In an end-user installation, `INSTALL_GIDEON_MASTER_WINDOWS.cmd` orchestrates
steps 4 through 6 automatically when the detected Windows edition supports
Hyper-V. A failure in any validation step prevents promotion and deployment.

1. Download the fixed Ubuntu 24.04 LTS **release** cloud image and verify its
   publisher SHA-256.
2. Run `installers/tools/Build-GideonGuacdApplianceCandidate.ps1`. The script
   converts QCOW2 to a dynamic VHDX and records the resolved converter image,
   tool output, source hash, and candidate hash.
3. Optionally run `installers/tools/Test-GideonGuacdApplianceWithQemu.ps1` on a
   Docker-capable host. It boots a disposable overlay with OVMF/UEFI and QEMU
   TCG, then verifies cloud-init, the pinned offline Docker bootstrap, and
   guacd TCP/4822. Its report is prevalidation evidence only and cannot promote
   the candidate.
4. On a clean Windows Pro/Enterprise/Server host with Hyper-V, run
   `installers/tools/Test-GideonGuacdApplianceOnHyperV.ps1` as Administrator. It
   boots an isolated `GIDEON-GUACD-VALIDATION` Generation 2 VM using the same
   CIDATA and GIDEONDATA mechanism as the production provisioner and leaves the
   validation resources available for inspection.
5. The Hyper-V validation report must prove all of the following: Generation 2 boot,
   successful cloud-init, Docker bootstrap from the offline pinned archive,
   Secure Boot with the Linux template, and a successful TCP connection to
   guacd on port 4822.
6. Promote only that exact hash with
   `installers/tools/Import-ValidatedGuacdAppliance.ps1`. The import tool
   preserves all existing dependency-lock entries.

The checked-in build output is intentionally named
`GIDEON-GUACD-UBUNTU-CANDIDATE.vhdx`. It is not copied to the production filename
until the Hyper-V validation gate passes.

Networking:

Windows physical LAN/VPN
        |
   Windows routing
        |
GIDEON Internal vSwitch / private NAT
        |
Ubuntu micro-VM
        |
Docker `--network host`
        |
guacd :4822

Using host networking *inside the dedicated micro-VM* avoids creating an
additional Docker subnet that could overlap a store/VPN route. Isolation is
provided by the dedicated VM, internal vSwitch, and container hardening.
