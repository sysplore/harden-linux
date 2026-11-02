# Security Audit: harden-linux

Date: 2026-11-02
Scope: the Ansible roles, playbooks, inventory and configuration in this
repository.
Reference: [How To Secure A Linux Server](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server)
and its Ansible companion by moltenbit.
Standards reviewed: NIST SP 800-123, NIST SP 800-53 Rev. 5, NIST SP 800-63B-4,
NIST CSF 2.0, BSI IT-Grundschutz Kompendium 2023 (SYS.1.1, SYS.1.3, DER.1,
OPS.1.1.3/4/5, ORP.4, CON.8), BSI TR-02102-4 2026-01 and TR-02102-2 2026-01.

This is a control mapping and engineering review, not a certification. A host is
only compliant after the controls are applied, evidenced and reviewed in its
own risk context.

## 1. Executive summary

The original repository was a useful Debian-only subset of the reference guide.
It had the right building blocks: SSH hardening, UFW, psad, fail2ban, ClamAV,
rkhunter, auditd, Lynis, unattended-upgrades and msmtp. It was not safe to run
at fleet scale:

- It stored plaintext credentials in a tracked `group_vars/variables.yml`.
- It granted the new user `NOPASSWD: ALL`.
- Its unattended-upgrades origin pattern was Debian-only, so Ubuntu received
  no automatic security updates, and the Debian pattern missed the
  `-security` codename.
- It could leave password login enabled through PAM keyboard-interactive even
  with `PasswordAuthentication no`.
- It appended SSH settings to `sshd_config`, where an earlier
  `/etc/ssh/sshd_config.d/` include (cloud-init, vendor images) can win.
- It depended on `wget` and `ansi2html` without installing them.
- It failed the whole play when mail, Lynis, rkhunter or a download failed.
- It had no per-host credentials, no feature selection, no Ubuntu support and no
  kernel, AIDE, faillock, login.defs, journald or NTP hardening.

This refactor fixes the critical defects, adds the missing baseline controls,
makes Debian and Ubuntu first-class, moves credentials to inventory/vault,
adds feature flags and tags, and makes optional components degrade gracefully.

Semaphore is the execution and credential plane. This repository is the
hardening product. There is no second web app.

## 2. Method

- Read every playbook, role, handler, template and variable file.
- Compared coverage with the reference guide's table of contents.
- Mapped controls to NIST and BSI requirements.
- Cross-checked package names and Debian/Ubuntu defaults.
- Pinned the third-party audit rules to a commit and checksum.
- Ran `ansible-playbook --syntax-check`, `yamllint` and `ansible-lint`.
- Host-level runtime verification is still required on a canary host.

## 3. Findings

Status values: **Fixed** means the code was changed. **Partial** means a control
exists but needs process or host verification. **Gap** means it is not
implemented.

### 3.1 Critical

| ID | Finding | Impact | Status |
|---|---|---|---|
| C-01 | `group_vars/variables.yml` was tracked with `root_pw`, `user_pw` and `mail_pw` | Anyone with repository access gets credentials; git history keeps them | Fixed: file removed, inventory/vault model, `no_log`; rotate any real values |
| C-02 | The hardening user received `NOPASSWD: ALL` | Compromise of that account is unrestricted root; violates least privilege | Fixed: default `sudo_nopasswd: false`, sudoers drop-in validated with `visudo` |
| C-03 | `pam_pwquality` line ended in `gecoschec` | Invalid option can make password changes fail | Fixed: `gecoscheck=1`, line validated by review |
| C-04 | unattended-upgrades origins were Debian-only and used `codename=${distro_codename}` for security | Ubuntu gets no automatic security updates; Debian may not match `bookworm-security` | Fixed: distro-specific origins, `#clear`, `-security`/ESM patterns |
| C-05 | `KbdInteractiveAuthentication` was never disabled | `PasswordAuthentication no` can be bypassed through PAM keyboard-interactive | Fixed: explicit no; `AuthenticationMethods publickey` unless MFA |
| C-06 | SSH hardening was appended to `sshd_config` | A drop-in included at the top (cloud-init) can override it | Fixed: `00-hardening.conf` drop-in, Include at BOF, legacy block removed |
| C-07 | `auditd` downloaded an unpinned rules file and ran `wget`, which was not installed | Play failure or supply-chain risk | Fixed: pinned commit + SHA256, `get_url`, no `wget` dependency |

### 3.2 High

| ID | Finding | Impact | Status |
|---|---|---|---|
| H-01 | `ansi2html` was not installed but Lynis used it | Lynis role fails at the last step | Fixed: `python3-ansi2html` installed |
| H-02 | Audit rules ended with `##-e 2` commented out | Rules stay mutable after compromise | Fixed: `99-zzzz-immutable.rules` with `-e 2` |
| H-03 | `password_hash('sha512')` without a stable salt and no `update_password` policy | Password hash changes every run; repeated password resets | Fixed: `update_password: on_create`, yescrypt where supported |
| H-04 | `/etc/sudoers` was edited with `lineinfile` without `validate` | A syntax error can break sudo | Fixed: `/etc/sudoers.d/` files with `visudo -cf` |
| H-05 | A mail failure aborted the play | No mail server means no hardening | Fixed: mail auto-disabled when `mail_to` is empty; non-fatal test |
| H-06 | No Ubuntu support | The fleet is Debian and Ubuntu | Fixed: distro group vars, Ubuntu universe, ssh.socket, ESM origins |
| H-07 | One shared `user_pw`/`mail_pw` for every host | No per-host credential isolation | Fixed: `host_vars/<host>.yml` + vault + Semaphore credentials |
| H-08 | No feature selection | Users cannot opt out of risky or irrelevant components | Fixed: `harden_features` + tags |
| H-09 | No kernel/network sysctl hardening | Missing ASLR, kptr/dmesg restrictions, anti-spoofing, syncookies | Fixed: `system_hardening` role |
| H-10 | No file-integrity monitoring | BSI SYS.1.1.A27 / NIST SI-7 evidence missing | Fixed: AIDE role |
| H-11 | No account lockout | Online guessing is unbounded | Fixed: faillock + pwquality |
| H-12 | No `login.defs` / umask hardening | Weak password aging and world-readable files | Fixed: `system_hardening` role |
| H-13 | `dpkg` conffile prompts could hang unattended upgrades | Security updates stall | Fixed: `Dpkg::Options --force-confdef --force-confold` |
| H-14 | No `ssh.socket` handling on socket-activated Ubuntu | Port changes do not apply | Fixed: `ssh.socket.d` drop-in and restart |
| H-15 | Missing `RequiredRSASize`, old KEX list, no PQ hybrid | Weaker SSH crypto than BSI TR-02102-4 expects | Fixed: version-aware `RequiredRSASize 3072`, PQ KEX where supported |
| H-16 | Alerts depended on a working SMTP server | Hosts without SMTP got no fail2ban, AIDE, ClamAV, rkhunter or Lynis alerts | Fixed: `notify` role with SMTP, generic webhook, ntfy, Gotify and local-only backends |

### 3.3 Medium

| ID | Finding | Impact | Status |
|---|---|---|---|
| M-01 | Audit log retention/rotation not configured | Logs can fill the disk or disappear | Fixed: `auditd.conf` limits and actions |
| M-02 | No journald persistence or iptables log separation | Reboots lose logs; psad/fail2ban evidence is mixed | Fixed: journald + rsyslog + dedicated iptables log |
| M-03 | No NTP configuration | Audit timestamps and TOTP can drift | Fixed: systemd-timesyncd |
| M-04 | ClamAV scanned `/` excluding only `/sys` | Scans `/proc`/`/dev`, takes hours, high I/O | Fixed: excludes `/proc`, `/sys`, `/dev`, `/run`, ClamAV DB; `nice`/`ionice`; log |
| M-05 | Lynis used an unpinned third-party repository | Supply-chain risk | Fixed: distro package default; vendor repo optional and pinned |
| M-06 | psad auto-ban danger level 3 | False positives can lock out administrators | Fixed: default 5, configurable |
| M-07 | `dpkg-statoverride` used `/bin/su` | Merged-/usr systems may not apply it | Fixed: detect `/usr/bin/su` or `/bin/su` |
| M-08 | No `force_handlers`, no preflight asserts, no serial | A failed run can leave configs unapplied; a fleet run is all-or-nothing | Fixed: `force_handlers`, platform asserts, `harden_serial` |
| M-09 | No config backups | No quick rollback after a bad change | Fixed: `backup: true` where practical |
| M-10 | No validation of sshd/fail2ban before restart | A bad config can lock out access or lose bans | Fixed: `sshd -t`, `fail2ban-client -t` |
| M-11 | No `no_log` on secret-bearing tasks | Secrets can leak into logs | Fixed: `no_log` on user/msmtp |
| M-12 | No mount hardening, module blacklist or `/proc` restriction | Larger kernel/filesystem attack surface | Fixed: optional mount hardening, module blacklist, `proc_hidepid` |
| M-13 | `ClientAliveCountMax 0`, `MaxStartups 2`, `UseDNS yes`, `Protocol 2` | Fragile or obsolete SSH settings | Fixed: 3/10:30:60/no/removed |
| M-14 | No CI/lint or collection manifest | Regressions and onboarding failures | Fixed: `ansible.cfg`, `requirements.yml`, CI, `.ansible-lint`, `.yamllint` |
| M-15 | No Ubuntu Pro/ESM hook | Ubuntu security coverage may be incomplete | Partial: optional `ubuntu_pro_token`; token provisioning is process |

### 3.4 Low

- `root_pw` was unused. Removed.
- `apt-transport-https` and `host` were unnecessary on Debian 12/13. Removed.
- `lynis` report was written to `/tmp` with default permissions. Fixed:
  `/var/log/lynis`, `umask 077`.
- `whois` was missing for fail2ban's `action_mwl`. Fixed: installed when mail is
  enabled; ban-only action when mail is disabled.
- `fail2ban`/`rkhunter`/`lynis` update failures used to abort. Fixed: non-fatal
  with explicit warnings.
- `psad` signature update was not retried. Fixed: retries.

## 4. Parity with How To Secure A Linux Server

| Guide section | Before | After |
|---|---|---|
| SSH keys and `AllowGroups` | Yes | Yes |
| `sshd_config` hardening | Partial; appended config can be overridden | Yes; drop-in + validation |
| Remove short DH moduli | Yes, but non-idempotent | Yes; idempotent |
| 2FA/MFA for SSH | No | Optional `mfa` role |
| Limit sudo | Yes, but `NOPASSWD: ALL` | Yes; password required by default |
| Limit su | Yes | Yes; path detection |
| FireJail | No | Not applicable to servers; out of scope |
| NTP client | No | Yes |
| Securing `/proc` | No | Optional `proc_hidepid` |
| Strong passwords | Buggy | Yes; NIST-aligned |
| Automatic security updates | Buggy | Yes; Debian/Ubuntu origins |
| Entropy pool | No | Not needed on current kernels; out of scope |
| Panic password | No | Not recommended; out of scope |
| UFW | Yes | Yes; improved defaults and comments |
| Docker and UFW | No | Gap; document if Docker is used |
| PSAD | Yes | Yes; safer auto-ban threshold |
| Fail2ban | Yes | Yes; mail-aware action |
| CrowdSec | No | Optional future integration |
| AIDE | No | Yes |
| ClamAV | Yes, heavy scan | Yes; scoped scan and logging |
| rkhunter | Yes | Yes; non-fatal updates |
| chkrootkit | No | Not added |
| logwatch | No | Yes; when mail is enabled |
| `ss` port review | No | Diagnostic only |
| Lynis | Yes, broken | Yes; distro package default |
| OSSEC | No | Out of scope |
| msmtp | Yes | Yes; non-fatal test |
| Separate iptables log | No | Yes |
| Backups before edits | No | Yes; `backup: true` |
| GRUB password / danger zone | No | Gap; document |

## 5. NIST mapping

| NIST control | Requirement | Status | Implementation |
|---|---|---|---|
| SP 800-123 | General server security lifecycle | Partial | Baseline roles; planning/process evidence still needed |
| AC-2 | Account management | Partial | User/group creation; no periodic access review |
| AC-6 | Least privilege | Partial | NOPASSWD off by default; sudo group; su restricted; `NOPASSWD` remains an explicit option |
| AC-7 | Unsuccessful login attempts | Met | faillock + pwquality |
| AC-17 | Remote access | Met | SSH key-only, modern crypto, optional MFA |
| AU-2/3/4/5/6/8/9/12 | Audit events, storage, review | Partial | auditd + journald + rsyslog; no central SIEM or review workflow |
| CM-2/6/7 | Baseline configuration | Partial | Ansible baseline and validation; drift detection is a process gap |
| IA-2/4/5/6/8 | Identification and authentication | Met | Key-only SSH, yescrypt, pwquality, faillock; MFA optional |
| RA-5 | Vulnerability scanning | Partial | Lynis; no CVE scanner or authenticated vulnerability feed |
| SC-7 | Boundary protection | Met | UFW default deny, fail2ban, psad |
| SC-8/12/13/23/28 | Cryptographic protection | Partial | Modern SSH, TLS for msmtp; no FIPS or certificate lifecycle |
| SI-2 | Flaw remediation | Met | Fixed security-only unattended upgrades, reboot window |
| SI-3 | Malicious code protection | Met | ClamAV + rkhunter |
| SI-4 | System monitoring | Partial | psad/fail2ban/journald; no host IDS/SIEM |
| SI-7 | Software/file integrity | Met | AIDE + apt signatures |
| SI-16 | Memory protection | Met | ASLR, kptr/dmesg restrictions, protected links, core dump restrictions |
| SP 800-63B-4 | Password requirements | Met | Min 15, no composition rules, dictionary/user checks, lockout; breach-list check is a residual gap |
| CSF 2.0 | Govern/Identify/Protect/Detect/Respond/Recover | Partial | Protect/Detect strong; Govern/Respond/Recover are process gaps |

## 6. BSI IT-Grundschutz mapping

| BSI requirement | Status | Implementation / gap |
|---|---|---|
| SYS.1.1.A2 Authentisierung | Partial | Key-only SSH, optional MFA; central authentication not implemented |
| SYS.1.1.A5 Schnittstellen | Gap | USB/port disable is hardware/vendor specific |
| SYS.1.1.A6 Nicht benötigte Dienste | Partial | Minimal package set; no explicit service inventory |
| SYS.1.1.A9 Virenschutz | Met | ClamAV |
| SYS.1.1.A10 Protokollierung | Partial | auditd, journald, rsyslog; no central log server |
| SYS.1.1.A11 Sicherheitsrichtlinie | Gap | Process/documentation, not code |
| SYS.1.1.A12 Planung | Gap | Process |
| SYS.1.1.A16 Sichere Grundkonfiguration | Partial | Ansible baseline; no continuous drift enforcement |
| SYS.1.1.A19 Lokaler Paketfilter | Met | UFW default deny |
| SYS.1.1.A21 Betriebsdokumentation | Partial | README/AUDIT; per-host runbooks still needed |
| SYS.1.1.A22 Notfallplanung | Gap | Backup/restore and emergency planning not implemented |
| SYS.1.1.A23 Monitoring | Partial | psad/fail2ban; no central monitoring |
| SYS.1.1.A24 Sicherheitsprüfungen | Partial | Lynis; no authenticated vulnerability scan |
| SYS.1.1.A27 Host-ID/Integrität | Partial | AIDE, psad, fail2ban; no HIDS/EDR |
| SYS.1.1.A33 Wurzelzertifikate | Gap | No certificate inventory management |
| SYS.1.1.A34 Festplattenverschlüsselung | Gap | LUKS not automated |
| SYS.1.1.A36 Secure Boot | Gap | Not automated |
| SYS.1.1.A37 Kapselung | Partial | AppArmor installed; profiles not enforced |
| SYS.1.1.A38 Read-only FS | Gap | Not implemented |
| SYS.1.1.A39 Zentrale Verwaltung | Partial | Semaphore + Ansible |
| SYS.1.3.A2 IDs | Met | Ansible user/group modules |
| SYS.1.3.A3 Wechsellaufwerke | Gap | No automount policy |
| SYS.1.3.A4 ASLR/DEP | Met | sysctl + kernel defaults |
| SYS.1.3.A5 Paketinstallation | Met | apt only; vendor repo pinned |
| SYS.1.3.A6 Benutzer/Gruppen | Met | Drop-ins instead of direct `/etc/sudoers` edits |
| SYS.1.3.A8 SSH | Met | Modern SSH policy |
| SYS.1.3.A10 AppArmor/SELinux | Partial | Installed; profile enforcement is a gap |
| SYS.1.3.A14 Informationsabfluss | Partial | `proc_hidepid` optional |
| SYS.1.3.A16 Zusätzliche Kapselung | Gap | Not implemented |
| SYS.1.3.A17 Gehärteter Kernel | Partial | sysctl hardening; no grsecurity/PaX |
| DER.1 Detektion | Partial | Local logs and IDS; no central detection |
| DER.4 Notfallmanagement | Gap | Process |
| OPS.1.1.3 Patchmanagement | Met | Unattended security updates |
| OPS.1.1.4 Schutz vor Schadprogrammen | Met | ClamAV + rkhunter |
| OPS.1.1.5 Protokollierung | Partial | Local retention; remote logging is a gap |
| ORP.4 Identitäts-/Berechtigungsmanagement | Partial | Least privilege improved; access reviews are process |
| NET.1.1 Netzarchitektur | Partial | Host firewall only; no segmentation |
| CON.8 Softwareentwicklung | Partial | CI/lint/syntax; no molecule integration tests |
| TR-02102-4 (SSH) | Met | Modern KEX/ciphers/MACs, RSA 3072, PQ hybrid where supported |
| TR-02102-2 (TLS) | Partial | msmtp uses system trust; no explicit TLS min/cipher policy |
| TR-02102-1 (Krypto) | Partial | Algorithm choices aligned; no full crypto inventory |

## 7. Compliance scorecard

| Area | Rating | Notes |
|---|---|---|
| Host baseline | Strong | Kernel, mounts, login.defs, umask, modules |
| SSH | Strong | Drop-in, key-only, validation, version-aware crypto |
| Authentication | Strong | pwquality, faillock, yescrypt; MFA optional |
| Patch management | Strong | Security-only unattended upgrades, reboot window |
| Network | Strong host-level | UFW default deny; no network segmentation |
| Audit/logging | Partial | Local retention strong; central logging missing |
| Malware/integrity | Strong | ClamAV, rkhunter, AIDE |
| Detection/response | Partial | psad/fail2ban only; no HIDS/SIEM |
| Recovery | Gap | Backup/restore and DR not in scope |
| Supply chain | Partial | Pinned audit rules, apt signatures, CI; no SBOM |
| Process/documentation | Partial | README/AUDIT; per-host evidence still needed |

## 8. What changed in this refactor

- Debian/Ubuntu group vars and distro-specific update origins.
- Inventory-driven `host_vars` and vault-based secrets; old tracked secrets
  file removed; `no_log` added.
- `harden_features` flags and role tags.
- Bootstrap role with sudoers drop-ins, `visudo` validation, su restriction,
  and `update_password: on_create`.
- SSH drop-in with `sshd -t` validation, socket activation support, modern
  KEX/ciphers/MACs, version-aware RSA/PQ settings, and explicit
  `AuthenticationMethods`.
- Password policy aligned with NIST 800-63B-4; faillock account lockout.
- `system_hardening`, `ntp`, `logging`, `integrity`, `mfa` roles.
- Fixed unattended-upgrades origins, conffile handling and reboot time.
- UFW/fail2ban/psad improvements, including mail-aware actions.
- Pluggable notifications (`smtp`, `webhook`, `ntfy`, `gotify`, `none`) so SMTP
  is no longer a hard dependency; ClamAV, AIDE, rkhunter, Lynis, logwatch,
  fail2ban and reboot-required checks use the notifier.
- Pinned audit rules and immutable audit configuration.
- Non-fatal optional components: mail, Lynis, rkhunter, ClamAV, AIDE.
- CI: yamllint, ansible-lint, syntax checks; collection manifest; ansible.cfg.
- Semaphore integration guide and hardening profiles.

## 9. Residual gaps and roadmap

Priority order:

1. **Central logging**: rsyslog/Vector/Fluent Bit over TLS to a SIEM. BSI
   OPS.1.1.5 and DER.1, NIST AU-6/AU-9.
2. **Host IDS/EDR**: Wazuh/OSSEC/CrowdSec for file integrity, log analysis and
   active response. BSI DER.1, NIST SI-4.
3. **Notification coverage**: psad and unattended-upgrades still use their
   native mail hooks; without SMTP they log locally. The notifier covers
   fail2ban, AIDE, ClamAV, rkhunter, Lynis, logwatch and reboot-required.
4. **Vulnerability management**: authenticated scanning and CVE-to-package
   mapping, not only Lynis.
5. **Backup/restore and DR**: BSI DER.4, NIST CP family. Not implemented.
6. **MFA rollout**: enroll users, remove `nullok`, add FIDO2/WebAuthn.
7. **AppArmor profile enforcement** and a documented profile review.
8. **Disk encryption and Secure Boot** for high-protection hosts.
9. **Docker/UFW interaction** if containers are added; `DOCKER-USER` policy.
10. **Network segmentation**: host firewall is not a substitute for zones.
11. **Integration tests**: molecule or disposable VMs for Debian 12/13 and
    Ubuntu 22.04/24.04/26.04; current CI is lint + syntax only.
12. **Evidence export**: Semaphore task history to SIEM/ticketing; no custom app.
13. **Process controls**: access reviews, change approval, incident response,
    decommissioning, per-host runbooks.

External controls (not implemented by this repository): Wazuh is assumed to
cover central logging/SIEM, host IDS/EDR, file integrity monitoring,
vulnerability detection and security configuration assessment. Backup/DR, disk
encryption, Secure Boot, network segmentation, access reviews and change
approval remain external and need their own evidence.

## 10. Verification commands

```bash
yamllint .
ansible-lint
ansible-playbook --syntax-check -i hosts.yml main-playbook.yml
ansible-playbook --syntax-check -i hosts.yml requirements-playbook.yml

# On a canary host after a run:
sshd -T | grep -E 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|authenticationmethods|requiredrsasize'
ufw status verbose
systemctl is-active auditd fail2ban psad clamav-freshclam systemd-timesyncd
auditctl -s
/usr/local/sbin/harden-notify --test
lynis audit system
aide --check
unattended-upgrade --dry-run
```

## 11. Sources

- [How To Secure A Linux Server](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server)
- [NIST SP 800-123, Guide to General Server Security](https://csrc.nist.gov/pubs/sp/800/123/final)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SP 800-63B-4, Digital Identity Guidelines](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [BSI SYS.1.1 Allgemeiner Server](https://it-grundschutzkompendium.de/sys_it-systeme/sys.1.1_allgemeiner_server)
- [BSI SYS.1.3 Server unter Linux und Unix](https://it-grundschutzkompendium.de/sys_it-systeme/sys.1.3_server_unter_linux_und_unix)
- [BSI TR-02102-4, Use of Secure Shell (SSH), 2026-01](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-4.html)
- [BSI TR-02102-2, Transport Layer Security, 2026-01](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html)
- [Neo23x0 auditd rules](https://github.com/Neo23x0/auditd)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [Semaphore UI](https://semaphoreui.com/)
