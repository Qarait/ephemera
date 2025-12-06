# Ephemera Recording Support Research

> [!NOTE]
> **Research Only**: This document outlines how Ephemera could support session auditing using native OpenSSH features. No implementation is currently planned.

## 1. Overview

Ephemera aims to provide "Recording Support" without acting as a Man-in-the-Middle (MITM) proxy. Traditional session recording solutions (like Teleport or Bastion hosts) often decrypt traffic, record it, and re-encrypt it. This introduces architectural complexity and a high-value target for attackers (the proxy keys).

Instead, Ephemera can leverage **OpenSSH's built-in audit and logging mechanisms** to capture session activity at the edge (the target host) and securely stream these logs to the Ephemera Remote Audit Black Box.

## 2. OpenSSH Session Recording Features

### A. Audit Subsystem (SFTP Logging)
OpenSSH can log all SFTP file operations (uploads, downloads, deletes) natively.

**Configuration:**
In `/etc/ssh/sshd_config`:
```ssh-config
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO
```

**What it captures:**
- File uploads/downloads
- Directory listings
- File deletions/renames
- Permission changes

### B. ForceCommand Logging (Command Execution)
For interactive shells, `ForceCommand` can be used to wrap the user's session in a logging script.

**Configuration:**
In `/etc/ssh/sshd_config`:
```ssh-config
Match Group ephemera-audit
    ForceCommand /usr/local/bin/ephemera_log_wrapper.sh
```

**Wrapper Script (`/usr/local/bin/ephemera_log_wrapper.sh`):**
```bash
#!/bin/bash
# Log the original command
logger -p authpriv.info -t ssh-audit "User $USER executed: $SSH_ORIGINAL_COMMAND"

# Execute the command (or shell if none provided)
if [ -z "$SSH_ORIGINAL_COMMAND" ]; then
    exec $SHELL -l
else
    exec $SHELL -c "$SSH_ORIGINAL_COMMAND"
fi
```

**What it captures:**
- The initial command sent via SSH (e.g., `ssh host ls -la`)
- Does **NOT** capture individual keystrokes inside an interactive shell session.

### C. PAM TTY Audit (Keystroke Logging)
To capture everything typed in an interactive session (including inside `vim` or `sudo`), Linux PAM provides `pam_tty_audit`.

**Configuration:**
In `/etc/pam.d/sshd`:
```pam
session required pam_tty_audit.so enable=* log_passwd=0
```

**What it captures:**
- All keystrokes (stdin)
- TTY output (optional, usually too noisy)
- Works even if user runs `sudo` or switches shells.

**Note:** Logs are binary and stored in `/var/log/audit/audit.log`. They need `aureport --tty` to read.
**Requirement:** `pam_tty_audit` depends on the `auditd` service being active. Some minimal distros ship with it disabled.

### D. JSON Structured Audit Logs
Modern OpenSSH (8.2+) supports structured logging to syslog, which is easier for machines to parse.

**Configuration:**
In `/etc/ssh/sshd_config`:
```ssh-config
LogLevel VERBOSE
# Ensure syslog is configured to forward to Ephemera
```

**Ephemera Integration:**
The Ephemera Black Box (syslog receiver) would parse these logs.

**Example Log Field:**
```json
{
  "event": "session_open",
  "user": "loritamus",
  "src_ip": "192.168.1.50",
  "auth_method": "publickey",
  "key_fingerprint": "SHA256:..."
}
```

## 3. Ephemera Integration Requirements

Ephemera does **not** need to modify its binary. It only needs to provide configuration guidance and policy enforcement.

### Required Integration Points:
1.  **Server Setup Script (`server-setup`):**
    *   Update to generate `sshd_config` snippets enabling the features above.
    *   Optionally install the `pam_tty_audit` module if missing.
2.  **Remote Audit Black Box:**
    *   Ensure it accepts and parses `AUTHPRIV` facility logs.
    *   Add a parser for `pam_tty_audit` binary logs (if forwarded) or rely on the host to convert them to text before forwarding.
3.  **Policy Engine:**
    *   Add a `recording_required: true` flag in `policy.yaml`.
    *   If true, the CA issues certificates only to hosts that report (via heartbeat) that auditing is enabled (Future Work).

## 4. Alternatives Comparison

| Feature | Ephemera (Native SSH) | Teleport / Boundary (Proxy) |
| :--- | :--- | :--- |
| **Architecture** | Decentralized (Edge Logging) | Centralized (MITM Proxy) |
| **Encryption** | End-to-End (Client ↔ Host) | Terminated at Proxy |
| **Complexity** | Low (Config only) | High (New infrastructure) |
| **Performance** | Native Speed | Proxy Latency |
| **Keystroke Logs** | via PAM (OS level) | via Proxy (Protocol level) |
| **Bypass Risk** | Root on host can disable logging | Root on host can bypass proxy agent |

## 5. Pros/Cons & Recommendations

### Pros
*   **Zero Latency:** No proxy hop.
*   **Zero Trust:** Ephemera server never sees the session data (decrypted).
*   **Standard Tools:** Uses standard Linux audit subsystems (auditd, syslog).

### Cons
*   **Host Dependency:** If an attacker gets root on the host, they can potentially stop the logging (though they can't erase logs already sent to the remote Black Box).
*   **Log Volume:** TTY audit generates massive logs.

### Recommendations
1.  **Enable Audit Subsystem** for all file transfers (Low noise, high value).
2.  **Use `pam_tty_audit` sparingly**, perhaps only for specific high-risk groups or servers, due to log volume.
3.  **Mandate Remote Syslog:** The security of this model relies entirely on logs being shipped off-box immediately (UDP/TCP) to the immutable Ephemera Black Box.
    *   Example `rsyslog.conf` snippet:
        ```
        *.* @192.168.1.50:514
        ```

## 6. Security Caveats

> [!WARNING]
> **Root Bypass Risk**: Since the logging happens on the target host, a user with `root` access (or `sudo`) could theoretically stop the audit daemon or filter outgoing syslog traffic.
>
> **Mitigation**:
> 1.  **Remote Logging**: Logs must be streamed in real-time. An attacker can stop *future* logs, but cannot delete *past* logs from the Black Box.
> 2.  **Heartbeats**: Ephemera could require hosts to send a signed "audit status" heartbeat. If audit stops, the CA revokes future access.

## 7. Explicit Non-Goals

*   **No MITM**: We will not build a proxy server.
*   **No Replay UI**: We will not build a "movie player" for terminal sessions (unless we parse the text logs later).
*   **No Decryption**: We will never hold the session keys.
