# sshhole-lab

Authentication bypass in OpenSSH on musl-based systems (Alpine Linux, OpenWrt). Accounts with `*` password hashes accept 257+ character passwords.

## Setup

```bash
pip3 install -r requirements.txt
```

## Run Test Container

```bash
docker run --rm -p 2222:22 ghcr.io/leonjza/sshhole-lab:latest
```

Or build locally:

```bash
docker build -t sshole-test .
docker run --rm -p 2222:22 sshole-test
```

## Test Single Target

```bash
python3 sshhole_tester.py --host <target>
```

## Test Multiple Targets
- newline-separated file containing target hosts
```bash
python3 sshhole_tester.py --targets targets.txt
```

## Reference

https://sshhole.com/
