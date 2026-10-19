# portscan

Fast multi-threaded TCP connect scanner with banner grabbing. Lightweight recon tool for SOC practice and lab exercises.

## Features

- TCP connect scan against a hostname or IP (IPv4 and IPv6)
- Port ranges (`1-1024`), lists (`22,80,443`), or curated `top20` set
- Multi-threaded (default 100 workers) for fast sweeps
- Live progress indicator on scans of 20+ ports
- Ctrl-C prints partial results immediately instead of a traceback
- Banner grabbing on open ports, with HTTP-probe fallback
- Clean terminal table output + JSON export

## Requirements

- Python 3.8+ (stdlib only — no dependencies)

## Usage

```bash
# Scan common ports on a target
python3 portscan.py --target 192.168.1.1

# Custom range, more threads
python3 portscan.py --target 192.168.1.1 --ports 1-1024 --threads 200

# Specific ports, export JSON
python3 portscan.py --target scanme.nmap.org --ports 22,80,443 --json-out result.json
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--target`, `-t` | *(required)* | Target hostname or IP |
| `--ports`, `-p` | `top20` | `1-1024` range, `22,80,443` list, or `top20` preset |
| `--threads` | `100` | Worker threads (1–1000) |
| `--timeout` | `1.0` | TCP connect timeout (seconds) |
| `--banner-timeout` | `2.0` | Banner read timeout (seconds) |
| `--json-out` | — | Write results to JSON file |
| `--quiet`, `-q` | — | Suppress progress lines |

## Example output

```
[*] scanning 127.0.0.1 (127.0.0.1): 2 port(s), 100 threads, timeout 1.0s

[+] 127.0.0.1 — 1 open port(s) in 0.0s

    PORT    STATE   BANNER
    ------------------------------------------------------------
    19999   open    SSH-2.0-TestBanner_1.0

[+] results written to result.json
```

JSON schema:

```json
{
  "target": "127.0.0.1",
  "resolved_ip": "127.0.0.1",
  "scanned_at": "2026-10-12T02:46:28+00:00",
  "ports_scanned": 2,
  "elapsed_seconds": 0.0,
  "open_ports": [
    {"port": 19999, "state": "open", "banner": "SSH-2.0-TestBanner_1.0"}
  ]
}
```

## Notes

- TCP connect scan (no raw sockets) — runs without root.
- IPv4 and IPv6: every resolved address is tried per port. `resolved_ip`
  in JSON lists all resolved addresses (comma-separated) when a hostname
  resolves to more than one.
- Only scan hosts you own or have explicit permission to test (e.g. `scanme.nmap.org`).
- Banner grabbing is best-effort; some services stay silent without a protocol-specific probe.
- Interrupting with Ctrl-C cancels pending probes and prints whatever was found so far (exit code 130).
- `--timeout` and `--banner-timeout` must be positive numbers.

## Tests

```bash
python3 -m unittest discover -s tests
```

26 tests (localhost only, never the internet): port-spec parsing, banner
cleaning/grabbing incl. the HTTP HEAD fallback, open/closed scans over
IPv4 and IPv6, target resolution, JSON output, and CLI exit codes.

## License

MIT — see [LICENSE](LICENSE).
