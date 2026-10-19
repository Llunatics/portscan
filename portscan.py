#!/usr/bin/env python3
"""portscan — fast multi-threaded TCP connect scanner with banner grabbing.

Usage:
    python3 portscan.py --target 192.168.1.1 --ports 1-1024
    python3 portscan.py --target scanme.nmap.org --ports 22,80,443 --json-out result.json
"""

import argparse
import concurrent.futures
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

# Curated list of commonly probed ports for quick recon.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080,
]

# Ports where an HTTP probe usually yields a useful banner.
HTTP_LIKE_PORTS = {80, 8000, 8080, 8888, 5000, 3000, 8443}


def parse_ports(spec):
    """Parse a port spec like '1-1024', '22,80,443', 'top20', or '80' into a sorted list."""
    spec = spec.strip().lower()
    if spec in ("top", "top20", "common"):
        return sorted(TOP_PORTS)
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            try:
                start, end = int(start_s), int(end_s)
            except ValueError:
                raise ValueError(f"invalid range: {chunk}")
            if not (0 < start <= 65535 and 0 < end <= 65535 and start <= end):
                raise ValueError(f"invalid range: {chunk}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError:
                raise ValueError(f"invalid port: {chunk}")
            if not (0 < port <= 65535):
                raise ValueError(f"invalid port: {chunk}")
            ports.add(port)
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def grab_banner(sock, port, timeout):
    """Best-effort banner grab. Returns a cleaned string or ''."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(1024)
        if data:
            return _clean(data)
    except (socket.timeout, OSError):
        pass
    # Fallback: poke HTTP-like ports; many services answer a HEAD request.
    if port in HTTP_LIKE_PORTS:
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
            data = sock.recv(1024)
            if data:
                return _clean(data)
        except (socket.timeout, OSError):
            pass
    return ""


def _clean(data):
    text = data.decode("utf-8", errors="replace")
    # Keep only the first line; banners are usually single-line.
    line = text.split("\n", 1)[0]
    return "".join(c for c in line if c.isprintable()).strip()[:120]


def scan_port(addrs, port, timeout, banner_timeout):
    """Return (port, banner) if open on any resolved address, else None.

    addrs: [(family, ip)] from resolve_target — tries every address so
    IPv6 targets work too (an AF_INET socket would just fail on ::1).
    """
    for family, ip in addrs:
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                banner = grab_banner(sock, port, banner_timeout)
                return port, banner
        except OSError:
            pass
        finally:
            sock.close()
    return None


def resolve_target(target):
    """Resolve to a de-duplicated [(family, ip)] list (v4 and v6)."""
    target = target.strip()
    # Accept bracketed IPv6 literals: [::1]
    if len(target) > 2 and target.startswith("[") and target.endswith("]"):
        target = target[1:-1]
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        sys.exit(f"error: cannot resolve target '{target}'")
    addrs = []
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if (family, ip) not in addrs:
            addrs.append((family, ip))
    if not addrs:
        sys.exit(f"error: cannot resolve target '{target}'")
    return addrs


def print_table(results, target, elapsed):
    print(f"\n[+] {target} — {len(results)} open port(s) in {elapsed:.1f}s\n")
    if not results:
        print("    (no open ports found)")
        return
    print(f"    {'PORT':<8}{'STATE':<8}BANNER")
    print("    " + "-" * 60)
    for port, banner in results:
        print(f"    {port:<8}{'open':<8}{banner}")


def show_progress(done, total):
    """Throttled single-line progress bar for long scans."""
    step = max(1, total // 50)
    if done % step == 0 or done == total:
        pct = done * 100 // total
        print(f"\r[*] {done}/{total} ports ({pct}%)", end="", flush=True)


def write_json(path, target, addrs, ports, elapsed, results):
    payload = {
        "target": target,
        "resolved_ip": ", ".join(ip for _, ip in addrs),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "ports_scanned": len(ports),
        "elapsed_seconds": round(elapsed, 2),
        "open_ports": [
            {"port": port, "state": "open", "banner": banner}
            for port, banner in results
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"\n[+] results written to {path}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="portscan — fast multi-threaded TCP connect scanner with banner grabbing."
    )
    ap.add_argument("--target", "-t", required=True, help="target hostname or IP (v4/v6)")
    ap.add_argument(
        "--ports", "-p", default="top20",
        help="ports: range '1-1024', list '22,80,443', or 'top20' (default)",
    )
    ap.add_argument("--threads", type=int, default=100, help="worker threads (default: 100)")
    ap.add_argument("--timeout", type=float, default=1.0, help="connect timeout in seconds (default: 1.0)")
    ap.add_argument(
        "--banner-timeout", type=float, default=2.0,
        help="banner read timeout in seconds (default: 2.0)",
    )
    ap.add_argument("--json-out", metavar="FILE", help="write results as JSON to FILE")
    ap.add_argument("--quiet", "-q", action="store_true", help="only print the table, no progress lines")
    args = ap.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        sys.exit(f"error: {e}")
    if args.threads < 1 or args.threads > 1000:
        sys.exit("error: --threads must be between 1 and 1000")
    if args.timeout <= 0 or args.banner_timeout <= 0:
        sys.exit("error: --timeout and --banner-timeout must be positive")

    addrs = resolve_target(args.target)
    ip = addrs[0][1]
    total = len(ports)
    if not args.quiet:
        print(f"[*] scanning {args.target} ({ip}): {total} port(s), "
              f"{args.threads} threads, timeout {args.timeout}s")

    started = time.monotonic()
    results = []
    interrupted = False
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)
    futures = {
        pool.submit(scan_port, addrs, port, args.timeout, args.banner_timeout): port
        for port in ports
    }
    try:
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if not args.quiet and total >= 20:
                show_progress(done, total)
            hit = fut.result()
            if hit:
                results.append(hit)
    except KeyboardInterrupt:
        interrupted = True
        for fut in futures:
            fut.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        print("\n[!] interrupted — showing partial results", flush=True)
    else:
        pool.shutdown(wait=True)
    elapsed = time.monotonic() - started
    results.sort(key=lambda r: r[0])

    print_table(results, args.target, elapsed)

    if args.json_out:
        try:
            write_json(args.json_out, args.target, addrs, ports, elapsed, results)
        except OSError as e:
            sys.exit(f"error: cannot write {args.json_out}: {e}")

    if interrupted:
        sys.stdout.flush()
        os._exit(130)  # exit fast; worker threads are killed, not joined


if __name__ == "__main__":
    main()
