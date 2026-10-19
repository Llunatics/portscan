"""Tests for portscan. Network tests bind localhost only — never the internet."""
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import portscan
from portscan import (_clean, grab_banner, main, parse_ports, resolve_target,
                      scan_port, write_json)


def _tcp_server(family=socket.AF_INET, banner=None, http_like=False):
    """Blocking one-shot TCP server on an ephemeral port. Returns port."""
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        try:
            conn, _ = srv.accept()
            conn.settimeout(5)
            try:
                if banner is not None:
                    conn.sendall(banner)
                elif http_like:
                    conn.recv(1024)  # wait for the HEAD probe
                    conn.sendall(b"HTTP/1.0 200 OK\r\nServer: TestSrv\r\n\r\n")
                else:
                    conn.recv(1024)  # silent: client times out reading
            except OSError:
                pass
            finally:
                conn.close()
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


class TestParsePorts(unittest.TestCase):
    def test_single(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_range(self):
        self.assertEqual(parse_ports("1-3"), [1, 2, 3])

    def test_list(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_mixed_dedup_sorted(self):
        self.assertEqual(parse_ports("443, 80-82, 80"), [80, 81, 82, 443])

    def test_aliases(self):
        for a in ("top", "top20", "common", " TOP20 "):
            self.assertEqual(parse_ports(a), sorted(portscan.TOP_PORTS))

    def test_errors(self):
        for bad in ("0", "65536", "0-10", "20-10", "abc", "1-2-3",
                    "", "   ", ",", "80,"):
            if bad in ("80,",):
                self.assertEqual(parse_ports(bad), [80])
                continue
            with self.assertRaises(ValueError, msg=bad):
                parse_ports(bad)


class TestClean(unittest.TestCase):
    def test_first_line_only(self):
        self.assertEqual(_clean(b"SSH-2.0-x\r\nsecond"), "SSH-2.0-x")

    def test_control_chars_stripped(self):
        self.assertEqual(_clean(b"ab\x00\x01cd"), "abcd")

    def test_truncated(self):
        self.assertLessEqual(len(_clean(b"x" * 500)), 120)

    def test_bad_bytes(self):
        self.assertIn("SSH", _clean(b"SSH-\xff\xfe"))


class TestGrabBanner(unittest.TestCase):
    def test_spontaneous_banner(self):
        a, b = socket.socketpair()
        try:
            b.sendall(b"SSH-2.0-OpenSSH\r\n")
            self.assertEqual(grab_banner(a, 22, 2.0), "SSH-2.0-OpenSSH")
        finally:
            a.close()
            b.close()

    def test_http_fallback(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        # Pretend this ephemeral port is HTTP-like for the test.
        portscan.HTTP_LIKE_PORTS.add(port)
        try:
            def serve():
                conn, _ = srv.accept()
                req = conn.recv(1024)
                assert b"HEAD" in req
                conn.sendall(b"HTTP/1.0 200 OK\r\nServer: T\r\n\r\n")
                conn.close()
                srv.close()
            threading.Thread(target=serve, daemon=True).start()
            c = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                banner = grab_banner(c, port, 2.0)
            finally:
                c.close()
            self.assertIn("HTTP/1.0 200 OK", banner)
        finally:
            portscan.HTTP_LIKE_PORTS.discard(port)

    def test_silent_port_empty(self):
        a, b = socket.socketpair()
        try:
            # b never sends: banner read must time out, not hang forever.
            self.assertEqual(grab_banner(a, 22, 0.5), "")
        finally:
            a.close()
            b.close()


class TestScanPort(unittest.TestCase):
    def test_open_port_with_banner(self):
        port = _tcp_server(banner=b"SSH-2.0-Test\r\n")
        addrs = [(socket.AF_INET, "127.0.0.1")]
        hit = scan_port(addrs, port, 2.0, 2.0)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0], port)
        self.assertEqual(hit[1], "SSH-2.0-Test")

    def test_closed_port(self):
        # Find a port that is (almost surely) closed: bind then release.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        addrs = [(socket.AF_INET, "127.0.0.1")]
        self.assertIsNone(scan_port(addrs, port, 1.0, 1.0))

    def test_ipv6(self):
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s6.bind(("::1", 0))
            s6.close()
        except OSError:
            self.skipTest("no IPv6 loopback on this machine")
        port = _tcp_server(family=socket.AF_INET6, banner=b"HELLO6\r\n")
        addrs = [(socket.AF_INET6, "::1")]
        hit = scan_port(addrs, port, 2.0, 2.0)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[1], "HELLO6")

    def test_http_like_banner(self):
        port = _tcp_server(http_like=True)
        portscan.HTTP_LIKE_PORTS.add(port)
        try:
            hit = scan_port([(socket.AF_INET, "127.0.0.1")], port, 2.0, 2.0)
            self.assertIsNotNone(hit)
            self.assertIn("HTTP/1.0 200 OK", hit[1])
        finally:
            portscan.HTTP_LIKE_PORTS.discard(port)


class TestResolve(unittest.TestCase):
    def test_localhost(self):
        addrs = resolve_target("127.0.0.1")
        self.assertIn((socket.AF_INET, "127.0.0.1"), addrs)

    def test_bad_name_exits(self):
        import unittest.mock as mock
        with mock.patch("socket.getaddrinfo",
                        side_effect=socket.gaierror("mocked")):
            with self.assertRaises(SystemExit):
                resolve_target("nama-yang-tidak-ada.invalid")


class TestWriteJson(unittest.TestCase):
    def test_shape(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                write_json(p, "tgt", [(socket.AF_INET, "1.2.3.4")],
                           [80, 443], 1.5, [(80, "b")])
            data = json.load(open(p, encoding="utf-8"))
            self.assertEqual(data["target"], "tgt")
            self.assertEqual(data["resolved_ip"], "1.2.3.4")
            self.assertEqual(data["ports_scanned"], 2)
            self.assertEqual(data["open_ports"],
                             [{"port": 80, "state": "open", "banner": "b"}])


class TestMain(unittest.TestCase):
    def test_scan_localhost(self):
        port = _tcp_server(banner=b"TESTBANNER\r\n")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.json")
            buf = io.StringIO()
            with redirect_stdout(buf):
                main(["--target", "127.0.0.1", "--ports", str(port),
                      "--threads", "4", "--timeout", "2",
                      "--banner-timeout", "2", "--quiet",
                      "--json-out", out])
            data = json.load(open(out, encoding="utf-8"))
            self.assertEqual(len(data["open_ports"]), 1)
            self.assertEqual(data["open_ports"][0]["port"], port)
            self.assertEqual(data["open_ports"][0]["banner"], "TESTBANNER")
        self.assertIn(str(port), buf.getvalue())

    def test_bad_ports_exit(self):
        with self.assertRaises(SystemExit):
            main(["--target", "127.0.0.1", "--ports", "99999", "--quiet"])

    def test_bad_target_exit(self):
        import unittest.mock as mock
        with mock.patch("socket.getaddrinfo",
                        side_effect=socket.gaierror("mocked")):
            with self.assertRaises(SystemExit):
                main(["--target", "nama-tidak-ada.invalid", "--ports", "80",
                      "--quiet"])

    def test_threads_range(self):
        with self.assertRaises(SystemExit):
            main(["--target", "127.0.0.1", "--ports", "80",
                  "--threads", "0", "--quiet"])


if __name__ == "__main__":
    unittest.main()
