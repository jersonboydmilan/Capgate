"""Destination hardening: legacy IP spellings, parser differentials, DNS answers, rebinding, redirects."""

import http.server
import threading

import pytest

from harness import ReasonCode
from harness.tools import DestinationRefused, HttpFetchTool
from helpers import make_harness


@pytest.mark.parametrize(
    "url",
    [
        "http://127.1/",
        "http://0x7f.1/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://017700000001/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:a9fe:a9fe]/",          # 169.254.169.254, IPv4-mapped
        "http://[2002:7f00:1::]/",             # 6to4 wrapping 127.0.0.1
        "http://[fe80::1]/",
        "http://user:pass@arxiv.org/",
        "http://arxiv.org\\\\@169.254.169.254/",
        "http://arxiv.org /",
        "http://arxiv.org\t.evil/",
        "http://arxiv.org:99999/",
        "http://ex\u0430mple.com/",             # Cyrillic 'a'
        "http://1.2.3/",
    ],
)
def test_policy_denies_ambiguous_or_private_urls(url):
    result = make_harness().authorize("researcher", "web.fetch", {"url": url})
    assert result.denied, url
    assert result.reason_code is ReasonCode.DOMAIN_NOT_ALLOWED


@pytest.mark.parametrize("url", ["https://arxiv.org/abs/1", "http://93.184.216.34/", "https://sub.example.com:443/x?q=1"])
def test_policy_allows_plain_public_urls(url):
    assert make_harness().authorize("researcher", "web.fetch", {"url": url}).allowed


class _Server:
    def __init__(self):
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer.requests.append((self.path, self.headers.get("Host")))
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                    self.end_headers()
                    return
                body = b"x" * 5000 if self.path == "/big" else b"hello"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = _Server()
    yield s
    s.close()


def resolver(mapping, calls):
    def resolve(host, port):
        calls.append(host)
        return mapping[host]
    return resolve


def test_refuses_hostname_resolving_to_private_address():
    calls = []
    tool = HttpFetchTool(resolver=resolver({"innocent.example.com": ["10.0.0.5"]}, calls))
    with pytest.raises(DestinationRefused, match="non-public"):
        tool({"url": "https://innocent.example.com/"})


def test_refuses_if_any_answer_is_private():
    calls = []
    tool = HttpFetchTool(resolver=resolver({"mixed.example.com": ["93.184.216.34", "127.0.0.1"]}, calls))
    with pytest.raises(DestinationRefused):
        tool({"url": "https://mixed.example.com/"})


def test_connection_is_pinned_to_the_vetted_address(server):
    """One resolution, and the socket goes to that address — a rebinding second answer is never consulted."""
    calls = []
    answers = iter([["127.0.0.1"], ["10.9.9.9"]])  # the second answer would be the rebind
    tool = HttpFetchTool(allow_private=True, allowed_ports=None, resolver=lambda h, p: calls.append(h) or next(answers))
    out = tool({"url": f"http://rebind.example.com:{server.port}/ok"})
    assert out["status"] == 200 and out["body"] == "hello" and out["resolved_ip"] == "127.0.0.1"
    assert calls == ["rebind.example.com"]
    assert server.requests == [("/ok", f"rebind.example.com:{server.port}")]


def test_https_pins_ip_but_verifies_hostname(monkeypatch):
    seen = {}

    def fake_create_connection(address, timeout=None, *a, **k):
        seen["address"] = address
        raise ConnectionRefusedError("stop here")

    monkeypatch.setattr("harness.tools.socket.create_connection", fake_create_connection)
    tool = HttpFetchTool(resolver=lambda h, p: ["93.184.216.34"])
    with pytest.raises(ConnectionRefusedError):
        tool({"url": "https://example.com/"})
    assert seen["address"] == ("93.184.216.34", 443)


def test_redirects_are_returned_not_followed(server):
    tool = HttpFetchTool(allow_private=True, allowed_ports=None, resolver=lambda h, p: ["127.0.0.1"])
    out = tool({"url": f"http://site.example.com:{server.port}/redirect"})
    assert out["followed"] is False and out["redirect_to"].startswith("http://169.254.169.254/")
    assert [path for path, _ in server.requests] == ["/redirect"]


def test_following_a_redirect_is_a_new_proposal_that_policy_denies():
    harness = make_harness()
    assert harness.authorize("researcher", "web.fetch", {"url": "http://169.254.169.254/latest/meta-data/"}).denied


def test_body_is_capped(server):
    tool = HttpFetchTool(allow_private=True, allowed_ports=None, max_bytes=100, resolver=lambda h, p: ["127.0.0.1"])
    out = tool({"url": f"http://big.example.com:{server.port}/big"})
    assert len(out["body"]) == 100 and out["truncated"] is True


@pytest.mark.parametrize("url, message", [
    ("http://example.com:8080/", "port 8080"),
    ("http://u:p@example.com/", "credentials"),
    ("ftp://example.com/", "http"),
    ("http://127.0.0.1/", "non-public"),
])
def test_tool_refuses_without_resolving(url, message):
    calls = []
    tool = HttpFetchTool(resolver=lambda h, p: calls.append(h) or ["93.184.216.34"])
    with pytest.raises(DestinationRefused, match=message):
        tool({"url": url})
    assert calls == []


def test_tool_failure_is_recorded_as_execution_outcome():
    harness = make_harness(tools={"web.fetch": HttpFetchTool(resolver=lambda h, p: ["10.0.0.1"])})
    result = harness.authorize("researcher", "web.fetch", {"url": "https://looks-public.example.com/"})
    assert result.allowed  # policy only sees the name…
    execution = harness.execute(result)
    assert execution.status == "failed" and "DestinationRefused" in execution.error  # …the executor sees the address
