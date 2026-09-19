"""Agent that authenticates to the harness over mTLS with a SPIFFE client cert.

It holds a workload-bound token AND its client certificate + key. It makes the
authorized call, then tries the same token while forging an X-Client-Spiffe-Id
header (the edge must overwrite it) and while claiming a denied action. Prints
one JSON object of observations.
"""

import http.client
import json
import os
import ssl
import sys

EDGE_HOST = os.environ["EDGE_HOST"]
EDGE_PORT = int(os.environ.get("EDGE_PORT", "8443"))
TOKEN = open(os.environ["AGENT_TOKEN_FILE"]).read().strip()
CERT, KEY, CA = os.environ["AGENT_CERT"], os.environ["AGENT_KEY"], os.environ["CA_CERT"]


def call(body, cert=(CERT, KEY), headers=None):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA)
    ctx.check_hostname = False
    if cert:
        ctx.load_cert_chain(cert[0], cert[1])
    try:
        conn = http.client.HTTPSConnection(EDGE_HOST, EDGE_PORT, context=ctx, timeout=10)
        h = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json", **(headers or {})}
        conn.request("POST", "/v1/actions", json.dumps(body), h)
        r = conn.getresponse()
        return r.status, json.loads(r.read() or b"{}")
    except ssl.SSLError as e:
        return "tls_error", str(e)
    except OSError as e:
        return "conn_error", str(e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    out = {}
    s, b = call({"action": "web.search", "arguments": {"query": "capability security"}})
    out["authorized_call"] = [s, (b.get("execution") or {}).get("status") if isinstance(b, dict) else b]
    s, b = call({"action": "database.write", "arguments": {"table": "users"}})
    out["denied_action"] = [s, b.get("reason_code") if isinstance(b, dict) else b]
    s, b = call({"action": "web.search", "arguments": {"query": "x"}},
                headers={"X-Client-Spiffe-Id": "spiffe://capgate.test/agent/admin",
                         "X-Client-Cert-Thumbprint": "A" * 43})
    out["forged_identity_header"] = [s, (b.get("execution") or {}).get("status") if isinstance(b, dict) else b]
    s, b = call({"action": "web.search", "arguments": {"query": "x"}}, cert=None)
    out["no_client_cert"] = [s, b if isinstance(b, str) else b.get("reason_code")]
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
