"""mitmproxy addon: only public destinations, TLS passed through (no CA in the VM).

  mitmdump --listen-host 192.168.56.1 --listen-port 3128 -s proxy_addon.py

Env SANDBOX_MODE=log: allow.txt misses are logged but allowed. Private destinations are always blocked.
Env SANDBOX_OAUTH_TOKEN / SANDBOX_ANTHROPIC_KEY: real credential; requests to api.anthropic.com get it in place of the
VM's placeholder (TLS is decrypted for that host only, everything else stays passthrough).
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from egress_rules import Denied, Rules  # noqa: E402
from mitmproxy import http  # noqa: E402

LOG = Path(__file__).resolve().parent / "proxy.log"
LOG_ONLY = os.environ.get("SANDBOX_MODE") == "log"
# Real credential stays on the host; the VM only holds a placeholder (CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY).
OAUTH = os.environ.get("SANDBOX_OAUTH_TOKEN", "")  # from `claude setup-token`, sent as Authorization: Bearer
APIKEY = os.environ.get("SANDBOX_ANTHROPIC_KEY", "")  # Console key, sent as x-api-key
CRED_HOST = "api.anthropic.com"
_LOG_WARNING_SENT = False


def log(decision, host, why=""):
    global _LOG_WARNING_SENT
    try:
        with LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"t": time.strftime("%FT%T"), "decision": decision, "host": host, "why": why}) + "\n")
    except OSError as e:
        # Disk-full/permission errors must never turn a denied connection into an allowed one.
        if not _LOG_WARNING_SENT:
            _LOG_WARNING_SENT = True
            try:
                print(f"warning: cannot write proxy audit log: {e}", file=sys.stderr)
            except Exception:
                pass  # even a broken/closed stderr must not interrupt a security decision


class Sandbox:
    def __init__(self):
        self.rules = Rules()

    def _allow_list(self, flow):
        host = flow.request.host
        if self.rules.host_allowed(host):
            return
        if LOG_ONLY:
            log("would-deny", host, "not in allow.txt")
            return
        flow.response = http.Response.make(403, b"blocked: not in allow list\n")
        log("deny", host, "not in allow.txt")

    def tls_clienthello(self, data):
        # tunnel HTTPS untouched, except the API host when a credential is set: decrypt it to swap the placeholder
        data.ignore_connection = not ((OAUTH or APIKEY) and data.context.client.sni == CRED_HOST)

    def http_connect(self, flow: http.HTTPFlow):
        self._allow_list(flow)

    def responseheaders(self, flow: http.HTTPFlow):
        # APT pipelines requests that can stall at an upstream keep-alive boundary.
        # Explicitly ending each plain-HTTP exchange lets it reconnect immediately.
        if (flow.request.scheme == "http" and flow.request.http_version.startswith("HTTP/1")
                and flow.request.headers.get("user-agent", "").startswith("Debian APT-HTTP/")):
            flow.response.headers["connection"] = "close"

    def request(self, flow: http.HTTPFlow):  # plain HTTP, and every redirect target is a new request
        self._allow_list(flow)
        if flow.response or flow.request.scheme != "https" or flow.request.pretty_host != CRED_HOST:
            return
        if OAUTH:
            flow.request.headers["authorization"] = f"Bearer {OAUTH}"
            flow.request.headers.pop("x-api-key", None)
        elif APIKEY:
            flow.request.headers["x-api-key"] = APIKEY
            flow.request.headers.pop("authorization", None)
        else:
            return
        log("credential-swap", CRED_HOST)  # never log the credential

    def server_connect(self, data):
        host, port = data.server.address
        try:
            data.server.address = (self.rules.resolve(host, port), port)
            log("allow", host, data.server.address[0])
        except Denied as e:
            data.server.error = f"blocked: {e}"
            log("deny", host, str(e))


addons = [Sandbox()]
