"""Process-specific readiness proof when Windows socket ownership is unavailable."""
import hmac
import http.client
import re
import secrets

HOST = "snp.invalid"
PATH = "/.well-known/snp-health/"
TOKEN = re.compile(r"[0-9a-f]{64}\Z")


def proof(key, challenge):
    return hmac.digest(bytes.fromhex(key), challenge.encode("ascii"), "sha256").hex().encode("ascii")


def check(host, port, key):
    """Challenge the actual proxy. Never send the private key or follow redirects."""
    if not isinstance(key, str) or not TOKEN.fullmatch(key):
        return False
    challenge = secrets.token_hex(32)
    connection = http.client.HTTPConnection(host, port, timeout=2)
    try:
        connection.request("GET", f"http://{HOST}{PATH}{challenge}", headers={"Connection": "close"})
        response = connection.getresponse()
        return response.status == 200 and hmac.compare_digest(response.read(65), proof(key, challenge))
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()
