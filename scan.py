"""Static scan of an untrusted project (folder or .zip) BEFORE you run anything. Stdlib only, never executes the target.

  python3 scan.py PATH [--json]     exit 1 if any high finding, else 0

Standalone: works for a human or any agent (read the text, or parse --json). Heuristic: obfuscated code can slip past.
"""
import base64
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "__pycache__"}
MAX_BYTES = 1_000_000  # ponytail: bigger files (bundles, minified) are skipped, lower it or chunk if one hides a payload
AUTORUN_FILES = {".envrc": "direnv runs it when you cd in", "setup.py": "runs on pip install",
                 ".devcontainer/devcontainer.json": "may run commands on container create"}
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepack")
GIT_CONFIG_KEYS = ("hookspath", "fsmonitor", "sshcommand", "smudge", "textconv")
# (severity, message, pattern)
PATTERNS = [(s, m, re.compile(p, re.I)) for s, m, p in (
    ("high", "download piped to shell", r"(curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod)[^\n|]*\|\s*(ba|z|k)?sh\b|\|\s*iex\b|Invoke-Expression"),
    ("high", "dynamic code from a string (new Function)", r"new\s+Function\s*\("),
    ("high", "PowerShell encoded command", r"powershell[^\n]*-e(nc|ncodedcommand)\b"),
    ("medium", "eval of dynamic code", r"\beval\s*\("),
    ("medium", "base64 decode", r"\batob\s*\(|base64\s+(-d|--decode)|from\s*\(\s*[^)]*['\"]base64['\"]|b64decode"),
    ("medium", "spawns processes", r"child_process|\bexecSync\b|\bos\.system\b|subprocess\.(run|Popen|call)"),
    ("medium", "touches credentials or wallets", r"\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|Login Data|wallet\.dat|keychain|\.netrc"),
)]
B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
URL = re.compile(r"https?://([A-Za-z0-9.-]+)", re.I)
KNOWN = ("github.com", "npmjs.org", "npmjs.com", "w3.org", "localhost", "example.com", "pypi.org", "reactjs.org",
         "mozilla.org", "googleapis.com", "gstatic.com", "nodejs.org", "yarnpkg.com", "schema.org", "json-schema.org")


def decoded_urls(text):
    """URLs hidden in base64 strings (the mockData.js trick)."""
    for b in B64.findall(text):
        try:
            s = base64.b64decode(b + "=" * (-len(b) % 4)).decode("ascii")
        except Exception:
            continue
        if URL.search(s):
            yield s


def scan(root):
    root, out, domains = Path(root), [], set()

    def add(sev, path, line, msg):
        f = {"severity": sev, "file": str(path.relative_to(root)), "line": line, "message": msg}
        if f not in out:
            out.append(f)

    def scan_text(path):
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            return
        for sev, msg, rx in PATTERNS:
            for m in rx.finditer(text):
                add(sev, path, text.count("\n", 0, m.start()) + 1, msg)
        for s in decoded_urls(text):
            add("high", path, 0, f"base64 string decodes to a URL: {s[:80]}")
        domains.update(d.lower() for d in URL.findall(text) if not d.lower().endswith(KNOWN))

    hooks = root / ".git" / "hooks"
    for h in hooks.glob("*") if hooks.is_dir() else ():
        if h.is_file() and not h.name.endswith(".sample"):
            add("high", h, 0, "git hook runs on git commands (post-checkout runs on checkout)")
            scan_text(h)
    cfg = root / ".git" / "config"
    for i, l in enumerate(cfg.read_text().splitlines() if cfg.is_file() else (), 1):
        if any(k in l.lower() for k in GIT_CONFIG_KEYS):
            add("high", cfg, i, f"git config runs commands: {l.strip()}")
    for name, why in AUTORUN_FILES.items():
        if (root / name).is_file():
            add("medium", root / name, 0, why)
    tasks = root / ".vscode" / "tasks.json"
    if tasks.is_file() and "folderOpen" in tasks.read_text():
        add("high", tasks, 0, "VS Code task runs when the folder opens")

    for p in root.rglob("*"):
        if p.is_symlink() or not p.is_file() or SKIP_DIRS & set(p.relative_to(root).parts) or p.stat().st_size > MAX_BYTES:
            continue
        if p.name == "package.json":
            try:
                pkg = json.loads(p.read_text())
            except ValueError:
                pkg = {}
            for k in INSTALL_SCRIPTS:
                if k in pkg.get("scripts", {}):
                    add("high", p, 0, f"npm {k} script runs on install: {pkg['scripts'][k][:80]}")
            for dep, v in {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}.items():
                if isinstance(v, str) and re.match(r"(git|https?:|github:)", v):
                    add("medium", p, 0, f"dependency {dep} comes from a URL, not the registry: {v[:60]}")
        scan_text(p)
    return out, sorted(domains)


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1:
        sys.exit(__doc__)
    path = Path(args[0])
    tmp = None
    if path.is_file() and zipfile.is_zipfile(path):
        tmp = tempfile.TemporaryDirectory()
        zipfile.ZipFile(path).extractall(tmp.name)  # extracting runs nothing; zipfile strips path traversal
        path = Path(tmp.name)
    if not path.is_dir():
        sys.exit(f"not a folder or zip: {path}")
    findings, domains = scan(path)
    rank = {"high": 0, "medium": 1}
    findings.sort(key=lambda f: (rank[f["severity"]], f["file"], f["line"]))
    if "--json" in argv:
        print(json.dumps({"findings": findings, "domains": domains}, indent=2))
    else:
        for f in findings:
            print(f"{f['severity']:<6} {f['file']}:{f['line']}  {f['message']}")
        print(f"\ndomains found in the code: {', '.join(domains) or 'none'}")
        high = sum(f["severity"] == "high" for f in findings)
        print(f"{high} high, {len(findings) - high} medium. {'DO NOT RUN before you read the high ones.' if high else 'No high findings; not proof of safety.'}")
    return int(any(f["severity"] == "high" for f in findings))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
