"""python3 leak_report.py probe-report.json > leak-report.md   (report from a real attack-suite run)
   add --html for a standalone HTML page: python3 leak_report.py probe-report.json --html > leak-report.html"""
import html
import json
import sys
from collections import Counter

args = [a for a in sys.argv[1:] if not a.startswith("--")]
rows = json.load(open(args[0] if args else "probe-report.json"))
leaks = [r for r in rows if not r["pass"] and r["severity"] != "info"]
held = [r for r in rows if r["pass"] and r["severity"] != "info"]
info = [r for r in rows if r["severity"] == "info"]
by = Counter(r["severity"] for r in leaks)

passed = sum(r["pass"] for r in rows)
if "--html" in sys.argv:
    e = html.escape

    def section(title, items, cls):
        li = "".join(f'<li class="{cls}"><b>{"PASS" if r["pass"] else "FAIL"}</b> {e(r["probe"])}'
                     + (f' <small>{e(str(r["got"]))} {e(r["note"])}</small>' if r["severity"] == "info" or not r["pass"] else "")
                     + "</li>" for r in items) or "<li>none</li>"
        return f"<h2>{title} ({len(items)})</h2><ul>{li}</ul>"

    ok = not leaks
    print(f"""<!doctype html><meta charset="utf-8"><title>VM leak report</title>
<style>body{{font:16px/1.5 system-ui;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
.banner{{padding:1rem 1.25rem;border-radius:8px;color:#fff;background:{"#1a7f37" if ok else "#c62828"}}}
.banner b{{font-size:1.4rem}}ul{{list-style:none;padding:0}}li{{padding:.25rem .5rem;border-bottom:1px solid #eee}}
li b{{display:inline-block;width:3.2rem;font-size:.8rem}}.pass b{{color:#1a7f37}}.fail b{{color:#c62828}}.info b{{color:#9a6700}}
small{{color:#666}}</style>
<div class="banner"><b>{passed} of {len(rows)} tests passed. {"No leaks." if ok else f"{len(leaks)} FAILED: the sandbox leaked."}</b><br>
Leaks: {len(leaks)} ({by['critical']} critical, {by['high']} high) &middot; Held: {len(held)} &middot; Known and accepted: {len(info)}</div>
<p>Only what the attack suite tried is counted. 0 leaks means none of these probes got through, not that the VM is safe.</p>
{section("Leaks", leaks, "fail")}{section("Held (the attack was blocked)", held, "pass")}{section("Known and accepted (matches the design)", info, "info")}""")
    sys.exit()
print("# VM leak report\n")
print(f"**{passed} of {len(rows)} tests passed.** " + ("No leaks." if not leaks else f"{len(leaks)} FAILED: the sandbox leaked.") + "\n")
print(f"Probes run: {len(rows)}. **Leaks: {len(leaks)}** ({by['critical']} critical, {by['high']} high). "
      f"Held: {len(held)}. Known and accepted: {len(info)}.\n")
print("Only what the attack suite tried is counted. 0 leaks means none of these probes got through, not that the VM is safe.\n")
print("## Leaks\n")
print(*[f"- **{r['severity']}**: {r['probe']}: expected {r['expect']}, got {r['got']}" for r in leaks] or ["- none"], sep="\n")
print("\n## Held (passed: the attack was blocked)\n")
print(*[f"- PASS {r['probe']}" for r in held] or ["- none"], sep="\n")
print("\n## Known and accepted (passed: matches the design)\n")
print(*[f"- PASS {r['probe']}: {r['got']} {r['note']}" for r in info] or ["- none"], sep="\n")
