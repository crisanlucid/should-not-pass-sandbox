# ShouldNotPass attack suite (mock malicious repo)

Looks like a take-home repo; `npm install` runs `probe.py` as a postinstall script, the way a hostile repo would. It only probes and reports. It reads file names, not contents, and sends nothing sensitive.

**Run it only inside the sandbox VM.** It refuses to run without `SNP_VM=1`, so an accidental run on the host does nothing.

```
# on the host, with the VM running: copies the files in and runs them there
python3 snp.py probe --gateway 192.168.1.1    # your router IP, see README
```

The report stays in the VM: `~/probe/probe-report.json`. To read it, `ssh` into the VM and run `cat ~/probe/probe-report.json`, or copy it out with `scp`.

Every probe has an expected result; `FAIL` means the sandbox leaked. Covers: host ports on the host-only address, raw TCP and no-proxy access, router / NAT gateway / metadata / localhost through the proxy, encoded IPs (decimal, hex, octal, short form, IPv6, IPv4-mapped, userinfo trick), hostnames that resolve to 127.0.0.1 (localtest.me, nip.io), other cloud metadata endpoints (GCP, ECS, Alibaba), private and CGNAT ranges, direct IPv6, raw DNS and ICMP as exfil channels, a redirect to metadata, credential files and secrets in the VM, Docker socket, shared folders, and exfiltration to a public site.

Real case modelled: a fake-recruiter take-home zip with a `.git/hooks/post-checkout` that runs `curl|bash` / `wget|bash` on checkout, plus a backend that does `fetch(atob(...))` then `new Function(...)` on startup. The suite confirms the hook runs (it will; hooks are not blocked) and that a direct stage-2 download with `curl`/`wget` fails. A stage-2 fetch through the proxy works in open mode (see the exfil probe); only an allow list stops that.

Not automated (check by hand): clipboard in both directions, drag and drop, USB, host filesystem visibility.

Expected today: the host-port probes FAIL until the nft rule on `vboxnet0` is loaded.
