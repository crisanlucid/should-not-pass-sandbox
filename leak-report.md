# VM leak report

**36 of 36 tests passed.** No leaks.

Probes run: 36. **Leaks: 0** (0 critical, 0 high). Held: 32. Known and accepted: 4.

Only what the attack suite tried is counted. 0 leaks means none of these probes got through, not that the VM is safe.

## Leaks

- none

## Held (passed: the attack was blocked)

- PASS host port 22
- PASS host port 8443
- PASS host proxy port 3128
- PASS raw tcp to 1.1.1.1:443
- PASS http without proxy
- PASS direct 169.254.169.254:80
- PASS direct 192.168.178.1:80
- PASS router via proxy
- PASS cloud metadata via proxy
- PASS NAT gateway via proxy
- PASS host localhost via proxy
- PASS host-only IP via proxy
- PASS decimal-encoded 127.0.0.1
- PASS hostname -> 127.0.0.1
- PASS redirect to metadata
- PASS short-form 127.1
- PASS 0.0.0.0
- PASS IPv6 loopback [::1]
- PASS IPv4-mapped IPv6 loopback
- PASS userinfo trick @127.0.0.1
- PASS rebind hostname localtest.me
- PASS rebind hostname nip.io
- PASS GCP metadata hostname
- PASS CGNAT 100.64.0.1
- PASS https to host port
- PASS direct IPv6 public tcp
- PASS direct IPv6 loopback ::1:7070
- PASS direct DNS to 1.1.1.1 (exfil channel)
- PASS ping 1.1.1.1 (ICMP tunnel)
- PASS credential files in VM home
- PASS real secrets in environment
- PASS shared folders mounted

## Known and accepted (passed: matches the design)

- PASS docker socket usable (info): open (dev is in the docker group by design: root inside the VM, not on the host)
- PASS exfil to public site (info): reached (open mode allows it; an allow list should make this blocked)
- PASS node fetch uses the proxy (info): reached (open mode; set NODE_USE_ENV_PROXY=1 if blocked)
- PASS git post-checkout hook runs (info): ran (unzipped .git/hooks run on checkout; the network is the containment)
