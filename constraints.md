# Constraints: ShouldNotPass sandbox VM

## Must have
1. The VM can reach the internet.
2. The VM cannot reach the host (localhost, host services, host files), the LAN, the router, or any other private network.
3. Works on Linux, macOS and Windows.
4. Open-source tools only (this rules out Vagrant, which is under the BSL).
5. Hypervisor is VirtualBox on x86_64, QEMU/HVF on Apple Silicon.
6. Enforcement lives outside the VM. The VM is assumed compromised by the repository it runs.
7. Simple to run: two steps at most.
8. Extra footprint well under 2 GB. No second VM (this rules out OPNsense).
9. The VM stays a full desktop with a browser, for live frontend demos (from `plan.md`).
10. No shared folders, clipboard or USB passthrough. Reset the VM after each repo.
11. Another developer can reproduce the same setup from the same files.
12. Add only what is needed.

## Accepted trade-offs
- Only HTTP and HTTPS (via CONNECT) work. Git over SSH needs a `ProxyCommand`. Databases and raw TCP/UDP do not work.
- Public internet egress stays open to allowed hosts, so data can still leave over HTTPS to an allowed site.
- The host-only address (`192.168.56.1`) is reachable from the VM, so other host services must be checked on each OS.
- The proxy runs on the host and parses traffic from a hostile VM, so it stays small and unprivileged.
- Guest proxy settings are configured once and baked into the `clean` snapshot.

## Open questions
- Which protocols besides HTTP and HTTPS do the take-home repos need?
- Do users have admin rights on the host (needed to create the host-only adapter)?
- Proxy rule mode: open internet with private ranges blocked, or a default-deny allow list?

## Decisions made
- Network: VirtualBox uses a host-only adapter, no NAT, no bridged, no host forwarding. Apple Silicon uses restricted QEMU networking, a loopback SSH forward and a filtering-proxy endpoint.
- Other ARM hosts remain unsupported; Apple Silicon uses an Ubuntu ARM64 image.
- Proxy: mitmproxy with a custom Python addon, TLS passthrough.
- Deny list: static private ranges plus `netinfo.py --deny` (this host's interfaces, subnets and gateway).
- Rejected: unrestricted NAT, OPNsense/pfSense, Vagrant, bubblewrap in the guest, Docker Sandboxes (no desktop, platform and licensing unconfirmed).
