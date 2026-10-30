# Security policy

ShouldNotPass exists to contain hostile code, so reports of a way out are the most valuable thing you can send.

## What to report
- The VM reaches the host, localhost, the LAN or any private network.
- Code in the VM bypasses the proxy, or makes the proxy connect to a private address (DNS rebinding, redirects, encoded IPs, IPv6).
- Code in the VM obtains the real Claude token or any other host secret.
- A way for the VM to survive `snp.py reset`.
- A bug in `snp.py`, `firewall.py` or the setup scripts that weakens any of the above.

## Known and accepted (not a report)
- In open mode, the VM can send data to any public site.
- `dev` is in the `docker` group and has passwordless sudo: that is root inside the VM, by design.
- macOS has not had a live VM test. Linux and Windows have live validation; the offline CI matrix includes Linux, Windows and macOS. ARM hosts are unsupported.
- A VirtualBox escape is a VirtualBox bug: report it to Oracle. If it works because of how this project configures the VM, report it here too.

## How to report
Use GitHub's private reporting: the repository's **Security** tab, then **Report a vulnerability**. Please do not open a public issue for an escape that still works. Include the steps, the VM name or `setup` options used, and the output of `python3 snp.py status`. Expect a first answer within a week; this is a personal project.

## How to test safely
Test on your own machine. Use throwaway credentials only: never a real token, SSH key or password inside the VM. The attack suite in `attack-suite/` is a harmless starting point.
