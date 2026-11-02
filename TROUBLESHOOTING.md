# Troubleshooting

Problems seen during `setup`, `provision` and `up`, and what to do. Examples use PowerShell on Windows. On Linux and macOS:

- Use `python3` instead of `python`, forward slashes (`.snp/ubuntu-dev/id_ed25519`) and your normal shell. The `bash` and `ssh` snippets work as they are.
- The firewall step asks for your `sudo` password in the terminal instead of showing a UAC prompt, so the UAC and "log looks frozen" notes below apply to Windows only.
- `VBoxManage` is normally already on your PATH.
- The VM-side problems (dpkg, snap, the store) are the same on every host, because the guest is always Ubuntu.

## Timing

A clean `setup` takes about 40 minutes (38 measured on a Windows 11 host): roughly 23 for the unattended Ubuntu install, 3 for the firewall step and VM restart, then 10 for the tools. Retries, a stalled UAC prompt or a repair can add 15 minutes or more.

The log can stay quiet for about 4 minutes right after the Chrome install. That is `snap wait system seed.loaded`: snapd finishes its first-boot setup before the VS Code and Insomnia snaps can install. Nothing is wrong unless it stays quiet for much longer.

## "Windows will ask for Administrator consent" and nothing happens

`setup`, `provision`, `up` and `reset` each run the firewall step, and each one shows a UAC prompt. The prompt often opens minimised: look in the taskbar for a flashing icon, or press `Alt+Tab`, then click **Yes**. Until you do, the command waits and the log stops at that line.

After you approve, the log can still look frozen for one to three minutes. The elevated step writes its output only when it ends.

## Don't touch the VM during `setup`

While `setup` runs, don't click in the VM window, don't run the Ubuntu updater and don't power the VM off. A power-off while the updater is unpacking leaves dpkg half-finished, and the tool install then stops with:

```
Error: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a'
```

Fix it from the host, then run `provision` again:

```powershell
ssh -F none -i .snp\ubuntu-dev\id_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=.snp/ubuntu-dev/known_hosts dev@192.168.56.100 "sudo DEBIAN_FRONTEND=noninteractive dpkg --configure -a"
```

If the updater also left the `firefox` package half-installed (`dpkg -l firefox` shows `iHR`), remove it with `sudo apt remove -y firefox`.

## Snap installs fail (VS Code, Insomnia)

Typical messages:

```
error: too early for operation, device not yet seeded or device model not acknowledged
error: unable to contact snap store
Bad Gateway
```

- `too early for operation`: snapd was still seeding after the first boot. `setup-dev.sh` waits for it with `snap wait system seed.loaded`.
- `unable to contact snap store` or `Bad Gateway`: the proxy could not connect to `api.snapcraft.io`. The proxy log shows `[WinError 121] The semaphore timeout period has expired`. On some networks about half of the store's addresses do not answer, and each connection picks one at random. `setup-dev.sh` retries every snap install 5 times, 10 seconds apart. If all 5 fail, run `provision` again.

To see which store addresses your host can reach:

```powershell
[System.Net.Dns]::GetHostAddresses('api.snapcraft.io')
```

## Re-running only the tool install

`provision` repeats the firewall step (one UAC prompt) and the SSH step. If the firewall is already up and you only want the SSH step, run the guest scripts directly from `.snp\ubuntu-dev` with Git Bash (the VM must be running; the IP is in `snp.py status` or `VBoxManage guestproperty get ubuntu-dev /VirtualBox/GuestInfo/Net/0/V4/IP`):

```bash
ssh -F none -i id_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=known_hosts dev@192.168.56.100 \
  "bash setup-guest-proxy.sh mitmproxy-ca-cert.pem && set -a && . /etc/environment && set +a && bash setup-dev.sh && bash report-installed.sh"
```

This leaves the VM running. `provision` powers it off at the end.

## `VBoxManage` is not recognized

VirtualBox may be installed outside `C:\Program Files`. `snp.py` finds it by itself, but your shell does not. Add its folder to your PATH, or point to it with `SNP_VBOXMANAGE`. A shell opened before the change keeps the old PATH: open a new window, or restart the app that hosts the terminal.

To run it by full path, put `&` in front of the quoted path:

```powershell
& 'F:\ProgramFiles\VBoxManage.exe' list vms
```

## `unsafe VM configuration; refusing to start`

`up` checks the VM before starting it. `NIC 1 must use the host-only adapter at 192.168.56.1` means the VM is still on NAT, which bypasses the proxy. After a complete `setup` this does not happen. If it does, `setup` was interrupted before it switched the network. Check that the disk really contains Ubuntu: a VM that shows `Could not read from the boot medium` was never installed, so remove it and run `setup` again.

```powershell
VBoxManage controlvm ubuntu-dev poweroff
VBoxManage unregistervm ubuntu-dev --delete
python snp.py setup
```

## `Tee-Object` and background runs hide failures

When you pipe `snp.py` through `Tee-Object`, PowerShell reports exit code 0 even if the script failed. Read the last lines of the log for `failed:` before trusting a green result. Don't write two runs to the same log file at once; the second one stops with `The process cannot access the file`.
