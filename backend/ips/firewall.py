"""OS-level native firewall integration (Windows Defender Firewall and Linux iptables)."""

from __future__ import annotations

import logging
import os
import subprocess
from typing import Tuple

LOGGER = logging.getLogger("kuruta.ips.firewall")


class FirewallController:
    """Manages system-level packet drop rules using OS native firewall utilities."""

    def __init__(self) -> None:
        self._is_windows = os.name == "nt"

    def block_ip(self, ip: str) -> Tuple[bool, str]:
        """Apply an OS-level firewall block rule against an IP address."""
        if not ip or ip in {"127.0.0.1", "::1"}:
            return False, "Cannot block loopback or empty address."

        if self._is_windows:
            return self._block_windows(ip)
        return self._block_linux(ip)

    def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """Remove previously added OS-level firewall block rules for an IP."""
        if not ip:
            return False, "Empty address."

        if self._is_windows:
            return self._unblock_windows(ip)
        return self._unblock_linux(ip)

    def _block_windows(self, ip: str) -> Tuple[bool, str]:
        rule_in = f"Kuruta-IPS-In-{ip}"
        rule_out = f"Kuruta-IPS-Out-{ip}"
        cmd_in = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_in}", "dir=in", "action=block", f"remoteip={ip}", "enable=yes"
        ]
        cmd_out = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_out}", "dir=out", "action=block", f"remoteip={ip}", "enable=yes"
        ]
        try:
            res_in = subprocess.run(cmd_in, capture_output=True, text=True, timeout=5)
            res_out = subprocess.run(cmd_out, capture_output=True, text=True, timeout=5)
            if res_in.returncode == 0 and res_out.returncode == 0:
                LOGGER.info("Applied Windows Firewall block for IP %s", ip)
                return True, f"Windows Firewall rules created: {rule_in}, {rule_out}"
            
            # Non-admin or privilege error
            err_msg = (res_in.stderr or res_in.stdout or "").strip()
            LOGGER.warning("Windows Firewall rule failed (elevated privileges may be required): %s", err_msg)
            return False, f"Netsh error (in-memory block active): {err_msg}"
        except Exception as error:
            LOGGER.warning("Windows Firewall execution exception: %s", error)
            return False, f"Subprocess exception: {error}"

    def _unblock_windows(self, ip: str) -> Tuple[bool, str]:
        rule_in = f"Kuruta-IPS-In-{ip}"
        rule_out = f"Kuruta-IPS-Out-{ip}"
        cmd_in = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"]
        cmd_out = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"]
        try:
            subprocess.run(cmd_in, capture_output=True, text=True, timeout=5)
            subprocess.run(cmd_out, capture_output=True, text=True, timeout=5)
            return True, f"Windows Firewall rules deleted for {ip}"
        except Exception as error:
            return False, f"Subprocess exception: {error}"

    def _block_linux(self, ip: str) -> Tuple[bool, str]:
        cmd_in = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        cmd_out = ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"]
        try:
            res_in = subprocess.run(cmd_in, capture_output=True, text=True, timeout=5)
            res_out = subprocess.run(cmd_out, capture_output=True, text=True, timeout=5)
            if res_in.returncode == 0 and res_out.returncode == 0:
                LOGGER.info("Applied iptables DROP for IP %s", ip)
                return True, f"iptables DROP rules created for {ip}"
            err = (res_in.stderr or res_in.stdout or "").strip()
            return False, f"iptables error: {err}"
        except Exception as error:
            return False, f"iptables exception: {error}"

    def _unblock_linux(self, ip: str) -> Tuple[bool, str]:
        cmd_in = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        cmd_out = ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"]
        try:
            subprocess.run(cmd_in, capture_output=True, text=True, timeout=5)
            subprocess.run(cmd_out, capture_output=True, text=True, timeout=5)
            return True, f"iptables DROP rules removed for {ip}"
        except Exception as error:
            return False, f"iptables exception: {error}"
