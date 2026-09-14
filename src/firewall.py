import subprocess
import ipaddress
from typing import Iterable


def _validate_ip(ip_address: str) -> bool:
    """Validasi IP agar tidak menyuntik perintah netsh."""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def apply_windows_firewall_block(ip_address: str) -> bool:
    """Menambahkan aturan Windows Firewall untuk memblokir IP masuk dan keluar."""
    if not _validate_ip(ip_address):
        return False

    rule_name = f"GTAFW_Block_{ip_address}"
    remove_windows_firewall_block(ip_address)

    def _run(direction: str) -> bool:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", f"dir={direction}", "action=block",
            f"remoteip={ip_address}", "enable=yes", "profile=any"
        ]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=8)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False

    return _run("in") and _run("out")


def remove_windows_firewall_block(ip_address: str) -> None:
    """Mencabut aturan pemblokiran IP tertentu secara bersih."""
    if not _validate_ip(ip_address):
        return
    rule_name = f"GTAFW_Block_{ip_address}"
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass


def flush_all_active_rules(active_blocked_ips: Iterable[str]) -> None:
    """Membersihkan seluruh aturan buatan GTAFW dari Windows Firewall."""
    for ip in list(active_blocked_ips):
        remove_windows_firewall_block(ip)
