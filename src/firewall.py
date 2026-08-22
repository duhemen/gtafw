import subprocess

def apply_windows_firewall_block(ip_address: str) -> bool:
    """Menambahkan aturan Windows Firewall untuk memblokir IP masuk dan keluar."""
    rule_name = f"GTAFW_Block_{ip_address}"
    
    # Hapus aturan lama jika ada untuk mencegah duplikasi nama aturan
    remove_windows_firewall_block(ip_address)
    
    cmd_in = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block",
        f"remoteip={ip_address}", "enable=yes"
    ]
    cmd_out = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=out", "action=block",
        f"remoteip={ip_address}", "enable=yes"
    ]
    try:
        subprocess.run(cmd_in, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(cmd_out, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def remove_windows_firewall_block(ip_address: str) -> None:
    """Mencabut aturan pemblokiran IP tertentu secara bersih dari Windows Firewall."""
    rule_name = f"GTAFW_Block_{ip_address}"
    cmd_delete = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}"
    ]
    try:
        subprocess.run(cmd_delete, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def flush_all_active_rules(active_blocked_ips: set | list) -> None:
    """Membersihkan seluruh aturan buatan GTAFW dari Windows Firewall."""
    print("[FIREWALL] Memulai pembersihan aturan jaringan aktif...")
    for ip in list(active_blocked_ips):
        remove_windows_firewall_block(ip)