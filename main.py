bantu emen untuk cek ulang semua kode yang baru saja di revisiimport os
import sys
import socket
from PyQt6.QtWidgets import QApplication
from src.gui import GTAFirewallUI


def _ensure_admin() -> bool:
    """Return True jika proses berjalan dengan hak Administrator di Windows."""
    if os.name != 'nt':
        print("[INFO] Platform non-Windows terdeteksi.")
        print("[INFO] Fitur Raw Socket & Windows Firewall dinonaktifkan.")
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _check_raw_socket_support() -> bool:
    """Cek apakah raw socket diizinkan di sistem ini."""
    if os.name != 'nt':
        return True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.close()
        return True
    except PermissionError:
        print("[ERROR] Raw socket ditolak. Pastikan antivirus/firewall pihak ketiga")
        print("        tidak memblokir raw socket Python.")
        return False
    except Exception as e:
        print(f"[WARN] Cek raw socket gagal: {e}")
        return True


if __name__ == "__main__":
    if not _ensure_admin():
        print("[SECURITY ERROR] GTAFW wajib dijalankan melalui 'Run as Administrator'!")
        input("\nTekan ENTER untuk keluar, lalu klik kanan -> Run as Administrator...")
        sys.exit(1)

    if not _check_raw_socket_support():
        input("\nTekan ENTER untuk keluar...")
        sys.exit(1)

    print("=" * 60)
    print("  GTAFW v2.5.1 — GTA Online Firewall & Anti-Cheat")
    print("  MODE DEFAULT: MONITOR ONLY (tidak ada auto-ban)")
    print("  Untuk mengaktifkan auto-ban: centang 'Auto-Ban' di UI.")
    print("=" * 60)

    app = QApplication(sys.argv)
    ui = GTAFirewallUI()
    ui.show()
    sys.exit(app.exec())
