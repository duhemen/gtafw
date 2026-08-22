import os
import sys
from PyQt6.QtWidgets import QApplication
from src.gui import GTAFirewallUI

if __name__ == "__main__":
    if os.name == 'nt':
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[SECURITY ERROR] GTAFW wajib dijalankan melalui 'Run as Administrator'!")
            input("\nTekan tombol ENTER untuk keluar lalu klik kanan -> Run as Administrator...")
            sys.exit(1)

    app = QApplication(sys.argv)
    ui = GTAFirewallUI()
    ui.show()
    sys.exit(app.exec())