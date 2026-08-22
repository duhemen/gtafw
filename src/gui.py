import os
import re
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QListWidget, QMessageBox, QGroupBox, QTextEdit)
from PyQt6.QtCore import pyqtSignal, QObject, Qt, QDateTime

from src.core import GTASniffer
from src.firewall import apply_windows_firewall_block, remove_windows_firewall_block, flush_all_active_rules

class CommSignals(QObject):
    detected_ip_signal = pyqtSignal(str, int)
    blocked_ip_signal = pyqtSignal(str, str)
    log_signal = pyqtSignal(str, str)


class GTAFirewallUI(QWidget):
    def __init__(self):
        super().__init__()
        self.whitelist_ips = set()
        self.blacklist_ips = set()
        self.banned_rids = set()
        
        self.whitelist_file = "whitelist.txt"
        self.blacklist_file = "blacklist.txt"
        self.banned_file = "banned_rid.txt"
        
        self.sniffer = None
        self.signals = CommSignals()
        
        self.signals.detected_ip_signal.connect(self.handle_incoming_active_player)
        self.signals.blocked_ip_signal.connect(self.handle_incoming_blocked_player)
        self.signals.log_signal.connect(self.log_message)
        
        self.init_ui_layout()
        self.load_database_from_file()
        
    def init_ui_layout(self):
        self.setWindowTitle("GTA Online - Firewall & Anti-Cheat System v2.5 (Auto-Detect Powered)")
        self.resize(1050, 620)
        
        main_layout = QVBoxLayout()
        
        # Panel Atas: Kontrol Proteksi
        top_box = QHBoxLayout()
        self.status_label = QLabel("STATUS FIREWALL: PROTECTION DISABLED")
        self.status_label.setStyleSheet("color: #C62828; font-weight: bold; font-size: 14px;")
        
        self.btn_toggle = QPushButton("Aktifkan Proteksi")
        self.btn_toggle.setStyleSheet("font-weight: bold; height: 30px;")
        self.btn_toggle.clicked.connect(self.toggle_protection_state)
        
        self.btn_flush = QPushButton("Reset Semua Aturan Windows")
        self.btn_flush.clicked.connect(self.force_flush_firewall)
        
        top_box.addWidget(self.status_label)
        top_box.addWidget(self.btn_toggle)
        top_box.addWidget(self.btn_flush)
        main_layout.addLayout(top_box)
        
        # Panel Tengah: Monitoring & Log
        middle_group = QGroupBox("Monitoring Aktivitas Sesi (Real-time)")
        middle_layout = QHBoxLayout()
        
        active_box = QVBoxLayout()
        active_box.addWidget(QLabel("Pemain Terhubung di Lobby:"))
        self.list_active = QListWidget()
        active_box.addWidget(self.list_active)
        
        active_actions = QHBoxLayout()
        self.btn_add_white = QPushButton("Pindahkan ke Whitelist")
        self.btn_add_white.clicked.connect(self.move_active_to_whitelist)
        self.btn_add_ban = QPushButton("Ban Permanen RID Player Ini")
        self.btn_add_ban.clicked.connect(self.move_active_to_banned)
        active_actions.addWidget(self.btn_add_white)
        active_actions.addWidget(self.btn_add_ban)
        active_box.addLayout(active_actions)
        
        log_box = QVBoxLayout()
        log_box.addWidget(QLabel("Log Aktivitas Anti-Cheat:"))
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setStyleSheet("background-color: #1e1e1e; color: #a9b7c6; font-family: Consolas, Monaco, monospace;")
        log_box.addWidget(self.log_viewer)
        
        middle_layout.addLayout(active_box, stretch=1)
        middle_layout.addLayout(log_box, stretch=1)
        middle_group.setLayout(middle_layout)
        main_layout.addWidget(middle_group)
        
        # Panel Bawah: Manajemen List
        management_layout = QHBoxLayout()
        
        # Group Whitelist
        white_group = QGroupBox("⚪ Whitelist (IP Aman / Teman)")
        white_vbox = QVBoxLayout()
        self.list_whitelist = QListWidget()
        self.btn_remove_white = QPushButton("Hapus dari Whitelist")
        self.btn_remove_white.clicked.connect(self.remove_selected_whitelist)
        white_vbox.addWidget(self.list_whitelist)
        white_vbox.addWidget(self.btn_remove_white)
        white_group.setLayout(white_vbox)
        
        # Group Blacklist
        black_group = QGroupBox("🔴 Blacklist (IP Diblokir Otomatis)")
        black_vbox = QVBoxLayout()
        self.list_blacklist = QListWidget()
        self.list_blacklist.setStyleSheet("color: #E65100;")
        self.btn_remove_black = QPushButton("Ampuni / Hapus Blacklist")
        self.btn_remove_black.clicked.connect(self.remove_selected_blacklist)
        black_vbox.addWidget(self.list_blacklist)
        black_vbox.addWidget(self.btn_remove_black)
        black_group.setLayout(black_vbox)
        
        # Group Banned List
        banned_group = QGroupBox("⚫ Banned List (Rockstar ID Permanen)")
        banned_vbox = QVBoxLayout()
        self.list_banned = QListWidget()
        self.list_banned.setStyleSheet("color: #C62828; font-weight: bold;")
        self.btn_unbanned = QPushButton("Unban RID (Buka Blokir)")
        self.btn_unbanned.clicked.connect(self.remove_selected_banned)
        banned_vbox.addWidget(self.list_banned)
        banned_vbox.addWidget(self.btn_unbanned)
        banned_group.setLayout(banned_vbox)
        
        management_layout.addWidget(white_group)
        management_layout.addWidget(black_group)
        management_layout.addWidget(banned_group)
        main_layout.addLayout(management_layout)
        
        self.setLayout(main_layout)
        self.log_message("Sistem GTAFW v2.5 siap digunakan. Modus Auto-Detect aktif.", "INFO")

    def load_database_from_file(self):
        if os.path.exists(self.whitelist_file):
            with open(self.whitelist_file, "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        self.whitelist_ips.add(ip)
                        self.list_whitelist.addItem(ip)

        if os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        self.blacklist_ips.add(ip)
                        self.list_blacklist.addItem(f"{ip} -> [Saved Blacklist]")

        if os.path.exists(self.banned_file):
            with open(self.banned_file, "r") as f:
                for line in f:
                    rid = line.strip()
                    if rid:
                        self.banned_rids.add(rid)
                        self.list_banned.addItem(rid)
                        
        self.log_message(f"Database dimuat: {len(self.whitelist_ips)} Whitelist, {len(self.blacklist_ips)} Blacklist, {len(self.banned_rids)} Banned RID.", "INFO")

    def save_database_to_file(self):
        with open(self.whitelist_file, "w") as f:
            for ip in sorted(list(self.whitelist_ips)):
                f.write(f"{ip}\n")
                
        with open(self.blacklist_file, "w") as f:
            for ip in sorted(list(self.blacklist_ips)):
                f.write(f"{ip}\n")

        with open(self.banned_file, "w") as f:
            for rid in sorted(list(self.banned_rids)):
                f.write(f"{rid}\n")

    def log_message(self, message, level="INFO"):
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
        color_map = {"INFO": "#a9b7c6", "SUCCESS": "#388E3C", "WARNING": "#F57C00", "CRITICAL": "#D32F2F"}
        color = color_map.get(level, "#a9b7c6")
        log_html = f'<span style="color: #808080;">[{timestamp}]</span> <span style="color: {color}; font-weight: bold;">[{level}]</span> <span style="color: #ffffff;">{message}</span>'
        self.log_viewer.append(log_html)

    def toggle_protection_state(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            self.sniffer = None
            self.status_label.setText("STATUS FIREWALL: PROTECTION DISABLED")
            self.status_label.setStyleSheet("color: #C62828; font-weight: bold; font-size: 14px;")
            self.btn_toggle.setText("Aktifkan Proteksi")
            self.log_message("Proteksi dinonaktifkan oleh pengguna.", "WARNING")
        else:
            self.sniffer = GTASniffer(self.signals, self.whitelist_ips, self.blacklist_ips, self.banned_rids)
            self.sniffer.start()
            self.status_label.setText("STATUS FIREWALL: ACTIVE (PROTECTING LOBBY)")
            self.status_label.setStyleSheet("color: #2E7D32; font-weight: bold; font-size: 14px;")
            self.btn_toggle.setText("Matikan Proteksi")

    def parse_display_text(self, text: str):
        ip = text.split()[0].strip()
        rid = "UNKNOWN_RID"
        fp = "UNKNOWN_FP"
        
        rid_match = re.search(r"\[RID:\s*([^\]]+)\]", text)
        if rid_match:
            rid = rid_match.group(1).strip()
            
        fp_match = re.search(r"\[FP:\s*([^\]]+)\]", text)
        if fp_match:
            fp = fp_match.group(1).strip()
            
        return ip, rid, fp

    def handle_incoming_active_player(self, raw_display_info, size):
        ip, rid, fp = self.parse_display_text(raw_display_info)
        
        found_row = -1
        for row in range(self.list_active.count()):
            item_text = self.list_active.item(row).text()
            if item_text.startswith(ip + " "):
                found_row = row
                break
                
        if found_row >= 0:
            current_text = self.list_active.item(found_row).text()
            if "UNKNOWN_RID" in current_text and rid != "UNKNOWN_RID":
                self.list_active.item(found_row).setText(raw_display_info)
                self.log_message(f"Update RID pemain {ip}: -> {rid}", "INFO")
        else:
            self.list_active.addItem(raw_display_info)
            self.log_message(f"Koneksi lobi masuk: {raw_display_info} ({size}B)", "INFO")

    def handle_incoming_blocked_player(self, log_text, reason):
        black_entry = f"{log_text} -> {reason}"
        self.list_blacklist.addItem(black_entry)
        
        ip, rid, fp = self.parse_display_text(log_text)
        self.blacklist_ips.add(ip)
        
        if rid != "UNKNOWN_RID" and rid not in self.banned_rids:
            self.banned_rids.add(rid)
            self.list_banned.addItem(rid)
                
        self.log_message(f"🚨 AUTO-BLOCK & BAN: {log_text} | Alasan: {reason}", "CRITICAL")
        self.save_database_to_file()

    def move_active_to_whitelist(self):
        current_item = self.list_active.currentItem()
        if current_item:
            raw_text = current_item.text()
            ip, rid, fp = self.parse_display_text(raw_text)
            
            if ip not in self.whitelist_ips:
                self.whitelist_ips.add(ip)
                self.list_whitelist.addItem(ip)
                self.log_message(f"IP {ip} dimasukkan ke Whitelist.", "SUCCESS")
                
                if ip in self.blacklist_ips:
                    self.blacklist_ips.remove(ip)
                    remove_windows_firewall_block(ip)
                if self.sniffer:
                    self.sniffer.active_blocked_ips.discard(ip)
                
                for row in range(self.list_blacklist.count()):
                    item = self.list_blacklist.item(row)
                    if item and ip in item.text():
                        self.list_blacklist.takeItem(row)
                        break
                        
                self.save_database_to_file()
                QMessageBox.information(self, "Berhasil", f"IP {ip} berhasil dipindahkan ke Whitelist.")

    def move_active_to_banned(self):
        current_item = self.list_active.currentItem()
        if current_item:
            raw_text = current_item.text()
            ip, rid, fp = self.parse_display_text(raw_text)
                
            if rid != "UNKNOWN_RID" and rid not in self.banned_rids:
                self.banned_rids.add(rid)
                self.list_banned.addItem(rid)
                self.blacklist_ips.add(ip)
                apply_windows_firewall_block(ip)
                
                if self.sniffer:
                    self.sniffer.active_blocked_ips.add(ip)
                    
                self.log_message(f"Akun RID {rid} (IP: {ip}) di-ban permanen.", "CRITICAL")
                self.save_database_to_file()
                QMessageBox.warning(self, "Banned", f"Rockstar ID {rid} berhasil di-ban permanen.")
            else:
                QMessageBox.critical(self, "Gagal", "RID pemain belum terdeteksi oleh sniffer.")

    def remove_selected_whitelist(self):
        current_row = self.list_whitelist.currentRow()
        if current_row >= 0:
            item = self.list_whitelist.takeItem(current_row)
            ip = item.text()
            if ip in self.whitelist_ips:
                self.whitelist_ips.remove(ip)
            self.log_message(f"IP {ip} dihapus dari Whitelist.", "INFO")
            self.save_database_to_file()
            del item

    def remove_selected_blacklist(self):
        current_row = self.list_blacklist.currentRow()
        if current_row >= 0:
            item = self.list_blacklist.takeItem(current_row)
            raw_text = item.text()
            ip, rid, fp = self.parse_display_text(raw_text)
            
            if ip in self.blacklist_ips:
                self.blacklist_ips.remove(ip)
                
            remove_windows_firewall_block(ip)
            if self.sniffer:
                self.sniffer.active_blocked_ips.discard(ip)
                
            self.log_message(f"Blokir dibatalkan untuk IP: {ip}", "WARNING")
            self.save_database_to_file()
            del item
            QMessageBox.information(self, "Update", f"Koneksi IP {ip} telah dipulihkan.")

    def remove_selected_banned(self):
        current_row = self.list_banned.currentRow()
        if current_row >= 0:
            item = self.list_banned.takeItem(current_row)
            rid = item.text()
            if rid in self.banned_rids:
                self.banned_rids.remove(rid)
            self.log_message(f"Akun Rockstar ID {rid} berhasil di-unban.", "SUCCESS")
            self.save_database_to_file()
            del item
            QMessageBox.information(self, "Unban", f"Rockstar ID {rid} telah dihapus dari Banned List.")

    def force_flush_firewall(self):
        active_ips = self.sniffer.active_blocked_ips if self.sniffer else self.blacklist_ips
        flush_all_active_rules(active_ips)
        if self.sniffer:
            self.sniffer.active_blocked_ips.clear()
        self.blacklist_ips.clear()
        self.banned_rids.clear()
        self.list_blacklist.clear()
        self.list_banned.clear()
        self.save_database_to_file()
        self.log_message("Pembersihan darurat selesai dilakukan.", "WARNING")
        QMessageBox.information(self, "Reset", "Seluruh aturan Windows Firewall berhasil dibersihkan.")

    def closeEvent(self, event):
        active_ips = set()
        if self.sniffer:
            active_ips = self.sniffer.active_blocked_ips.copy()
            self.sniffer.stop()
        flush_all_active_rules(active_ips)
        event.accept()