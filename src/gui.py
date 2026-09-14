import os
import time
import re
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QListWidget, QTextEdit, QTabWidget,
                             QListWidgetItem, QGroupBox, QComboBox, QCheckBox)
from PyQt6.QtCore import pyqtSignal, QObject, Qt
from PyQt6.QtGui import QColor
from src.core import GTASniffer
from src.firewall import apply_windows_firewall_block, remove_windows_firewall_block, flush_all_active_rules
from src.malicious_player import MaliciousDetectionDatabase, MaliciousPlayerTracker, MaliciousType


class ExtendedCommSignals(QObject):
    detected_ip_signal = pyqtSignal(str, int, bytes, int, int)   # ← 5 argumen
    blocked_ip_signal = pyqtSignal(str, str)
    log_signal = pyqtSignal(str, str)
    malicious_player_signal = pyqtSignal(str, dict)
    rid_banned_signal = pyqtSignal(str)


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
        self._closing = False
        self.signals = ExtendedCommSignals()

        self.malicious_database = MaliciousDetectionDatabase()
        self.malicious_tracker = MaliciousPlayerTracker(self.signals, self.malicious_database)

        self.signals.detected_ip_signal.connect(self.handle_incoming_active_player)
        self.signals.blocked_ip_signal.connect(self.handle_incoming_blocked_player)
        self.signals.log_signal.connect(self.log_message)
        self.signals.malicious_player_signal.connect(self.handle_malicious_player_detection)
        self.signals.rid_banned_signal.connect(self.persist_banned_rids)

        self.init_ui_layout()
        self.load_database_from_file()

    # =========================================================
    # PERSISTENCE
    # =========================================================
    def load_database_from_file(self):
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and ip not in self.whitelist_ips:
                            self.whitelist_ips.add(ip)
                            self.list_whitelist.addItem(ip)

            if os.path.exists(self.blacklist_file):
                with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and ip not in self.blacklist_ips:
                            self.blacklist_ips.add(ip)
                            self.list_blacklist.addItem(f"{ip} -> [Modder]")

            if os.path.exists(self.banned_file):
                with open(self.banned_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        rid = line.strip()
                        if rid:
                            self.banned_rids.add(rid)

            self.log_message(
                f"Database lokal dimuat: {len(self.whitelist_ips)} whitelist, "
                f"{len(self.blacklist_ips)} blacklist, {len(self.banned_rids)} RID banned.",
                "INFO")
        except Exception as e:
            self.log_message(f"Gagal memuat database lokal: {e}", "WARNING")

    @staticmethod
    def _atomic_write(path: str, content: str):
        tmp = path + ".tmp"
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(content)
            os.replace(tmp, path)
        except Exception:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass

    def save_whitelist(self):
        self._atomic_write(self.whitelist_file, "\n".join(sorted(self.whitelist_ips)) + "\n")

    def save_blacklist(self):
        self._atomic_write(self.blacklist_file, "\n".join(sorted(self.blacklist_ips)) + "\n")

    def save_banned_rids(self):
        self._atomic_write(self.banned_file, "\n".join(sorted(self.banned_rids)) + "\n")

    def persist_banned_rids(self, rid: str):
        if self._closing:
            return
        self.banned_rids.add(rid)
        self.save_banned_rids()

    # =========================================================
    # UI LAYOUT
    # =========================================================
    def init_ui_layout(self):
        self.setWindowTitle("GTA Online - Firewall & Anti-Cheat System v2.5.1")
        self.resize(1400, 700)
        main_layout = QVBoxLayout()

        # ── Top bar: status + toggle proteksi + reset + auto-ban ──
        top_box = QHBoxLayout()
        self.status_label = QLabel("STATUS FIREWALL: PROTECTION DISABLED")
        self.status_label.setStyleSheet("color: #C62828; font-weight: bold; font-size: 14px;")

        self.btn_toggle = QPushButton("Aktifkan Proteksi")
        self.btn_toggle.setStyleSheet("font-weight: bold; height: 30px;")
        self.btn_toggle.clicked.connect(self.toggle_protection_state)

        self.btn_flush = QPushButton("Reset Semua Aturan Windows")
        self.btn_flush.clicked.connect(self.force_flush_firewall)

        # ── Auto-Ban Toggle (default OFF — SAFE MODE) ──
        self.chk_auto_ban = QCheckBox("Auto-Ban (Risiko false positive)")
        self.chk_auto_ban.setChecked(False)
        self.chk_auto_ban.setStyleSheet("color: #C62828; font-weight: bold;")
        self.chk_auto_ban.setToolTip(
            "Jika OFF, sistem hanya melaporkan ancaman. Ban dilakukan manual.\n"
            "Jika ON, sistem akan memblokir IP dengan confidence ≥ 0.85 secara otomatis.\n\n"
            "PERINGATAN: Aktifkan hanya jika Anda yakin dengan akurasi deteksi RID di region Anda."
        )
        self.chk_auto_ban.stateChanged.connect(self.on_auto_ban_toggled)

        top_box.addWidget(self.status_label)
        top_box.addWidget(self.btn_toggle)
        top_box.addWidget(self.btn_flush)
        top_box.addWidget(self.chk_auto_ban)
        main_layout.addLayout(top_box)

        self.tab_widget = QTabWidget()
        self.setup_clean_players_tab()
        self.setup_malicious_players_tab()
        self.setup_malicious_history_tab()

        main_layout.addWidget(self.tab_widget)
        self.setLayout(main_layout)
        self.log_message("Sistem GTAFW v2.5.1 siap digunakan. Modus Game Asli Aktif.", "INFO")
        self.log_message(
            "Mode saat ini: MONITOR ONLY. Auto-Ban OFF — "
            "sistem melaporkan tapi tidak memblokir otomatis.", "INFO")

    def on_auto_ban_toggled(self, state):
        """Handler ketika checkbox Auto-Ban diklik."""
        if self._closing:
            return
        if self.chk_auto_ban.isChecked():
            self.log_message(
                "⚠️ AUTO-BAN AKTIF! IP dengan confidence ≥ 0.85 akan diblokir otomatis.",
                "CRITICAL")
        else:
            self.log_message(
                "Auto-Ban dimatikan. Sistem kembali ke MODE MONITOR (aman).", "WARNING")

    def setup_clean_players_tab(self):
        clean_tab = QWidget()
        layout = QVBoxLayout()

        monitoring_group = QGroupBox("Pemain Terhubung di Lobby:")
        monitoring_layout = QVBoxLayout()
        self.list_active = QListWidget()
        self.list_active.setStyleSheet("color: #2E7D32;")
        monitoring_layout.addWidget(self.list_active)

        actions_layout = QHBoxLayout()
        self.btn_add_white = QPushButton("Pindahkan ke Whitelist")
        self.btn_add_white.clicked.connect(self.move_active_to_whitelist)
        self.btn_add_ban = QPushButton("Ban Permanen RID Player Ini")
        self.btn_add_ban.clicked.connect(self.move_active_to_banned)
        actions_layout.addWidget(self.btn_add_white)
        actions_layout.addWidget(self.btn_add_ban)
        monitoring_layout.addLayout(actions_layout)
        monitoring_group.setLayout(monitoring_layout)
        layout.addWidget(monitoring_group)

        logs_group = QGroupBox("Log Aktivitas Anti-Cheat:")
        logs_layout = QVBoxLayout()
        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setStyleSheet(
            "background-color: #1e1e1e; color: #a9b7c6; font-family: Consolas;")
        logs_layout.addWidget(self.log_viewer)
        logs_group.setLayout(logs_layout)
        layout.addWidget(logs_group)

        management_group = QGroupBox("Manajemen Jaringan:")
        management_layout = QHBoxLayout()

        white_group = QGroupBox("Whitelist (Teman Aman)")
        white_vbox = QVBoxLayout()
        self.list_whitelist = QListWidget()
        self.btn_remove_white = QPushButton("Hapus dari Whitelist")
        self.btn_remove_white.clicked.connect(self.remove_selected_whitelist)
        white_vbox.addWidget(self.list_whitelist)
        white_vbox.addWidget(self.btn_remove_white)
        white_group.setLayout(white_vbox)

        black_group = QGroupBox("Blacklist (IP Terblokir)")
        black_vbox = QVBoxLayout()
        self.list_blacklist = QListWidget()
        self.list_blacklist.setStyleSheet("color: #E65100;")
        self.btn_remove_black = QPushButton("Ampuni / Hapus Blacklist")
        self.btn_remove_black.clicked.connect(self.remove_selected_blacklist)
        black_vbox.addWidget(self.list_blacklist)
        black_vbox.addWidget(self.btn_remove_black)
        black_group.setLayout(black_vbox)

        management_layout.addWidget(white_group)
        management_layout.addWidget(black_group)
        management_group.setLayout(management_layout)
        layout.addWidget(management_group)

        clean_tab.setLayout(layout)
        self.tab_widget.addTab(clean_tab, "Clean Players")

    def setup_malicious_players_tab(self):
        malicious_tab = QWidget()
        layout = QVBoxLayout()

        stats_layout = QHBoxLayout()
        self.malicious_stats_label = QLabel("Malicious Players: 0 | Hacker: 0 | Cheater: 0 | Moderator: 0")
        self.malicious_stats_label.setStyleSheet("color: #D32F2F; font-weight: bold;")
        stats_layout.addWidget(self.malicious_stats_label)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by Type:"))
        self.malicious_type_filter = QComboBox()
        self.malicious_type_filter.addItems(
            ["All", "Hacker", "Cheater", "Moderator", "Exploiter", "MultiAuth", "Bot", "Script Kiddie"])
        self.malicious_type_filter.currentIndexChanged.connect(self.filter_malicious_players)
        filter_layout.addWidget(self.malicious_type_filter)
        stats_layout.addLayout(filter_layout)
        layout.addLayout(stats_layout)

        malicious_group = QGroupBox("Malicious Players Detected (🚨):")
        malicious_layout = QVBoxLayout()
        self.list_malicious = QListWidget()
        self.list_malicious.setStyleSheet("color: #D32F2F; font-weight: bold;")
        malicious_layout.addWidget(self.list_malicious)

        actions_layout = QHBoxLayout()
        self.btn_view_malicious_details = QPushButton("View Details")
        self.btn_view_malicious_details.clicked.connect(self.view_malicious_details)
        self.btn_ban_malicious = QPushButton("Apply Ban")
        self.btn_ban_malicious.clicked.connect(self.ban_malicious_player)
        self.btn_whitelist_malicious = QPushButton("Whitelist (False Positive)")
        self.btn_whitelist_malicious.clicked.connect(self.whitelist_malicious_player)
        actions_layout.addWidget(self.btn_view_malicious_details)
        actions_layout.addWidget(self.btn_ban_malicious)
        actions_layout.addWidget(self.btn_whitelist_malicious)
        malicious_layout.addLayout(actions_layout)
        malicious_group.setLayout(malicious_layout)
        layout.addWidget(malicious_group)

        evidence_group = QGroupBox("Detection Evidence:")
        evidence_layout = QVBoxLayout()
        self.malicious_evidence_text = QTextEdit()
        self.malicious_evidence_text.setReadOnly(True)
        self.malicious_evidence_text.setStyleSheet("background-color: #2a0a0a; color: #ff6b6b;")
        evidence_layout.addWidget(self.malicious_evidence_text)
        evidence_group.setLayout(evidence_layout)
        layout.addWidget(evidence_group)

        malicious_tab.setLayout(layout)
        self.tab_widget.addTab(malicious_tab, "Malicious Players")

    def setup_malicious_history_tab(self):
        history_tab = QWidget()
        layout = QVBoxLayout()
        controls_layout = QHBoxLayout()
        self.btn_refresh_history = QPushButton("Refresh History")
        self.btn_refresh_history.clicked.connect(self.load_malicious_history)
        self.btn_cleanup_history = QPushButton("Cleanup Old Entries")
        self.btn_cleanup_history.clicked.connect(self.cleanup_malicious_history)
        controls_layout.addWidget(self.btn_refresh_history)
        controls_layout.addWidget(self.btn_cleanup_history)
        layout.addLayout(controls_layout)

        history_group = QGroupBox("Malicious Player History:")
        history_layout = QVBoxLayout()
        self.list_history = QListWidget()
        self.list_history.setStyleSheet("color: #E65100;")
        history_layout.addWidget(self.list_history)
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)

        history_tab.setLayout(layout)
        self.tab_widget.addTab(history_tab, "History")

    # =========================================================
    # SIGNAL HANDLERS
    # =========================================================
    def handle_incoming_active_player(self, display_info: str, payload_size: int,
                                      raw_payload: bytes = b"",
                                      pps_current: int = 0, ttl: int = 0):
        if self._closing:
            return
        self.malicious_tracker.handle_player_detection(
            display_info, payload_size,
            raw_payload=raw_payload,
            pps_current=pps_current,
            ttl=ttl,
        )
        target_ip = display_info.split()[0]
        new_text = f"{display_info} ({payload_size}B)"
        # FIX: pakai delimiter " [" agar tidak salah match 192.168.1.5 vs 192.168.1.50
        items = self.list_active.findItems(target_ip + " [", Qt.MatchFlag.MatchStartsWith)
        if not items:
            self.list_active.addItem(new_text)
            MAX_ACTIVE_ROWS = 100
            while self.list_active.count() > MAX_ACTIVE_ROWS:
                self.list_active.takeItem(0)
        else:
            items[0].setText(new_text)

    def handle_incoming_blocked_player(self, log_text: str, reason: str):
        if self._closing:
            return
        self.malicious_tracker.handle_player_blocked(log_text, reason)

        # Sinkronisasi widget blacklist (jika belum ditampilkan)
        parts = log_text.split()
        if parts:
            ip = parts[0]
            if ip not in self.blacklist_ips:
                self.blacklist_ips.add(ip)
                self.list_blacklist.addItem(f"{ip} -> [Auto-Ban]")
                self.save_blacklist()   # ← PERSIST ke disk agar tidak hilang saat crash

        self.log_message(f"FIREWALL BLOCK: {log_text} -> Alasan: {reason}", "CRITICAL")
        self.load_malicious_history()

    def log_message(self, message: str, level: str = "INFO"):
        if self._closing:
            return
        timestamp = time.strftime('%H:%M:%S')
        self.log_viewer.append(f"[{timestamp}] [{level}] {message}")

    def handle_malicious_player_detection(self, display_info: str, player_data: dict):
        if self._closing:
            return
        self.log_message(f"MALICIOUS PLAYER DETECTED: {display_info}", "CRITICAL")
        self.update_malicious_stats()
        self.filter_malicious_players()
        self.display_malicious_evidence(player_data)

        # ── Auto-ban HANYA jika user mengaktifkan toggle & confidence tinggi ──
        auto_ban_enabled = self.chk_auto_ban.isChecked()
        confidence = player_data.get('confidence_score', 0)

        if auto_ban_enabled and confidence >= 0.85:
            self.log_message(
                f"AUTO-BANNING HIGH CONFIDENCE PLAYER: {display_info}", "CRITICAL")
            parts = display_info.split()
            if parts:
                self.auto_ban_malicious_player(parts[0])
        elif confidence >= 0.85:
            self.log_message(
                f"[MONITOR MODE] {display_info} terdeteksi ancaman (conf {confidence:.2f}) "
                f"tapi TIDAK di-ban. Aktifkan 'Auto-Ban' untuk memblokir otomatis.",
                "WARNING")

    # =========================================================
    # MALICIOUS UI
    # =========================================================
    def update_malicious_stats(self):
        players = self.malicious_database.get_malicious_players()
        stats = {
            'total': len(players),
            'hacker': sum(1 for p in players if p.malicious_type == MaliciousType.HACKER),
            'cheater': sum(1 for p in players if p.malicious_type == MaliciousType.CHEATER),
            'moderator': sum(1 for p in players if p.malicious_type == MaliciousType.MODERATOR),
            'bot': sum(1 for p in players if p.malicious_type == MaliciousType.BOT),
        }
        self.malicious_stats_label.setText(
            f"Malicious: {stats['total']} | Hacker: {stats['hacker']} | "
            f"Cheater: {stats['cheater']} | Moderator: {stats['moderator']} | Bot: {stats['bot']}")

    def filter_malicious_players(self):
        selected_text = self.malicious_type_filter.currentText()
        mapping = {
            'Hacker': MaliciousType.HACKER,
            'Cheater': MaliciousType.CHEATER,
            'Moderator': MaliciousType.MODERATOR,
            'Exploiter': MaliciousType.EXPLOITER,
            'MultiAuth': MaliciousType.MULTIAUTH,
            'Bot': MaliciousType.BOT,
            'Script Kiddie': MaliciousType.SCRIPT_KIDDY,
        }
        if selected_text == "All":
            players = self.malicious_database.get_malicious_players()
        else:
            players = self.malicious_database.get_malicious_players(mapping.get(selected_text))

        self.list_malicious.clear()
        for p in players:
            item_text = (f"{p.ip} [RID: {p.rid}] [FP: {p.fingerprint}] "
                         f"[{p.malicious_type.value.upper()}] (Conf: {p.confidence_score:.2f})")
            item = QListWidgetItem(item_text)
            item.setForeground(QColor('#D32F2F'))
            self.list_malicious.addItem(item)

    def load_malicious_history(self):
        self.list_history.clear()
        for p in self.malicious_database.get_malicious_players():
            last_seen_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.last_seen))
            status_str = "BANNED" if p.ban_status else "ACTIVE"
            item_text = (f"{p.ip} [RID: {p.rid}] [{p.malicious_type.value.upper()}] "
                         f"Status: {status_str} (Last Seen: {last_seen_str})")
            item = QListWidgetItem(item_text)
            item.setForeground(QColor('#E65100') if p.ban_status else QColor('#2E7D32'))
            self.list_history.addItem(item)

    def cleanup_malicious_history(self):
        self.malicious_database.cleanup_old_entries(days_to_keep=7)
        self.load_malicious_history()
        self.log_message("Database riwayat dibersihkan (Data > 7 hari dihapus).", "INFO")

    def display_malicious_evidence(self, player_data: dict):
        m_type = player_data.get('malicious_type', 'N/A')
        evidence_text = (
            f"IP: {player_data.get('ip', 'N/A')}\n"
            f"RID: {player_data.get('rid', 'N/A')}\n"
            f"Type: {str(m_type).upper()}\n"
            f"Confidence Score: {player_data.get('confidence_score', 0):.2f}\n\n"
            f"Evidence Details:\n"
        )
        for ev in player_data.get('evidence', []):
            t_str = time.strftime('%H:%M:%S', time.localtime(ev.get('timestamp', 0)))
            evidence_text += f"[{t_str}] [{ev.get('severity')}] {ev.get('description')}\n"
        self.malicious_evidence_text.setText(evidence_text)

    def view_malicious_details(self):
        current_item = self.list_malicious.currentItem()
        if not current_item:
            return
        ip = current_item.text().split()[0]
        for player in self.malicious_database.malicious_players.values():
            if player.ip == ip:
                self.display_malicious_evidence(player.to_dict())
                break

    def ban_malicious_player(self):
        current_item = self.list_malicious.currentItem()
        if not current_item:
            return
        ip = current_item.text().split()[0]
        self.auto_ban_malicious_player(ip)

    def auto_ban_malicious_player(self, ip: str):
        target_player = None
        for player in self.malicious_database.malicious_players.values():
            if player.ip == ip:
                target_player = player
                break

        if ip not in self.blacklist_ips:
            self.blacklist_ips.add(ip)
            self.list_blacklist.addItem(f"{ip} -> [Modder]")
            self.save_blacklist()

        if apply_windows_firewall_block(ip):
            if self.sniffer:
                self.sniffer.active_blocked_ips.add(ip)
            self.log_message(f"MALICIOUS PLAYER BANNED VIA FIREWALL: {ip}", "CRITICAL")

        if target_player:
            self.malicious_database.update_ban_status(
                ip, target_player.rid, target_player.fingerprint, True)
            if target_player.rid != "UNKNOWN_RID":
                self.banned_rids.add(target_player.rid)
                self.save_banned_rids()

    def whitelist_malicious_player(self):
        current_item = self.list_malicious.currentItem()
        if not current_item:
            return
        ip = current_item.text().split()[0]

        if ip not in self.whitelist_ips:
            self.whitelist_ips.add(ip)
            self.list_whitelist.addItem(ip)
            self.save_whitelist()

        if ip in self.blacklist_ips:
            self.blacklist_ips.remove(ip)
            self.save_blacklist()

        remove_windows_firewall_block(ip)
        if self.sniffer and ip in self.sniffer.active_blocked_ips:
            self.sniffer.active_blocked_ips.remove(ip)

        fp = "UNKNOWN_FP"
        for p in self.malicious_database.malicious_players.values():
            if p.ip == ip:
                fp = p.fingerprint
                break
        self.malicious_database.update_ban_status(ip, "UNKNOWN_RID", fp, False)
        self.log_message(f"False Positive Cleared: {ip} dipindahkan ke Whitelist.", "SUCCESS")
        self.filter_malicious_players()

    # =========================================================
    # PROTECTION CONTROL
    # =========================================================
    def toggle_protection_state(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            self.sniffer.join(timeout=2)
            self.sniffer = None
            self.status_label.setText("STATUS FIREWALL: PROTECTION DISABLED")
            self.status_label.setStyleSheet("color: #C62828; font-weight: bold; font-size: 14px;")
            self.btn_toggle.setText("Aktifkan Proteksi")
            self.list_active.clear()
            self.log_message("Proteksi dinonaktifkan. Pemantauan jaringan berhenti.", "WARNING")
        else:
            self.sniffer = GTASniffer(
                self.signals, self.whitelist_ips,
                self.blacklist_ips, self.banned_rids)
            self.sniffer.start()
            self.status_label.setText("STATUS FIREWALL: RUNNING (PROTECTED)")
            self.status_label.setStyleSheet("color: #2E7D32; font-weight: bold; font-size: 14px;")
            self.btn_toggle.setText("Matikan Proteksi")
            self.log_message("Proteksi diaktifkan! Menjaga lobi dari serangan modder...", "SUCCESS")

    def force_flush_firewall(self):
        active_rules = set(self.blacklist_ips)
        if self.sniffer:
            active_rules.update(self.sniffer.active_blocked_ips)

        flush_all_active_rules(active_rules)

        self.blacklist_ips.clear()
        if self.sniffer:
            self.sniffer.active_blocked_ips.clear()

        self.list_blacklist.clear()
        self.save_blacklist()
        self.log_message("Seluruh aturan Windows Firewall dibersihkan secara paksa.", "WARNING")

    # =========================================================
    # CLEAN TAB ACTIONS
    # =========================================================
    def move_active_to_whitelist(self):
        curr = self.list_active.currentItem()
        if not curr:
            return
        ip = curr.text().split()[0]
        if ip not in self.whitelist_ips:
            self.whitelist_ips.add(ip)
            self.list_whitelist.addItem(ip)
            self.save_whitelist()
            self.log_message(f"[MANUAL] {ip} berhasil dipindahkan ke Whitelist teman.", "SUCCESS")

            if ip in self.blacklist_ips:
                self.blacklist_ips.remove(ip)
                self.save_blacklist()
                remove_windows_firewall_block(ip)
                if self.sniffer:
                    self.sniffer.active_blocked_ips.discard(ip)

    def move_active_to_banned(self):
        curr = self.list_active.currentItem()
        if not curr:
            return
        ip = curr.text().split()[0]

        rid_match = re.search(r'\[RID:\s*([^\]]+)\]', curr.text())
        rid = rid_match.group(1).strip() if rid_match else "UNKNOWN_RID"

        if rid == "UNKNOWN_RID":
            self.log_message(
                f"Gagal ban manual: Pemain {ip} menyembunyikan RID (Strict Mode Aktif).", "WARNING")
            return

        self.banned_rids.add(rid)
        self.save_banned_rids()
        self.auto_ban_malicious_player(ip)
        self.log_message(f"RID {rid} dari {ip} berhasil diblokir permanen.", "SUCCESS")

    def remove_selected_whitelist(self):
        curr = self.list_whitelist.currentItem()
        if not curr:
            return
        ip = curr.text().strip()
        self.whitelist_ips.discard(ip)
        self.list_whitelist.takeItem(self.list_whitelist.row(curr))
        self.save_whitelist()
        self.log_message(f"Whitelist dihapus: {ip}", "INFO")

    def remove_selected_blacklist(self):
        curr = self.list_blacklist.currentItem()
        if not curr:
            return
        ip = curr.text().split()[0].strip()
        self.blacklist_ips.discard(ip)
        self.list_blacklist.takeItem(self.list_blacklist.row(curr))
        remove_windows_firewall_block(ip)
        if self.sniffer:
            self.sniffer.active_blocked_ips.discard(ip)
        self.save_blacklist()
        self.log_message(f"Blacklist diampuni: {ip}", "INFO")

    # =========================================================
    # CLEANUP — TIDAK LAGI BLOCKING
    # =========================================================
    def closeEvent(self, event):
        """Graceful shutdown: matikan thread dulu, baru simpan, tanpa blocking."""
        self._closing = True

        # 1. Putus sinyal agar sniffer yang masih hidup tidak emit ke widget yang sudah mati
        for sig in (
            self.signals.detected_ip_signal,
            self.signals.blocked_ip_signal,
            self.signals.log_signal,
            self.signals.malicious_player_signal,
            self.signals.rid_banned_signal,
        ):
            try:
                sig.disconnect()
            except (TypeError, RuntimeError):
                pass

        # 2. Stop sniffer — tidak blocking karena socket di-close & timeout 1s
        if self.sniffer:
            try:
                self.sniffer.stop()
                self.sniffer.join(timeout=2)  # aman, thread dijamin selesai ≤1s
            except Exception:
                pass
            self.sniffer = None

        # 3. Persist data terakhir (atomic, cepat karena tidak ada indent)
        try:
            self.malicious_database.flush_if_needed(force=True)
            self.save_whitelist()
            self.save_blacklist()
            self.save_banned_rids()
        except Exception:
            pass

        event.accept()
