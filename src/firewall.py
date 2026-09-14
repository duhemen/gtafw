import hashlib
import socket
import struct
import threading
import time
from collections import defaultdict, deque
from src.firewall import apply_windows_firewall_block


class GTASniffer(threading.Thread):
    def __init__(self, signals_handler, whitelist, blacklist, banned_list, port=6672):
        super().__init__(daemon=True)
        self.port = port
        self.signals = signals_handler
        self.whitelist = whitelist
        self.blacklist = blacklist
        self.banned_list = banned_list
        self.running = False
        self._stop_event = threading.Event()
        self._sniffer_socket = None

        self.packet_timestamps = defaultdict(deque)
        self.pps_violation_count = defaultdict(int)
        self.ip_to_rid_map = {}
        self.banned_fingerprints = set()
        self.active_blocked_ips = set()
        self.host_ip = "127.0.0.1"
        self.max_pps = 500              # ← naik dari 280 → 500 (GTA peak traffic)
        self.crash_size_threshold = 1600  # ← naik dari 1400 → 1600 (GTA P2P max normal)
        self.crash_streak_needed = 3    # ← butuh 3 paket besar berturut-turut
        self._crash_streak = defaultdict(int)

        self._rid_candidate_history = defaultdict(lambda: deque(maxlen=5))
        self._confirmed_rids = {}   # ip → rid yang sudah diverifikasi

    # ---------- Utility ----------
    def get_local_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        except Exception:
            return '127.0.0.1'
        finally:
            s.close()

    def generate_fingerprint(self, ip: str, ttl: int) -> str:
        if not self._validate_ip(ip):
            return "INVALID_IP"
        if not self._validate_ttl(ttl):
            return "INVALID_TTL"
        raw = f"IP:{ip}|TTL:{ttl}|SALT:gtafw_secure_salt_2026"
        return hashlib.sha256(raw.encode()).hexdigest()[:8].upper()

    def _validate_ip(self, ip: str) -> bool:
        try:
            socket.inet_aton(ip)
        except (socket.error, ValueError, OSError):
            return False
        if ip == self.host_ip or ip.startswith(("127.", "192.168.", "10.", "224.", "225.")):
            return False
        if ip == "255.255.255.255":
            return False
        return True

    @staticmethod
    def _validate_ttl(ttl: int) -> bool:
        return 1 <= ttl <= 255

    # ---------- Thread Lifecycle ----------
    def run(self):
        self.running = True
        self.host_ip = self.get_local_ip()

        try:
            self._sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self._sniffer_socket.bind((self.host_ip, 0))
            self._sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            # Timeout agar recvfrom tidak block selamanya → memungkinkan graceful shutdown
            self._sniffer_socket.settimeout(1.0)
            self.signals.log_signal.emit(
                f"Native Raw Socket aktif pada IP {self.host_ip} (Port UDP {self.port}).", "SUCCESS")
        except Exception as e:
            self.signals.log_signal.emit(f"Gagal membuka Raw Socket: {e}", "CRITICAL")
            self.running = False
            return

        while self.running and not self._stop_event.is_set():
            try:
                raw_data, _ = self._sniffer_socket.recvfrom(65535)
                self.process_raw_packet(raw_data)
            except socket.timeout:
                continue  # normal, hanya cek flag stop
            except OSError:
                break
            except Exception as e:
                if self.running:
                    try:
                        self.signals.log_signal.emit(f"Peringatan jaringan: {e}", "WARNING")
                    except RuntimeError:
                        break

        # Cleanup
        try:
            if self._sniffer_socket:
                try:
                    self._sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
                self._sniffer_socket.close()
        except Exception:
            pass
        self._sniffer_socket = None

        try:
            self.signals.log_signal.emit("Thread pemantauan Native Socket dihentikan.", "WARNING")
        except RuntimeError:
            pass

    def stop(self):
        """Interupsi recvfrom yang blocking + sinyal thread untuk berhenti."""
        self.running = False
        self._stop_event.set()
        if self._sniffer_socket:
            try:
                self._sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            try:
                self._sniffer_socket.close()  # ini yang membangunkan recvfrom di Windows
            except Exception:
                pass

    # ---------- Packet Processing ----------
    def process_raw_packet(self, raw_data: bytes):
        if len(raw_data) < 28:
            return

        iph = struct.unpack('!BBHHHBBH4s4s', raw_data[0:20])
        ttl, protocol = iph[5], iph[6]
        src_ip = socket.inet_ntoa(iph[8])

        if not self._validate_ip(src_ip):
            return
        if protocol != 17:  # hanya UDP
            return

        udph = struct.unpack('!HHHH', raw_data[20:28])
        src_port, dst_port = udph[0], udph[1]
        if src_port != self.port and dst_port != self.port:
            return

        raw_payload = raw_data[28:]
        payload_size = len(raw_payload)
        current_time = time.time()

        # ── Update PPS window DULU sebelum emit ──
        dq = self.packet_timestamps[src_ip]
        dq.append(current_time)
        while dq and current_time - dq[0] > 1.0:
            dq.popleft()
        current_pps = len(dq)

        fp_id = self.generate_fingerprint(src_ip, ttl)
        current_rid = self.extract_rockstar_id(src_ip, raw_payload)  # ← tambah src_ip
        if current_rid:
            self.ip_to_rid_map[src_ip] = current_rid

        assigned_rid = self.ip_to_rid_map.get(src_ip, "UNKNOWN_RID")
        display_info = f"{src_ip} [RID: {assigned_rid}] [FP: {fp_id}]"

        # ── Emit ke GUI dengan payload ter-truncate (128 byte cukup untuk entropy) ──
        self.signals.detected_ip_signal.emit(
            display_info,
            payload_size,
            raw_payload[:128],
            current_pps,
            ttl,
        )

        # ── Skip conditions ──
        if src_ip in self.active_blocked_ips or src_ip in self.whitelist:
            return

        if assigned_rid != "UNKNOWN_RID" and assigned_rid in self.banned_list:
            self.execute_block(src_ip, assigned_rid, f"Banned RID Terdeteksi ({assigned_rid})")
            return

        if src_ip in self.blacklist or fp_id in self.banned_fingerprints:
            if assigned_rid != "UNKNOWN_RID":
                self.execute_block(src_ip, assigned_rid, "Session Blacklist Match")
            else:
                self.signals.log_signal.emit(
                    f"Suspicious: IP {src_ip} blacklist sesi, ban ditangguhkan (RID tersembunyi).",
                    "WARNING")
            return

        # ── Crash packet (>1400 bytes) ──
        if payload_size > self.crash_size_threshold:
            self._crash_streak[src_ip] += 1
            if self._crash_streak[src_ip] >= self.crash_streak_needed:
                if assigned_rid != "UNKNOWN_RID":
                    self.banned_fingerprints.add(fp_id)
                    self.trigger_automatic_ban_by_rid(
                        src_ip, assigned_rid,
                        f"Crash Attack Repeated ({payload_size}B x{self._crash_streak[src_ip]})")
                else:
                    self.signals.log_signal.emit(
                        f"Paket besar berulang dari {src_ip} diabaikan (RID anonim).",
                        "WARNING")
                return
            else:
                self.signals.log_signal.emit(
                    f"Paket besar ({payload_size}B) dari {src_ip} — monitoring "
                    f"({self._crash_streak[src_ip]}/{self.crash_streak_needed}).", "INFO")
            return
        else:
            self._crash_streak[src_ip] = 0

        # ── PPS Flooding ──
        if current_pps > self.max_pps:
            self.pps_violation_count[src_ip] += 1
            if self.pps_violation_count[src_ip] >= 3:
                if assigned_rid != "UNKNOWN_RID":
                    self.banned_fingerprints.add(fp_id)
                    self.trigger_automatic_ban_by_rid(
                        src_ip, assigned_rid, f"Modder Flooding ({current_pps} PPS)")
                else:
                    self.signals.log_signal.emit(
                        f"Flooding ({current_pps} PPS) dari {src_ip} diabaikan (RID anonim).", "WARNING")
                return
        else:
            self.pps_violation_count[src_ip] = max(0, self.pps_violation_count[src_ip] - 1)

    def extract_rockstar_id(self, src_ip: str, payload: bytes):
        """Extract RID dengan verifikasi konsistensi 5 paket."""
        if len(payload) < 20:
            return self._confirmed_rids.get(src_ip)
        try:
            candidate, = struct.unpack(">Q", payload[12:20])
            if 1_000_000 < candidate < 9_999_999_999:
                hist = self._rid_candidate_history[src_ip]
                hist.append(candidate)
                # Hanya konfirmasi jika 5 paket terakhir memberi RID SAMA
                if len(hist) >= 5 and len(set(hist)) == 1:
                    self._confirmed_rids[src_ip] = str(candidate)
                    return str(candidate)
        except Exception:
            pass
        return self._confirmed_rids.get(src_ip)

    def execute_block(self, ip: str, rid: str, reason: str):
        if ip in self.active_blocked_ips:
            return
        if apply_windows_firewall_block(ip):
            self.active_blocked_ips.add(ip)
            log_text = f"{ip} [RID: {rid}]" if rid != "UNKNOWN_RID" else ip
            self.signals.blocked_ip_signal.emit(log_text, reason)

    def trigger_automatic_ban_by_rid(self, ip: str, rid: str, reason: str):
        if rid in ("UNKNOWN_RID", "", None):
            return
        self.blacklist.add(ip)
        self.banned_list.add(rid)
        self.execute_block(ip, rid, reason)
        self.signals.rid_banned_signal.emit(rid)
