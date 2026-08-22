import hashlib
import socket
import struct
import threading
import time
from collections import defaultdict, deque
from src.firewall import apply_windows_firewall_block

class GTASniffer(threading.Thread):
    def __init__(self, signals_handler, whitelist, blacklist, banned_list, port=6672):
        super().__init__()
        self.port = port
        self.signals = signals_handler
        self.whitelist = whitelist      
        self.blacklist = blacklist      
        self.banned_list = banned_list  
        self.running = False
        self.daemon = True              

        self.packet_timestamps = defaultdict(deque)
        self.pps_violation_count = defaultdict(int)
        self.ip_to_rid_map = {} 
        self.banned_fingerprints = set()
        self.active_blocked_ips = set()
        self.host_ip = "127.0.0.1"
        self.max_pps = 280  # Ditingkatkan agar aman saat proses bergabung ke lobi

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def generate_fingerprint(self, ip: str, ttl: int) -> str:
        """Fingerprint spesifik host (IP + TTL) untuk mencegah false positive masal."""
        raw_signature = f"IP:{ip}|TTL:{ttl}"
        return hashlib.md5(raw_signature.encode()).hexdigest()[:8].upper()

    def run(self):
        self.running = True
        self.host_ip = self.get_local_ip()
        
        try:
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((self.host_ip, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            self.signals.log_signal.emit(f"Native Raw Socket aktif pada IP {self.host_ip} (Port UDP {self.port}).", "SUCCESS")
        except Exception as e:
            self.signals.log_signal.emit(f"Gagal membuka Raw Socket: {e}", "CRITICAL")
            return

        while self.running:
            try:
                raw_data, _ = sniffer.recvfrom(65535)
                self.process_raw_packet(raw_data)
            except Exception as e:
                if self.running:
                    self.signals.log_signal.emit(f"Peringatan jaringan: {e}", "WARNING")
                break

        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sniffer.close()
        except Exception:
            pass
            
        self.signals.log_signal.emit("Thread pemantauan Native Socket dihentikan.", "WARNING")

    def stop(self):
        self.running = False

    def process_raw_packet(self, raw_data):
        if len(raw_data) < 28:
            return

        ip_header = raw_data[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ttl = iph[5]
        protocol = iph[6]

        if protocol == 17:  # UDP
            src_ip = socket.inet_ntoa(iph[8])
            
            # Filter IP Lokal & Broadcast
            if src_ip == self.host_ip or src_ip.startswith("127.") or src_ip.startswith("224.") or src_ip == "255.255.255.255":
                return

            udp_header = raw_data[20:28]
            udph = struct.unpack('!HHHH', udp_header)
            src_port = udph[0]
            dst_port = udph[1]

            if src_port == self.port or dst_port == self.port:
                raw_payload = raw_data[28:]
                payload_size = len(raw_payload)
                current_time = time.time()

                fp_id = self.generate_fingerprint(src_ip, ttl)

                current_rid = self.extract_rockstar_id(raw_payload)
                if current_rid:
                    self.ip_to_rid_map[src_ip] = current_rid

                assigned_rid = self.ip_to_rid_map.get(src_ip, "UNKNOWN_RID")
                
                display_info = f"{src_ip} [RID: {assigned_rid}] [FP: {fp_id}]"
                self.signals.detected_ip_signal.emit(display_info, payload_size)

                if src_ip in self.active_blocked_ips:
                    return

                if src_ip in self.whitelist:
                    return

                if assigned_rid in self.banned_list or src_ip in self.blacklist or fp_id in self.banned_fingerprints:
                    self.execute_block(src_ip, assigned_rid, "Banned RID / Session Blacklist")
                    return

                # Deteksi Crash Packet (>1400 Bytes)
                if payload_size > 1400:
                    self.banned_fingerprints.add(fp_id)
                    self.trigger_automatic_ban_by_rid(src_ip, assigned_rid, f"Crash Attack ({payload_size}B) | FP:{fp_id}")
                    return

                # Deteksi Packet Flooding (PPS)
                dq = self.packet_timestamps[src_ip]
                dq.append(current_time)
                while dq and current_time - dq[0] > 1.0:
                    dq.popleft()

                pps = len(dq)
                if pps > self.max_pps:
                    self.pps_violation_count[src_ip] += 1
                    if self.pps_violation_count[src_ip] >= 3:
                        self.banned_fingerprints.add(fp_id)
                        self.trigger_automatic_ban_by_rid(src_ip, assigned_rid, f"Modder Flooding ({pps} PPS) | FP:{fp_id}")
                        return
                else:
                    self.pps_violation_count[src_ip] = max(0, self.pps_violation_count[src_ip] - 1)

    def extract_rockstar_id(self, payload: bytes) -> str | None:
        if len(payload) < 20:
            return None
        try:
            rid_candidate, = struct.unpack(">Q", payload[12:20])
            if 1000000 < rid_candidate < 9999999999:
                return str(rid_candidate)
        except Exception:
            pass
        return None

    def execute_block(self, ip: str, rid: str, reason: str):
        if ip not in self.active_blocked_ips:
            if apply_windows_firewall_block(ip):
                self.active_blocked_ips.add(ip)
                log_text = f"{ip} [RID: {rid}]" if rid != "UNKNOWN_RID" else ip
                self.signals.blocked_ip_signal.emit(log_text, reason)

    def trigger_automatic_ban_by_rid(self, ip: str, rid: str, reason: str):
        self.blacklist.add(ip)
        if rid != "UNKNOWN_RID":
            self.banned_list.add(rid)
        self.execute_block(ip, rid, reason)