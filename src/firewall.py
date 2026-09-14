import os
import time
import json
import re
import math
from enum import Enum
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


MAX_EVIDENCE_PER_PLAYER = 50


class MaliciousType(Enum):
    HACKER = "hacker"
    CHEATER = "cheater"
    MODERATOR = "moderator"
    EXPLOITER = "exploiter"
    MULTIAUTH = "multiauthority"
    BOT = "bot"
    SCRIPT_KIDDY = "script_kiddy"
    UNKNOWN = "unknown"

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


@dataclass
class DetectionEvidence:
    timestamp: float
    evidence_type: str
    value: str
    severity: str
    description: str


@dataclass
class MaliciousPlayer:
    ip: str
    rid: str
    fingerprint: str
    malicious_type: MaliciousType
    confidence_score: float
    first_detected: float
    last_seen: float
    evidence: List[DetectionEvidence]
    score_history: List[Tuple[float, float]]
    session_count: int
    ban_status: bool = False

    def add_evidence(self, evidence: DetectionEvidence):
        self.evidence.append(evidence)
        if len(self.evidence) > MAX_EVIDENCE_PER_PLAYER:
            self.evidence = self.evidence[-MAX_EVIDENCE_PER_PLAYER:]
        self.last_seen = evidence.timestamp

    def update_score(self, timestamp: float, score: float):
        self.score_history.append((timestamp, score))
        self.last_seen = timestamp
        if len(self.score_history) > 100:
            self.score_history = self.score_history[-100:]

    def to_dict(self):
        return {
            'ip': self.ip,
            'rid': self.rid,
            'fingerprint': self.fingerprint,
            'malicious_type': self.malicious_type.value,
            'confidence_score': self.confidence_score,
            'first_detected': self.first_detected,
            'last_seen': self.last_seen,
            'evidence': [asdict(e) for e in self.evidence],
            'score_history': self.score_history,
            'session_count': self.session_count,
            'ban_status': self.ban_status,
        }


# =====================================================================
# DATABASE — WAJIB ADA, TIDAK BOLEH DIHAPUS
# =====================================================================
class MaliciousDetectionDatabase:
    def __init__(self, database_file="malicious_players.json"):
        self.database_file = database_file
        self.malicious_players: Dict[str, MaliciousPlayer] = {}
        self._dirty = False
        self._last_save = 0.0
        self._save_interval = 5.0
        self.load_database()

    # ---------- Persistence ----------
    def mark_dirty(self):
        self._dirty = True

    def flush_if_needed(self, force: bool = False):
        now = time.time()
        if not self._dirty:
            return
        if force or (now - self._last_save) >= self._save_interval:
            self.save_database()
            self._last_save = now
            self._dirty = False

    def save_database(self):
        """Atomic write: tulis ke .tmp lalu os.replace → cegah korup saat crash."""
        tmp_file = self.database_file + ".tmp"
        try:
            data = {k: p.to_dict() for k, p in self.malicious_players.items()}
            with open(tmp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, separators=(',', ':'))
            os.replace(tmp_file, self.database_file)
        except Exception as e:
            print(f"[DB] Error saving database: {e}")
            try:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
            except Exception:
                pass

    def load_database(self):
        """Robust loader — handle file kosong / korup / tidak ada."""
        if not os.path.exists(self.database_file):
            return
        try:
            if os.path.getsize(self.database_file) == 0:
                print("[DB] File kosong, mulai fresh.")
                return
            with open(self.database_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            if not content:
                return
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("Root JSON bukan dict.")
        except json.JSONDecodeError as e:
            print(f"[DB] JSON korup ({e}), backup ke .bak.")
            try:
                backup = self.database_file + ".bak"
                if os.path.exists(backup):
                    os.remove(backup)
                os.replace(self.database_file, backup)
            except Exception:
                pass
            return
        except Exception as e:
            print(f"[DB] Error loading database: {e}")
            return

        for key, pd in data.items():
            try:
                evidence_list = [
                    DetectionEvidence(
                        timestamp=ev['timestamp'],
                        evidence_type=ev['evidence_type'],
                        value=ev['value'],
                        severity=ev['severity'],
                        description=ev['description'],
                    ) for ev in pd.get('evidence', [])
                ]
                player = MaliciousPlayer(
                    ip=pd['ip'],
                    rid=pd['rid'],
                    fingerprint=pd['fingerprint'],
                    malicious_type=MaliciousType(pd['malicious_type']),
                    confidence_score=pd['confidence_score'],
                    first_detected=pd['first_detected'],
                    last_seen=pd['last_seen'],
                    evidence=evidence_list,
                    score_history=[(ts, sc) for ts, sc in pd.get('score_history', [])],
                    session_count=pd.get('session_count', 1),
                    ban_status=pd.get('ban_status', False),
                )
                self.malicious_players[key] = player
            except (KeyError, TypeError, ValueError) as e:
                print(f"[DB] Skip corrupt entry {key}: {e}")

    # ---------- Query ----------
    def get_malicious_players(self, malicious_type: Optional[MaliciousType] = None,
                              confidence_threshold: float = 0.0,
                              time_filter_hours: Optional[int] = None) -> List[MaliciousPlayer]:
        players = list(self.malicious_players.values())
        if malicious_type is not None:
            players = [p for p in players if p.malicious_type == malicious_type]
        if confidence_threshold > 0:
            players = [p for p in players if p.confidence_score >= confidence_threshold]
        if time_filter_hours:
            cutoff = time.time() - (time_filter_hours * 3600)
            players = [p for p in players if p.last_seen >= cutoff]
        return sorted(players, key=lambda p: p.confidence_score, reverse=True)

    def update_ban_status(self, ip: str, rid: str, fingerprint: str, status: bool):
        if not fingerprint or fingerprint == "UNKNOWN_FP":
            for player in self.malicious_players.values():
                if player.ip == ip:
                    player.ban_status = status
                    if rid != "UNKNOWN_RID":
                        player.rid = rid
            self.mark_dirty()
            self.flush_if_needed(force=True)
            return

        key = f"{ip}_{fingerprint}"
        player = self.malicious_players.get(key)
        if player:
            player.ban_status = status
            if rid != "UNKNOWN_RID":
                player.rid = rid
            self.mark_dirty()
            self.flush_if_needed(force=True)

    def cleanup_old_entries(self, days_to_keep: int = 30):
        cutoff = time.time() - (days_to_keep * 86400)
        keys_to_remove = [k for k, p in self.malicious_players.items() if p.last_seen < cutoff]
        for key in keys_to_remove:
            del self.malicious_players[key]
        if keys_to_remove:
            self.mark_dirty()
            self.flush_if_needed(force=True)


# =====================================================================
# CLASSIFICATION ENGINE
# =====================================================================
class ClassificationEngine:
    def __init__(self, database: MaliciousDetectionDatabase):
        self.database = database
        self.score_weights = {
            'packet_size': 0.30,
            'pps_violation': 0.25,
            'behavior_pattern': 0.20,
            'network_anomaly': 0.15,
            'repeat_offense': 0.10,
        }

    def classify_player(self, ip, rid, fingerprint,
                        packet_size=0, pps_violations=0,
                        behavior_score=0.0, network_anomaly=False,
                        repeat_offenses=0,
                        payload_entropy=0.0,
                        identical_payload_streak=0,
                        rid_mismatch=False) -> MaliciousPlayer:
        base_score = self._calculate_confidence_score(
            packet_size, pps_violations, behavior_score, network_anomaly, repeat_offenses)
        malicious_type = self._determine_malicious_type(
            rid=rid, fingerprint=fingerprint, packet_size=packet_size,
            pps_violations=pps_violations, behavior_score=behavior_score,
            network_anomaly=network_anomaly, repeat_offenses=repeat_offenses,
            payload_entropy=payload_entropy,
            identical_payload_streak=identical_payload_streak,
            rid_mismatch=rid_mismatch)

        current_time = time.time()
        key = f"{ip}_{fingerprint}"

        if key in self.database.malicious_players:
            player = self.database.malicious_players[key]
            if malicious_type != MaliciousType.UNKNOWN and player.malicious_type == MaliciousType.UNKNOWN:
                player.malicious_type = malicious_type
            if rid != "UNKNOWN_RID" and player.rid == "UNKNOWN_RID":
                player.rid = rid
            if base_score > player.confidence_score:
                player.confidence_score = base_score
            if current_time - player.last_seen > 3600:
                player.session_count += 1
            player.last_seen = current_time
        else:
            player = MaliciousPlayer(
                ip=ip, rid=rid, fingerprint=fingerprint,
                malicious_type=malicious_type,
                confidence_score=base_score,
                first_detected=current_time, last_seen=current_time,
                evidence=[], score_history=[], session_count=1,
            )
            self.database.malicious_players[key] = player

        # ── Evidence (independen per indikator) ──
        evidence_added = False

        if packet_size > CRASH_SIZE_THRESHOLD:
            player.add_evidence(DetectionEvidence(
                timestamp=current_time, evidence_type="packet_size",
                value=str(packet_size), severity="HIGH",
                description=f"Large packet detected: {packet_size} bytes"))
            evidence_added = True

        if pps_violations >= 3:
            player.add_evidence(DetectionEvidence(
                timestamp=current_time, evidence_type="pps_violation",
                value=str(pps_violations), severity="MEDIUM",
                description=f"Packet flood: {pps_violations}x PPS violations"))
            evidence_added = True

        if behavior_score > 0.7:
            player.add_evidence(DetectionEvidence(
                timestamp=current_time, evidence_type="behavior_pattern",
                value=str(behavior_score), severity="HIGH",
                description=f"Abnormal behavior score: {behavior_score:.2f}"))
            evidence_added = True

        if network_anomaly:
            player.add_evidence(DetectionEvidence(
                timestamp=current_time, evidence_type="network_anomaly",
                value="true", severity="CRITICAL",
                description="Network anomaly detected (spoof/malformed)"))
            evidence_added = True

        if rid_mismatch:
            player.add_evidence(DetectionEvidence(
                timestamp=current_time, evidence_type="rid_mismatch",
                value="true", severity="CRITICAL",
                description="RID spoofing: 1 IP terdeteksi pakai multiple RID"))
            evidence_added = True

        if identical_payload_streak >= 20:
            player.add_evidence(DetectionEvidence(
                timestamp=current_time, evidence_type="bot_pattern",
                value=str(identical_payload_streak), severity="HIGH",
                description=f"Bot pattern: {identical_payload_streak}x payload identik"))
            evidence_added = True

        if repeat_offenses >= 2:
            player.add_evidence(DetectionEvidence(
                timestamp=current_time, evidence_type="repeat_offense",
                value=str(repeat_offenses), severity="MEDIUM",
                description=f"Repeat offenses count: {repeat_offenses}"))
            evidence_added = True

        if evidence_added:
            player.update_score(current_time, player.confidence_score)
            self.database.mark_dirty()

        self.database.flush_if_needed()
        return player

    def _calculate_confidence_score(self, packet_size, pps_violations,
                                    behavior_score, network_anomaly, repeat_offenses) -> float:
        score = 0.0
        if packet_size > CRASH_SIZE_THRESHOLD:
            score += self.score_weights['packet_size']
        if pps_violations >= 3:
            score += self.score_weights['pps_violation']
        if behavior_score > 0.7:
            score += self.score_weights['behavior_pattern']
        if network_anomaly:
            score += self.score_weights['network_anomaly']
        if repeat_offenses >= 2:
            score += self.score_weights['repeat_offense']
        return min(score, 1.0)

    def _determine_malicious_type(self, rid, fingerprint, packet_size, pps_violations,
                                  behavior_score, network_anomaly, repeat_offenses,
                                  payload_entropy, identical_payload_streak,
                                  rid_mismatch) -> MaliciousType:
        """Urutan prioritas: yang paling berbahaya dulu."""
        rid_str = str(rid or "")

        # 1. HACKER — spoofing/anomali jaringan = paling berbahaya
        if network_anomaly or rid_mismatch:
            return MaliciousType.HACKER

        # 2. EXPLOITER — pelanggaran berulang crash packet
        if repeat_offenses >= 3:
            return MaliciousType.EXPLOITER

        # 3. MULTIAUTH — flooding PPS masif
        if pps_violations >= 3:
            return MaliciousType.MULTIAUTH

        # 4. BOT — payload identik sangat konsisten
        if identical_payload_streak >= 30 and payload_entropy < 1.0:
            return MaliciousType.BOT

        # 5. CHEATER — crash packet tunggal tapi besar
        if packet_size > CRASH_SIZE_THRESHOLD:
            return MaliciousType.CHEATER

        # 6. SCRIPT_KIDDY — pola amatir
        if repeat_offenses == 2 or behavior_score > 0.5:
            return MaliciousType.SCRIPT_KIDDY

        # 7. MODERATOR — RID sangat kecil (kemungkinan internal/QA) — paling akhir
        if rid_str.isdigit() and 0 < int(rid_str) < 1_000_000:
            return MaliciousType.MODERATOR

        return MaliciousType.UNKNOWN


# =====================================================================
# TRACKER — dengan throttling emit + periodic cleanup
# =====================================================================
class MaliciousPlayerTracker:
    PPS_THRESHOLD = 500              # ← naik dari 100 → 500 (real GTA peak)
    ENTROPY_LOW_THRESHOLD = 1.0      # ← turunkan agar BOT butuh entropy benar-benar rendah
    IDENTICAL_STREAK_THRESHOLD = 30  # ← naik dari 20 → 30
    IDENTICAL_STREAK_MIN_INTERVAL = 30.0  # ← detik antar-paket minimal untuk dianggap BOT
    SESSION_TIMEOUT = 3600
    CLEANUP_INTERVAL = 500
    EMIT_MIN_INTERVAL = 15.0         # ← naik agar UI tidak spam
    EMIT_CONF_DELTA = 0.15

    def __init__(self, signals_handler, malicious_database: MaliciousDetectionDatabase):
        self.signals = signals_handler
        self.database = malicious_database
        self.classification_engine = ClassificationEngine(malicious_database)
        self.current_session_data: Dict[str, Dict] = {}
        self._ip_rid_history: Dict[str, set] = {}
        self._packet_count = 0

    # ---------- Helpers ----------
    @staticmethod
    def _payload_entropy(payload: bytes) -> float:
        """Shannon entropy (0..8)."""
        if not payload:
            return 0.0
        freq = [0] * 256
        for b in payload:
            freq[b] += 1
        n = len(payload)
        ent = 0.0
        for f in freq:
            if f:
                p = f / n
                ent -= p * math.log2(p)
        return ent

    def _extract_rid_fp(self, text: str) -> Tuple[str, str]:
        rid_match = re.search(r'\[RID:\s*([^\]]+)\]', text)
        rid = rid_match.group(1).strip() if rid_match else "UNKNOWN_RID"
        fp_match = re.search(r'\[FP:\s*([^\]]+)\]', text)
        fp = fp_match.group(1).strip() if fp_match else "UNKNOWN_FP"
        return rid, fp

    # ---------- Main handler ----------
    def handle_player_detection(self, raw_display_info: str, packet_size: int,
                                raw_payload: bytes = b"",
                                pps_current: int = 0,
                                ttl: int = 0):
        parts = raw_display_info.split()
        if not parts:
            return
        ip = parts[0]
        rid, fingerprint = self._extract_rid_fp(raw_display_info)

        # ── RID spoofing detection (1 IP banyak RID) ──
        rid_mismatch = False
        if rid != "UNKNOWN_RID":
            rid_set = self._ip_rid_history.setdefault(ip, set())
            rid_set.add(rid)
            if len(rid_set) > 1:
                rid_mismatch = True

        # ── Session state ──
        session_key = f"{ip}_{fingerprint}"
        session = self.current_session_data.setdefault(session_key, {
            'packet_size': 0,
            'pps_violations': 0,
            'behavior_score': 0.0,
            'network_anomaly': False,
            'repeat_offenses': 0,
            'identical_payload_streak': 0,
            'last_payload_hash': None,
            'last_detection': time.time(),
            'total_packets': 0,
            'last_emit_time': 0.0,
            'last_emit_confidence': 0.0,
            'last_emit_type': None,
        })

        # ── Update metrik ──
        session['packet_size'] = packet_size
        session['last_detection'] = time.time()
        session['total_packets'] += 1

        if packet_size > CRASH_SIZE_THRESHOLD:
            session['repeat_offenses'] += 1

        if pps_current > self.PPS_THRESHOLD:
            session['pps_violations'] += 1

        # Behavior score: naik saat anomali, decay saat normal
        if rid_mismatch or pps_current > self.PPS_THRESHOLD or packet_size > 1400:
            session['behavior_score'] = min(1.0, session['behavior_score'] + 0.25)
        else:
            session['behavior_score'] = max(0.0, session['behavior_score'] - 0.02)

        # Network anomaly dari TTL ekstrem
        if ttl and (ttl > 200 or ttl < 20):
            session['network_anomaly'] = True

        # Entropy & identical-payload streak
        entropy = 0.0
        if raw_payload:
            entropy = self._payload_entropy(raw_payload)
            payload_hash = hash(raw_payload)

            now = time.time()
            last_hash = session['last_payload_hash']
            last_ts = session.get('last_payload_time', 0.0)
            time_delta = now - last_ts

            if last_hash == payload_hash:
                # Hanya hitung streak jika jarak antar-paket < 30 detik
                # (heartbeat GTA normalnya 1-5 detik; >30 detik tidak wajar untuk bot)
                if time_delta < self.IDENTICAL_STREAK_MIN_INTERVAL:
                    session['identical_payload_streak'] += 1
                else:
                    session['identical_payload_streak'] = 1  # mulai streak baru
            else:
                session['identical_payload_streak'] = 0

            session['last_payload_hash'] = payload_hash
            session['last_payload_time'] = now

        # ── Klasifikasi ──
        player = self.classification_engine.classify_player(
            ip=ip, rid=rid, fingerprint=fingerprint,
            packet_size=packet_size,
            pps_violations=session['pps_violations'],
            behavior_score=session['behavior_score'],
            network_anomaly=session['network_anomaly'],
            repeat_offenses=session['repeat_offenses'],
            payload_entropy=entropy,
            identical_payload_streak=session['identical_payload_streak'],
            rid_mismatch=rid_mismatch,
        )

        # ── Throttled emit ──
        if rid != "UNKNOWN_RID":
            self._maybe_emit(player, session, ip, rid, fingerprint)

        # ── Periodic cleanup (jangan tiap paket!) ──
        self._packet_count += 1
        if self._packet_count % self.CLEANUP_INTERVAL == 0:
            self._cleanup_stale_sessions()

    def _maybe_emit(self, player, session, ip, rid, fingerprint):
        """Emit sinyal hanya jika ada perubahan penting / sudah cukup waktu."""
        now = time.time()
        cur_type = player.malicious_type
        cur_conf = player.confidence_score

        last_type = session.get('last_emit_type')
        last_conf = session.get('last_emit_confidence', 0.0)
        last_time = session.get('last_emit_time', 0.0)

        should_emit = False

        if cur_type in (MaliciousType.BOT, MaliciousType.MODERATOR):
            # Tipe langka — emit saat pertama kali / berubah / tiap 30 detik
            if cur_type != last_type or (now - last_time) > 30:
                should_emit = True
        elif cur_conf >= 0.7:
            if cur_type != last_type:
                should_emit = True
            elif cur_conf >= last_conf + self.EMIT_CONF_DELTA:
                should_emit = True
            elif (now - last_time) > self.EMIT_MIN_INTERVAL:
                should_emit = True

        if not should_emit:
            return

        session['last_emit_time'] = now
        session['last_emit_confidence'] = cur_conf
        session['last_emit_type'] = cur_type

        try:
            self.signals.malicious_player_signal.emit(
                f"{ip} [RID: {rid}] [FP: {fingerprint}] "
                f"[TYPE: {cur_type.value.upper()}] "
                f"[CONF: {cur_conf:.2f}]",
                player.to_dict()
            )
        except RuntimeError:
            pass

    def handle_player_blocked(self, log_text: str, reason: str):
        parts = log_text.split()
        if not parts:
            return
        ip = parts[0]
        rid, _ = self._extract_rid_fp(log_text)
        self.database.update_ban_status(ip, rid, "UNKNOWN_FP", True)

    def update_player_behavior_score(self, ip: str, fingerprint: str, score_delta: float):
        key = f"{ip}_{fingerprint}"
        session = self.current_session_data.get(key)
        if session:
            session['behavior_score'] = min(1.0, max(0.0, session['behavior_score'] + score_delta))

    def _cleanup_stale_sessions(self):
        now = time.time()
        stale = [k for k, s in self.current_session_data.items()
                 if now - s['last_detection'] > self.SESSION_TIMEOUT]
        for k in stale:
            del self.current_session_data[k]
        # Bersihkan juga IP RID history yang sudah tidak aktif
        active_ips = {k.split('_', 1)[0] for k in self.current_session_data}
        stale_ips = [ip for ip in self._ip_rid_history if ip not in active_ips]
        for ip in stale_ips:
            del self._ip_rid_history[ip]
