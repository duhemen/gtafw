# 🛡️ GTA Firewall (GTAFW) v2.5

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![PyQt6](https://img.shields.io/badge/PyQt6-6.7%2B-green?style=for-the-badge&logo=qt)
![Network](https://img.shields.io/badge/Socket-Native%20Raw-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20Only-0078D6?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**GTAFW (GTA Firewall)** adalah aplikasi keamanan jaringan lokal tingkat lanjut berbasis **PyQt6** dan **Native Raw Sockets**. Aplikasi ini dirancang khusus untuk memproteksi sesi lobi GTA Online dari *Modder*, serangan *Crash Packet*, dan *Lobby Flooding* melalui ekstraksi **Rockstar ID (RID)** serta **Device Fingerprinting (`FP`)** secara real-time pada protokol P2P UDP port 6672.

---

## 🖼️ Tampilan Sistem & Review Operasional

![GTAFW System Interface](gtafw.png)

### 📊 Review Performa & Pengujian Sesi Publik

Berdasarkan hasil pengujian langsung pada lobi publik GTA Online (*Public Session*):

* **Stabilitas Lobi (Zero Session Split)**: Aplikasi berhasil memantau lalu lintas P2P tanpa memicu *disconnect* massal (*lobby split*). Pemain resmi tetap terhubung secara stabil.
* **Presisi Device Fingerprinting (`FP`)**: Setiap klien *peer* yang terhubung mendapatkan Hash Fingerprint unik (contoh: `FP: 041A7CD4`, `FP: 3F1051E9`). Hal ini mencegah kesalahan pemblokiran acak (*false positive*) yang kerap terjadi pada metode pemblokiran IP Range.
* **Bypass IP Lokal Keras**: Sistem secara otomatis mengecualikan IP host lokal (`192.168.43.113`) dan IP *loopback/broadcast*, sehingga aplikasi aman dari risiko *self-block*.
* **Lightweight Sniffing Engine**: Penggunaan Raw Socket bawaan Python menghilangkan ketergantungan pada pustaka pihak ketiga seperti Scapy atau Npcap driver, sehingga konsumsi CPU dan RAM tetap minim saat game berjalan.

---

## 🚀 Fitur Utama

- 🧬 **Composite Device Fingerprinting (`FP`)**: Menggabungkan parameter header `IP + TTL` menjadi Signature Hash 8-karakter unik untuk mengenali perangkat modder meskipun mereka mengganti alamat IP atau menggunakan VPN.
- 🔍 **Real-time RID Parsing**: Membedah *payload* biner UDP RAGE Engine secara instan untuk mendeteksi identitas asli Rockstar ID pemain.
- ⚡ **Automated Attack Mitigation**: Algoritma mitigasi otomatis terhadap serangan *Crash Packets* (>1400 Bytes) dan *Packet Flooding* (>280 PPS dengan sistem 3x penalti toleransi).
- 🛡️ **Smart Anti-Self Block**: Mekanisme filtrasi otomatis untuk mendeteksi IP lokal PC serta lalu lintas *broadcast* agar tidak memblokir diri sendiri.
- 🧱 **Windows Firewall Integration**: Menambahkan dan menghapus aturan *Inbound/Outbound* secara *native* via API `netsh` Windows Firewall.
- 📜 **Persistent Database**: Menyimpan daftar Whitelist IP, Blacklist, dan Banned RID secara otomatis ke berkas teks lokal.
- 🧹 **Graceful Emergency Cleanup**: Tombol reset darurat dan pembersihan otomatis aturan firewall saat aplikasi ditutup.

---

## 📁 Struktur Proyek

```text
gtafw/
├── .gtafw/                # Environment virtual Python
├── src/
│   ├── __init__.py        # Module package initializer
│   ├── core.py            # Engine sniffing Native Raw Socket & Fingerprinting
│   ├── firewall.py        # Modul manipulasi Windows Firewall (netsh API)
│   └── gui.py             # User Interface PyQt6 & Signal Router
├── gtafw.png              # Tangkapan layar antarmuka & review sistem
├── main.py                # Entry point & privilege checker (Admin Escalation)
├── README.md              # Dokumentasi teknis proyek
└── requirements.txt       # Daftar dependensi Python (PyQt6)

```

---

## ⚙️ Panduan Instalasi

Sistem ini wajib dioperasikan pada OS Windows dengan hak akses Administrator.

### 1. Kloning Repositori & Masuk ke Direktori

```powershell
git clone [https://github.com/duhemen/gtafw.git](https://github.com/duhemen/gtafw.git)
cd gtafw

```

### 2. Membuat & Mengaktifkan Virtual Environment

Buka **PowerShell / Command Prompt** (Run as Administrator):

```powershell
python -m venv .gtafw
.\.gtafw\Scripts\activate

```

### 3. Menginstal Dependensi

```powershell
pip install --upgrade pip
pip install -r requirements.txt

```

---

## 🎮 Cara Menjalankan Aplikasi

Aplikasi membutuhkan akses mentah ke Kartu Jaringan (*Network Interface Card*) dan Windows Firewall. **Wajib dijalankan sebagai Administrator**.

```powershell
# Pastikan venv .gtafw aktif
python main.py

```

---

## 📖 Panduan Penggunaan

1. **Aktifkan Proteksi**:
Jalankan aplikasi lalu klik **Aktifkan Proteksi** saat berada di sesi GTA Online. Sistem akan mulai menangkap lalu lintas P2P di port UDP 6672.
2. **Pantau Klien & Fingerprint**:
Daftar pemain yang terhubung akan menampilkan IP, Rockstar ID (`RID`), dan Device Fingerprint (`FP`).
3. **Whitelist Teman**:
Pilih IP teman di daftar lobi aktif, lalu klik **Pindahkan ke Whitelist** untuk menjamin koneksinya tidak terganggu.
4. **Permanent Ban RID & Fingerprint**:
Pilih modder/pengganggu pada tabel aktif, lalu klik **Ban Permanen RID Player Ini**. Identitas RID dan Fingerprint perangkat akan dikunci permanen.
5. **Reset Emergency**:
Gunakan tombol **Reset Semua Aturan Windows** untuk membersihkan seluruh aturan pemblokiran firewall buatan GTAFW secara instan.
