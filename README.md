# Cryptography: Checkpoint 3 (Secure Chat Anti-MITM)

Demo protokol **Secure Chat** antara Alice dan Bob yang tahan terhadap serangan Man-in-the-Middle (MITM). Dibuat untuk tugas Checkpoint 3 mata kuliah Kriptografi. Hanya untuk belajar, **bukan protokol produksi** dan belum diaudit.

## Isi repo

| File | Keterangan |
|---|---|
| `chat_protocol.py` | Kode utama: handshake, penurunan kunci, enkripsi pesan, dan 7 skenario pengujian |

## Ide protokol

1. Alice dan Bob sudah saling memegang **kunci publik identitas** yang fingerprint-nya dicek tatap muka.
2. Masing-masing membuat **kunci ECDH sementara**, lalu menandatanganinya dengan kunci identitas (ECDSA). Eve tidak bisa menukar kunci tanpa ketahuan.
3. Kedua pihak menghitung rahasia bersama lewat ECDH, lalu **HKDF** menurunkan dua kunci: `K_AB` (Alice ke Bob) dan `K_BA` (Bob ke Alice). Tidak ada kunci yang dikirim lewat jaringan.
4. Pesan dienkripsi dengan **AES-256-GCM**. Nomor urut (`seq`) dipakai sebagai nonce dan AAD untuk menolak pesan yang diulang (replay).

Primitive yang dipakai: ECDH P-256, ECDSA P-256, HKDF-SHA256, AES-256-GCM, SHA-256.

## Struktur kode `chat_protocol.py`

| Bagian | Fungsi |
|---|---|
| `sign`, `verify`, `fingerprint`, `pub_bytes` | Fungsi bantu: tanda tangan, verifikasi, fingerprint kunci publik |
| `derive_keys` | HKDF: satu rahasia bersama menjadi dua kunci arah |
| `class Party` | Satu pihak (Alice atau Bob) |
| `Party.msg1` | Pesan 1: Alice membuat kunci sementara dan menandatanganinya |
| `Party.msg2` | Pesan 2: Bob memverifikasi Alice, lalu membalas dengan kunci dan tanda tangannya |
| `Party.handle_msg2` | Alice memverifikasi balasan Bob |
| `Party._finish` | ECDH + HKDF, lalu menghapus kunci privat sementara |
| `Party.send`, `Party.receive` | Enkripsi dan dekripsi AES-GCM, plus penolakan replay |
| `setup`, `run_handshake` | Menyiapkan dua pihak dan menjalankan handshake |
| blok `__main__` | Menjalankan pengujian T1 sampai T7 |

## Cara menjalankan

Butuh Python 3.10 atau lebih baru.

```bash
pip install cryptography
python chat_protocol.py
```

## Hasil yang diharapkan

| Uji | Skenario | Hasil |
|---|---|---|
| T1 | Pesan normal Alice ke Bob | Diterima |
| T2 | Eve mengubah ciphertext | Ditolak (`InvalidTag`) |
| T3 | Eve mengirim ulang pesan lama | Ditolak (replay) |
| T4 | Eve mengganti kunci sementara Alice | Ditolak (tanda tangan tidak valid) |
| T5 | Eve memakai tanda tangan dari kuncinya sendiri | Ditolak (tanda tangan tidak valid) |
| T6 | Kunci identitas palsu, fingerprint tidak dicek | **Berhasil ditipu**, ini sengaja untuk menunjukkan batas desain |
| T7 | Dua sesi berturut-turut | Kunci sesi berbeda (forward secrecy) |

Nilai fingerprint berbeda di setiap eksekusi karena kunci dibuat acak.

## Batasan

- Keamanan bergantung pada fingerprint kunci identitas yang diverifikasi dengan benar.
- Tidak melindungi dari DoS, kebocoran metadata, atau perangkat yang sudah terinfeksi.
- Forward secrecy hanya per sesi, bukan per pesan (tidak ada Double Ratchet).
- `del` di Python tidak menjamin memori terhapus (lihat praktikum zeroization Minggu 9).
- Protokol ini versi sederhana dari pola signed Diffie-Hellman yang sudah ada (Station-to-Station, SIGMA, TLS 1.3), bukan protokol baru.
