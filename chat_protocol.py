"""
Checkpoint 3 - Protokol Secure Chat sederhana (Alice <-> Bob)
Primitive (sesuai praktikum Minggu 9): ECDH P-256, HKDF-SHA256, AES-256-GCM
Tambahan untuk autentikasi (anti-MITM): ECDSA P-256 (tanda tangan identitas)
Hanya untuk BELAJAR, bukan protokol produksi.
"""
import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature, InvalidTag


def pub_bytes(pub):
    return pub.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint)


def sign(priv, data):
    return priv.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(pub, sig, data):
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def fingerprint(pub):
    return hashlib.sha256(pub_bytes(pub)).hexdigest()[:16]


def derive_keys(shared, transcript):
    """HKDF: satu shared secret -> dua kunci arah (konteks berbeda, Lab 1 Minggu 9)."""
    salt = hashlib.sha256(transcript).digest()
    def one(label):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label).derive(shared)
    return one(b"chat/v1/A->B"), one(b"chat/v1/B->A")


# ---------------------------------------------------------------- handshake
class Party:
    def __init__(self, name, ik_priv, peer_name, peer_ik_pub):
        self.name, self.ik_priv = name, ik_priv
        self.peer, self.peer_ik_pub = peer_name, peer_ik_pub   # pub peer = hasil verifikasi fingerprint

    # Pesan 1 (Alice -> Bob)
    def msg1(self):
        self.ek_priv = ec.generate_private_key(ec.SECP256R1())
        self.ek_pub = pub_bytes(self.ek_priv.public_key())
        self.nonce = os.urandom(16)
        self.m1 = b"MSG1|" + self.name.encode() + b"|" + self.peer.encode() + b"|" + self.ek_pub + self.nonce
        return self.ek_pub, self.nonce, sign(self.ik_priv, self.m1)

    # Bob memproses pesan 1, membalas pesan 2
    def msg2(self, ek_a, nonce_a, sig_a):
        m1 = b"MSG1|" + self.peer.encode() + b"|" + self.name.encode() + b"|" + ek_a + nonce_a
        if not verify(self.peer_ik_pub, sig_a, m1):
            raise ValueError("Tanda tangan Alice TIDAK valid -> sesi dibatalkan")
        self.ek_priv = ec.generate_private_key(ec.SECP256R1())
        ek_b = pub_bytes(self.ek_priv.public_key())
        nonce_b = os.urandom(16)
        self.transcript = m1 + ek_b + nonce_b
        sig_b = sign(self.ik_priv, b"MSG2|" + self.transcript)
        self._finish(ek_a)
        return ek_b, nonce_b, sig_b

    # Alice memproses pesan 2
    def handle_msg2(self, ek_b, nonce_b, sig_b):
        self.transcript = self.m1 + ek_b + nonce_b
        if not verify(self.peer_ik_pub, sig_b, b"MSG2|" + self.transcript):
            raise ValueError("Tanda tangan Bob TIDAK valid -> sesi dibatalkan")
        self._finish(ek_b)

    def _finish(self, peer_ek_bytes):
        peer_ek = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_ek_bytes)
        shared = self.ek_priv.exchange(ec.ECDH(), peer_ek)
        self.k_ab, self.k_ba = derive_keys(shared, self.transcript)
        self.ek_priv = None        # "hapus" kunci ephemeral (forward secrecy; batas del lihat Lab 7)
        self.send_seq, self.recv_seq = 0, -1

    # ------------------------------------------------------------- chat
    def send(self, text, i_am_alice):
        key = self.k_ab if i_am_alice else self.k_ba
        self.send_seq += 1
        nonce = self.send_seq.to_bytes(12, "big")               # counter: tidak pernah berulang
        aad = b"A->B" if i_am_alice else b"B->A"
        aad += self.send_seq.to_bytes(8, "big")
        return self.send_seq, AESGCM(key).encrypt(nonce, text.encode(), aad)

    def receive(self, seq, ct, from_alice):
        if seq <= self.recv_seq:
            raise ValueError("REPLAY: nomor urut sudah pernah dipakai -> ditolak")
        key = self.k_ab if from_alice else self.k_ba
        aad = (b"A->B" if from_alice else b"B->A") + seq.to_bytes(8, "big")
        pt = AESGCM(key).decrypt(seq.to_bytes(12, "big"), ct, aad)   # InvalidTag jika diubah
        self.recv_seq = seq
        return pt.decode()


def setup():
    ik_a = ec.generate_private_key(ec.SECP256R1())   # kunci identitas (jangka panjang)
    ik_b = ec.generate_private_key(ec.SECP256R1())
    # Distribusi kunci publik identitas: bertemu langsung & cocokkan fingerprint
    alice = Party("Alice", ik_a, "Bob", ik_b.public_key())
    bob = Party("Bob", ik_b, "Alice", ik_a.public_key())
    return ik_a, ik_b, alice, bob


def run_handshake(alice, bob):
    m1 = alice.msg1()
    m2 = bob.msg2(*m1)
    alice.handle_msg2(*m2)


def test(nama, fn):
    try:
        hasil = fn()
        print(f"[{nama}] -> {hasil}")
    except Exception as e:
        print(f"[{nama}] -> DITOLAK ({type(e).__name__}: {e})")


if __name__ == "__main__":
    ik_a, ik_b, alice, bob = setup()
    print("Fingerprint IK_A:", fingerprint(ik_a.public_key()), "| IK_B:", fingerprint(ik_b.public_key()))
    run_handshake(alice, bob)
    print("Kunci A->B sama di kedua sisi :", alice.k_ab == bob.k_ab)
    print("Kunci B->A sama di kedua sisi :", alice.k_ba == bob.k_ba)
    print("Kunci A->B != B->A            :", alice.k_ab != alice.k_ba)

    print("\n=== Pengujian ===")
    # T1 pesan normal
    seq, ct = alice.send("Halo Bob, ini rahasia", True)
    test("T1 pesan normal", lambda: bob.receive(seq, ct, True))
    # T2 ciphertext dimodifikasi
    seq2, ct2 = alice.send("Transfer 100", True)
    bad = bytearray(ct2); bad[0] ^= 1
    test("T2 ciphertext diubah Eve", lambda: bob.receive(seq2, bytes(bad), True))
    # T3 replay
    test("T3 replay pesan lama", lambda: bob.receive(seq, ct, True))
    # T4 MITM: Eve mengganti kunci ephemeral Alice dengan miliknya
    _, _, a2, b2 = setup()
    ek, nonce, sig = a2.msg1()
    eve_ek = pub_bytes(ec.generate_private_key(ec.SECP256R1()).public_key())
    test("T4 MITM tukar kunci ephemeral", lambda: b2.msg2(eve_ek, nonce, sig))
    # T5 Eve membuat tanda tangan dengan kunci identitas miliknya sendiri
    _, _, a3, b3 = setup()
    ek, nonce, _ = a3.msg1()
    eve_ik = ec.generate_private_key(ec.SECP256R1())
    fake_sig = sign(eve_ik, b"MSG1|Alice|Bob|" + ek + nonce)
    test("T5 Eve pakai tanda tangan sendiri", lambda: b3.msg2(ek, nonce, fake_sig))
    # T6 kasus gagal: fingerprint TIDAK diverifikasi (Bob memegang IK palsu milik Eve untuk 'Alice')
    ik_a6 = ec.generate_private_key(ec.SECP256R1()); ik_b6 = ec.generate_private_key(ec.SECP256R1())
    eve6 = ec.generate_private_key(ec.SECP256R1())
    alice6 = Party("Alice", ik_a6, "Bob", ik_b6.public_key())
    bob6 = Party("Bob", ik_b6, "Alice", eve6.public_key())   # Bob menerima IK palsu
    eve_alice = Party("Alice", eve6, "Bob", ik_b6.public_key())
    def t6():
        m1 = eve_alice.msg1(); m2 = bob6.msg2(*m1)
        return "Bob menerima Eve sebagai Alice (anti-MITM GAGAL karena IK tidak diverifikasi)"
    test("T6 IK palsu tanpa cek fingerprint", t6)
    # T7 dua sesi -> kunci berbeda (forward secrecy)
    _, _, a7, b7 = setup(); run_handshake(a7, b7); k1 = a7.k_ab
    run_handshake(a7, b7); k2 = a7.k_ab
    print("[T7 dua sesi, kunci sesi berbeda] ->", k1 != k2)
