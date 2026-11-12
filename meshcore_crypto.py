"""MeshCore V1 packet decryption helpers.

Implements the algorithms used by meshcore-dev/MeshCore:
AES-128-ECB with zero padding and a 2-byte truncated HMAC-SHA256.
"""
import hashlib
import hmac
import json
import os
import struct

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception:
    Cipher = algorithms = modes = None

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.bindings import crypto_scalarmult
except Exception:
    SigningKey = VerifyKey = crypto_scalarmult = None


class MeshCoreCrypto:
    def __init__(self, directory):
        self.directory = directory
        self.config_path = os.path.join(directory, "meshcore_keys.json")
        self.config = {}
        self.channels = []
        self.identity_seed = None
        self.identity_public = None
        self._load_config()

    def _load_config(self):
        try:
            with open(self.config_path, "r", encoding="utf-8") as handle:
                self.config = json.load(handle)
        except FileNotFoundError:
            print("[MeshCore crypto] No meshcore_keys.json; metadata-only mode.")
            return
        except Exception as exc:
            print("[MeshCore crypto] Could not read key config:", repr(exc))
            return

        for item in self.config.get("channels", []):
            try:
                name = str(item["name"])
                if "secret" in item and item["secret"]:
                    secret = bytes.fromhex(item["secret"])
                elif name.startswith("#"):
                    # MeshCore hashtag channel key: first 16 bytes of SHA256(name).
                    secret = hashlib.sha256(name.encode("utf-8")).digest()[:16]
                else:
                    raise ValueError("channel requires a hex secret or a #name")
                if len(secret) not in (16, 32):
                    raise ValueError("channel secret must be 16 or 32 bytes")
                padded = secret.ljust(32, b"\\x00")
                channel_hash = hashlib.sha256(secret).digest()[0]
                self.channels.append((name, channel_hash, padded))
            except Exception as exc:
                print("[MeshCore crypto] Ignoring invalid channel entry:", repr(exc))

        seed_hex = self.config.get("identity_private_seed")
        if seed_hex:
            try:
                seed = bytes.fromhex(seed_hex)
                if len(seed) != 32:
                    raise ValueError("identity_private_seed must be 32-byte hex")
                if SigningKey is None:
                    raise RuntimeError("PyNaCl is not installed")
                self.identity_seed = seed
                self.identity_public = bytes(SigningKey(seed).verify_key)
            except Exception as exc:
                print("[MeshCore crypto] Identity key unavailable:", repr(exc))

        if Cipher is None:
            print("[MeshCore crypto] cryptography package missing; decryption disabled.")
        if SigningKey is None:
            print("[MeshCore crypto] PyNaCl missing; direct-message decryption disabled.")

    @staticmethod
    def _decrypt_mac_payload(secret, mac_and_ciphertext):
        if Cipher is None or len(secret) != 32 or len(mac_and_ciphertext) < 18:
            return None
        mac = mac_and_ciphertext[:2]
        ciphertext = mac_and_ciphertext[2:]
        if not ciphertext or len(ciphertext) % 16:
            return None
        expected = hmac.new(secret, ciphertext, hashlib.sha256).digest()[:2]
        if not hmac.compare_digest(mac, expected):
            return None
        try:
            decryptor = Cipher(algorithms.AES(secret[:16]), modes.ECB()).decryptor()
            plain = decryptor.update(ciphertext) + decryptor.finalize()
            return plain.rstrip(b"\\x00")
        except Exception:
            return None

    def decrypt_group(self, channel_hash, mac_and_ciphertext, payload_name):
        for name, known_hash, secret in self.channels:
            if known_hash != channel_hash:
                continue
            plain = self._decrypt_mac_payload(secret, mac_and_ciphertext)
            if plain is None or len(plain) < 5:
                continue
            timestamp = struct.unpack("<I", plain[:4])[0]
            flags = plain[4]
            body = plain[5:].decode("utf-8", errors="replace")
            return "%s | %s | %s (flags=0x%02X)" % (name, timestamp, body, flags)
        return None

    def decrypt_direct(self, payload, known_pubkeys):
        if self.identity_seed is None or self.identity_public is None or SigningKey is None:
            return None
        if len(payload) < 6:
            return None
        dest_hash, src_hash = payload[0], payload[1]
        if dest_hash == self.identity_public[0]:
            peer_hash = src_hash
        elif src_hash == self.identity_public[0]:
            peer_hash = dest_hash
        else:
            return None
        peer_hex = known_pubkeys.get(peer_hash)
        if not peer_hex:
            return None
        try:
            peer_public = bytes.fromhex(peer_hex)
            if len(peer_public) != 32 or VerifyKey is None:
                return None
            private_curve = SigningKey(self.identity_seed).to_curve25519_private_key()
            public_curve = VerifyKey(peer_public).to_curve25519_public_key()
            shared = crypto_scalarmult(bytes(private_curve), bytes(public_curve))
            plain = self._decrypt_mac_payload(shared, payload[2:])
            if plain is None or len(plain) < 5:
                return None
            timestamp = struct.unpack("<I", plain[:4])[0]
            flags = plain[4]
            body = plain[5:].decode("utf-8", errors="replace")
            return "DM | %s | %s (flags=0x%02X)" % (timestamp, body, flags)
        except Exception as exc:
            print("[MeshCore crypto] DM decrypt error:", repr(exc))
            return None
