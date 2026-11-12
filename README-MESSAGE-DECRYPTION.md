# MeshCore message decryption

The GNU Radio flowgraph still performs the RF/LoRa receive and packet decode. This addition decrypts MeshCore V1 message payloads when the matching keys are configured.

## Setup

Install the Python dependencies in the same Python environment used by GNU Radio:

```bash
python3 -m pip install -r requirements-meshcore-crypto.txt
```

Copy `meshcore_keys.example.json` to `meshcore_keys.json` next to `meshcore_rx.py`.

### Public hashtag channel

Add the channel name including `#`. MeshCore derives the 16-byte channel secret from the first 16 bytes of SHA-256 of the UTF-8 channel name. Anyone who knows the hashtag can derive this key; it is not private.

### Private channel

Add the channel name and its 16- or 32-byte secret as hexadecimal:

```json
{"name":"my-private-channel","secret":"32_OR_64_HEX_CHARACTERS"}
```

### Direct messages

Set `identity_private_seed` to the Ed25519 private key in hex (32-byte seed or 64-byte expanded private key) for the receiving/sending node. The decoder can decrypt a DM only when the packet is addressed to or sent by that identity and the other node's full public key has already been learned from an Advert/Discover response. A passive receiver cannot decrypt DMs for unrelated nodes.

Keep `meshcore_keys.json` private. Do not commit real channel secrets or private identity keys.

## Notes

- MeshCore group messages are unauthenticated; the displayed sender name is message text, not cryptographic proof of sender identity.
- Existing packet metadata and Advert CSV export remain in place.
