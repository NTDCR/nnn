# Fort-Knox Antiforensic Container Specification (V1)

## 1. Overview & Security Goals

The Fort-Knox container format is designed for high-security, antiforensic file storage:
- **Zero Magic Bytes / File Signatures**: The encrypted file starts and ends with high-entropy bytes indistinguishable from pure uniform random noise.
- **Zero Plaintext Metadata**: Filenames, MIME types, chunk counts, nonces, timestamps, and padding lengths are strictly concealed inside an encrypted, XORed metadata payload.
- **Padded Fixed-Block Chunking**: All data chunks are processed in uniform 1 MB (1,048,576 bytes) blocks. The final chunk is padded with cryptographically secure random bytes (`crypto.getRandomValues`) so that the payload length is an exact multiple of 1 MB.
- **Hidden Metadata Blob at Pseudo-Random Offset**: Metadata is embedded within the ciphertext stream at a pseudo-random offset.
- **Encrypted Tail Pointer**: The last 32 bytes of the container contain the encrypted location and length of the hidden metadata blob.

---

## 2. Container Layout (Byte-Level)

```
+-----------------------------------------------------------------------------+
| Offset (Hex / Dec)   | Field                                | Length        |
+-----------------------------------------------------------------------------+
| 0x0000000000000000   | Encrypted Chunk 0 (Cascade 1..4)     | 1,048,576 B   |
| 0x0000000000100000   | Encrypted Chunk 1 (Cascade 1..4)     | 1,048,576 B   |
| ...                  | ...                                  | ...           |
| [Random Offset O]    | Hidden Metadata Blob (XORed Stream)  | 512 Bytes     |
| ...                  | ...                                  | ...           |
| [Padded Chunk N-1]   | Final Encrypted Chunk (Random Pad)   | 1,048,576 B   |
| EOF - 32 Bytes       | Encrypted Offset Pointer + Auth Tag  | 32 Bytes      |
+-----------------------------------------------------------------------------+
```

---

## 3. Hidden Metadata Blob Specification (512 Bytes)

The hidden metadata blob is a fixed 512-byte binary structure:

| Offset (Bytes) | Size (Bytes) | Field Name | Description |
|---|---|---|---|
| 0 | 4 | `MAGIC_HEADER` | Internal verification magic: `0x464B4E31` ("FKN1") |
| 4 | 4 | `VERSION` | Container format version: `0x00000001` (v1) |
| 8 | 8 | `ORIGINAL_SIZE` | Original unpadded plaintext size in bytes (uint64, LE) |
| 16 | 4 | `CHUNK_COUNT` | Total number of 1 MB chunks (uint32, LE) |
| 20 | 4 | `CHUNK_SIZE` | Chunk size in bytes: `1048576` (uint32, LE) |
| 24 | 16 | `NONCE_THREEFISH` | Base nonce for Layer 1 (Threefish-1024-CTR) |
| 40 | 16 | `NONCE_SERPENT` | Base nonce for Layer 2 (Serpent-256-CTR) |
| 56 | 12 | `NONCE_CHACHA20` | Base nonce for Layer 3 (ChaCha20-Poly1305) |
| 68 | 12 | `NONCE_AES256` | Base nonce for Layer 4 (AES-256-GCM) |
| 80 | 32 | `HMAC_INTEGRITY` | HMAC-SHA256 of entire plaintext under Layer 1/2 key |
| 112 | 32 | `ORDER_CONFIRM` | Hash proving correct 4-layer cascade sequence |
| 144 | 16 | `KDF_SALT_RESERVED`| Salt if optional Argon2id key-wrapping is enabled |
| 160 | 352 | `RANDOM_PADDING` | Cryptographic random padding to exactly 512 bytes |

### Keystream XOR Obfuscation

Before insertion, the 512-byte metadata blob is XORed with a keystream derived using HKDF-SHA256 from the outermost key (Layer 4 AES key) and a metadata-specific salt:

```
Keystream = ChaCha20_Keystream(
    Key = HKDF_Extract_and_Expand(Key4, Salt="FORTKNOX_METADATA_V1", Length=32),
    Nonce = 12 bytes derived from pointer
)
Cipher_Metadata = Plain_Metadata XOR Keystream
```

---

## 4. Encrypted Tail Pointer (Last 32 Bytes)

The final 32 bytes of the container encode the location of the hidden metadata blob:

```
[Offset (8 Bytes LE)] [Length (4 Bytes LE)] [Padding (4 Bytes)] [AEAD Auth Tag (16 Bytes)]
```

- **Encryption**: Encrypted using AES-256-GCM with Key 4 and Nonce `AES_POINTER_NONCE` (derived from `NONCE_AES256 ^ 0xFF..FF`).
- **Antiforensic Property**: To any party without Key 4, these 32 bytes are indistinguishable from the preceding ciphertext.

---

## 5. Constant-Time Verification & Error Handling

When decrypting:
1. Attempt to read and decrypt the 32-byte tail pointer.
2. Read and un-XOR the hidden metadata blob.
3. Validate internal magic marker `0x464B4E31` and HMAC integrity tags using `subtle.constant_time_compare`.
4. If **any** check fails at **any** layer, the application returns a single uniform error:
   ```
   "Decryption failed. Check all keys."
   ```
   **No timing oracle or status code reveals which layer or key failed.**

---

## 6. Anti-Forensic Plausible Deniability & Modulo Annihilation (V1.1)

To protect files against static digital forensic analyzers that detect fixed mathematical block/container formulas:

1. **Cryptographic Random Tail Jitter Padding (CRTP)**:
   - When Anti-Forensic mode is active, an unpredictable random sequence of $R$ cryptographically secure pseudorandom bytes ($1,024 \le R \le 65,536$) is appended after the masked metadata blob and before the tail pointer.
   - The file size becomes:
     $$\text{Total Container Size} = \sum_{i=0}^{N-1} \text{Len}(\text{Chunk}_i) + \text{Len}(\text{MaskedMeta}) + R + \text{Len}(\text{TailPointer})$$
   - This completely destroys the forensic modulo equation `(FileSize - 544) % 1048608 === 0`.
2. **Decoupled Authenticated Tail Salt**:
   - The 16-byte salt for AES-256-GCM tail pointer encryption is derived from the 16 bytes immediately preceding the 32-byte tail pointer block:
     $$\text{Salt}_{16} = \text{Container}[\text{EOF} - 48 \dots \text{EOF} - 32]$$
   - If $R = 0$ (Legacy mode), the salt is the last 16 bytes of the metadata block.
   - If $R > 0$ (Anti-forensic mode), the salt is the last 16 bytes of the CSPRNG jitter padding.
   - Any bit tampering with the jitter padding or the tail pointer results in immediate authentication failure.
3. **Statistical Indistinguishability from Random Noise (IND-CPA / Plausible Deniability)**:
   - Every byte from Byte 0 to Byte EOF exhibits uniform Shannon entropy ($H \ge 7.9998$ bits/byte) and satisfies Chi-squared independence tests ($\chi^2 \approx 255 \pm 30$).
   - Without Key 4, the container cannot be mathematically distinguished from pseudo-random garbage generated by drive-wiping utilities (e.g. `dd if=/dev/urandom of=wipe.dat`).
4. **Permanent Removal of Legacy Fixed Pointers (No Backward Compatibility)**:
   - Backward compatibility with legacy V1.0 fixed-offset pointers (`EOF - 32`) has been permanently removed to eliminate the dual-trial attack surface and prevent timing variance.
   - All containers strictly enforce the V2.0 Blind KDF Pointer offset. Legacy unpadded containers without blind offset are strictly rejected.

---

## 7. Next-Gen 2X Anti-Forensics: Blind KDF Pointer, Pre-Metadata Jitter & Acoustic Polyglot (V2.1)

For high-adversity threat models requiring absolute pointer concealment, boundary obliteration, and entropy triage evasion:

1. **Blind KDF-Derived Pointer Offset (Expanded 64 KB Window)**:
   - Eliminates the fixed `EOF - 32` tail pointer anchor entirely.
   - The distance from the end of the container is derived using HMAC-SHA256 from Key 4 across an expanded 64 KB ($65,536\text{ bytes}$) search space:
     $$\text{Delta} = \text{HMAC-SHA256}(K_4, \text{"FORTKNOX_BLIND_POINTER_DELTA_V2"}) \pmod{65536}$$
     $$\text{PointerOffset} = \text{ContainerEnd} - 32 - \text{Delta}$$
   - The pointer is insulated on both sides by CSPRNG random jitter (`PrefixJitter` $\ge 1024$ bytes before, `SuffixJitter` = $\text{Delta}$ bytes after).
   - An investigator inspecting `EOF - 32` finds only random noise across a 64 KB window.

2. **Scatter-Gather Pre-Metadata Jitter (Internal Boundary Obliteration)**:
   - Eliminates the deterministic chunk-to-metadata boundary at `chunkCount * 1048608`.
   - A variable CSPRNG jitter buffer ($1,024 \dots 32,768$ bytes) is streamed immediately between the final encrypted chunk and the masked metadata blob:
     $$\text{MetadataOffset} = \text{chunkCount} \times 1048608 + \text{PreMetaJitter}$$
   - The exact offset is stored only inside the authenticated tail pointer. To an adversary without Key 4, there is zero recognizable boundary between chunks, metadata, and jitter noise.

3. **RIFF WAVE Polyglot Carrier with Acoustic TPDF Dithering (`.wav`)**:
   - Encapsulates the cascade container inside a valid RIFF WAVE audio stream with authentic studio-grade TPDF acoustic dithering ($-72\text{ dBFS}$, $\pm 1 \dots \pm 12$ LSB at 44.1 kHz, 16-bit mono).
   - **Entropy Discontinuity Annihilation**: The PCM audio section exhibits natural acoustic entropy ($3.5 \dots 4.8\text{ bits/byte}$), eliminating the artificial $0.0 \to 8.0$ step-function that automated triage scanners (e.g. `binwalk -E`) flag as suspect.
   - **Playback Compliance**: Plays as clean, natural studio room tone in VLC, Windows Media Player, QuickTime, Audacity, and web browsers with zero distortion or clipping.
   - **Decryption**: The decryptor inspects the first 128 bytes, detects the RIFF WAVE carrier, extracts the payload offset, and decrypts the underlying cascade container bit-for-bit.


