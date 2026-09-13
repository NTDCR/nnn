# Security Architecture, Threat Model & Limitations

## 1. Threat Model

The Fort-Knox Cascade is designed against an adversary with:
- **Full Physical Storage Interception**: Storage media or cloud backups inspected by forensic teams, government agencies, or unauthorized actors.
- **Quantum Computing Advances**: Grover's algorithm halves symmetric key strength (256-bit -> 128-bit effective security). A 4-layer cascade with four independent 256-bit keys ensures a combined effective post-quantum security margin far exceeding 256 bits.
- **Cryptanalytic Breaks on Individual Ciphers**: If an unexpected breakthrough compromises AES (e.g. biclique attacks or cache attacks) or ChaCha20, the inner Threefish-1024 and Serpent-256 layers preserve 100% confidentiality.
- **Traffic / Storage Identification Avoidance**: The absence of file magic bytes, MIME headers, or known file signatures frustrates heuristic deep packet inspection (DPI) and automated ransomware scanners.

---

## 2. Cascade Composition Rationale

The cascade sequence is strictly:
1. **Threefish-1024-CTR (Innermost)**: Extremely large 1024-bit state cipher. Designed for high diffusion with 80 rounds of ARX (Add-Rotate-Xor) operations.
2. **Serpent-256-CTR**: AES finalist rated highest for conservative security margins (32 rounds, 8 4x4 S-boxes).
3. **ChaCha20-Poly1305 AEAD**: High-speed, SIMD-friendly stream cipher with constant-time 128-bit Carter-Wegman MAC.
4. **AES-256-GCM AEAD (Outermost)**: Hardware-accelerated (AES-NI / ARMv8 Crypto) envelope providing Galois/Counter Mode authentication.

---

## 3. WebAssembly & Browser JIT Constant-Time Limitations (Honest Disclosure)

Users and security engineers must recognize fundamental browser execution limitations:
1. **Browser JIT Compiler Non-Determinism**: Even when Rust code compiles to branchless, constant-time machine code via LLVM, modern JavaScript/WASM engines (V8 in Chromium, SpiderMonkey in Firefox, JavaScriptCore in WebKit) perform dynamic tiering, speculative optimization, and register allocation. Strict constant-time cannot be mathematically guaranteed across arbitrary browser architectures.
2. **Cache-Timing in Software AES/Serpent**: Hardware AES (AES-NI) is constant time. Software implementations of table-based ciphers or S-boxes can exhibit microarchitectural cache-line latency variations. In Fort-Knox, outermost AES uses native browser WebCrypto `AES-GCM` (leveraging hardware CPU instructions) whenever available.
3. **Threefish and Serpent Verification Status**: While ChaCha20-Poly1305 and AES-GCM have extensive formal verification (e.g., HACL*, Project Everest), Threefish-1024 and Serpent lack equivalent publicly verified constant-time implementations in WASM.
4. **Spectre & Microarchitectural Leaks**: Browsers have added site isolation and reduced timer resolution (`performance.now()` jitter) to mitigate side-channel timing attacks, but shared-core CPU execution inherently carries low-bandwidth cache leakage risks.

---

## 4. Key Management & Recovery Policy

- **No Passphrase KDF Overhead by Default**: Keys are generated using the browser's cryptographically secure pseudo-random number generator (`crypto.getRandomValues`) with 256 bits of true entropy per key. This bypasses Argon2id computation during routine file streaming and maximizes I/O throughput.
- **Zero Key Persistence**: Keys reside strictly in ephemeral memory in the active session and Web Worker. They are never written to IndexedDB, LocalStorage, or cookies.
- **Absolute Non-Recovery Guarantee**: There is NO backdoor, recovery escrow, or password reset mechanism. If any of the four keys is lost, data recovery is mathematically impossible.
