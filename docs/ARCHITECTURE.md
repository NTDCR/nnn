# Fort-Knox Cascade Architecture Overview

## 1. System Architecture Diagram

```
+-----------------------------------------------------------------------------------+
| Browser Main Thread (React 19 + TypeScript + Tailwind CSS)                       |
|                                                                                   |
|  - Key Management (4 x 256-bit keys, crypto.getRandomValues, entropy evaluation) |
|  - File Picker (Drag-and-Drop, File System Access API picker)                    |
|  - In-App PWA Install Prompt & Service Worker Cache Manager                       |
|  - Multi-Layer Progress Tracker (Layer 1..4, Chunk N/Total, MB/s throughput)     |
+------------------------------------------+----------------------------------------+
                                           | PostMessage (Zero-Copy Transferable)
                                           v
+-----------------------------------------------------------------------------------+
| Dedicated Web Worker (`cascadeWorker.ts`)                                         |
|                                                                                   |
|  - Reads file stream in 1 MB chunks (ReadableStream / slice)                      |
|  - RAM Ceiling: 2 - 3 MB active heap (buffer reclaimed immediately per chunk)     |
|  - Direct-to-Disk Streaming via FileSystemWritableFileStream                      |
|                                                                                   |
|  +-----------------------------------------------------------------------------+ |
|  | Cryptographic Pipeline (Per 1 MB Chunk)                                     | |
|  |                                                                             | |
|  | Plaintext (1 MB)                                                            | |
|  |    │                                                                        | |
|  |    ▼ [Layer 1] Threefish-1024-CTR (Innermost, 1024-bit block ARX cipher)   | |
|  |    │                                                                        | |
|  |    ▼ [Layer 2] Serpent-256-CTR (32 rounds bit-slice S-box cipher)          | |
|  |    │                                                                        | |
|  |    ▼ [Layer 3] ChaCha20-Poly1305 (AEAD with 128-bit MAC tag)                 | |
|  |    │                                                                        | |
|  |    ▼ [Layer 4] AES-256-GCM (Outermost, WebCrypto hardware AES-NI / WASM)    | |
|  |    │                                                                        | |
|  |    ▼ Encrypted Chunk to Disk Writable Stream                                | |
|  +-----------------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------------+
```

---

## 2. Directory Structure

```
/
├── public/
│   ├── icon.svg
│   ├── pwa-192x192.png
│   ├── pwa-512x512.png
│   ├── pwa-maskable-512x512.png
│   └── apple-touch-icon.png
├── docs/
│   ├── ARCHITECTURE.md
│   ├── FILE_FORMAT_SPEC.md
│   └── SECURITY_NOTES.md
├── rust-wasm-crate/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── threefish.rs
│       ├── serpent.rs
│       ├── chacha.rs
│       └── aes.rs
├── src/
│   ├── components/
│   │   ├── FileProcessor.tsx
│   │   ├── FormatInspectorModal.tsx
│   │   ├── KeyManager.tsx
│   │   ├── OfflineIndicator.tsx
│   │   ├── ProgressBar.tsx
│   │   ├── PWAInstallButton.tsx
│   │   ├── RustCrateViewerModal.tsx
│   │   ├── SecurityNotesModal.tsx
│   │   └── TestVectorsModal.tsx
│   ├── crypto/
│   │   ├── aes256gcm.ts
│   │   ├── cascade.ts
│   │   ├── chacha20poly1305.ts
│   │   ├── format.ts
│   │   ├── serpent256.ts
│   │   ├── testVectors.ts
│   │   ├── threefish1024.ts
│   │   └── wasmBridge.ts
│   ├── hooks/
│   │   ├── useOnlineStatus.ts
│   │   └── usePWAInstall.ts
│   ├── types/
│   │   └── crypto.ts
│   ├── workers/
│   │   └── cascadeWorker.ts
│   ├── App.tsx
│   ├── index.css
│   └── main.tsx
├── index.html
├── metadata.json
├── package.json
├── tsconfig.json
└── vite.config.ts
```
