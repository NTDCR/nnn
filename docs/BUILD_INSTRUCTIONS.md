# Fort-Knox Cascade: Compilation & Build Guide

This document details the build pipeline for both the Web application and the high-throughput Rust WebAssembly crate.

---

## 1. Web Application & PWA Build

The web frontend is built using Vite, React 18, and Tailwind CSS.

### Development Mode
```bash
npm run dev
```
Starts the local development server at `http://localhost:3000`.

### Production Build
```bash
npm run build
```
Outputs the static, fully offline-capable PWA bundle into `/dist`, including:
- Service Worker registration (`sw.js`)
- Precached asset manifest (`workbox`)
- Web Workers (`cascadeWorker.js`)
- PWA Web App Manifest (`manifest.webmanifest`)
- High-resolution adaptive icons (192x192, 512x512, maskable, apple-touch-icon)

---

## 2. Rust WebAssembly Crate Compilation

The cryptographic cascade core is implemented in Rust inside `/rust-wasm-crate/`.

### Prerequisites
1. Install Rust and `cargo` via rustup:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
2. Add the `wasm32-unknown-unknown` target:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```
3. Install `wasm-pack`:
   ```bash
   cargo install wasm-pack
   ```

### Compiling to WASM
From the repository root or within `/rust-wasm-crate/`:
```bash
cd rust-wasm-crate
wasm-pack build --target web --release --out-dir ../src/wasm_pkg
```

### Compiler Optimization Flags
The `Cargo.toml` file is configured with:
```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
overflow-checks = false
```
This produces a compact binary (~80 KB gzipped) with loop unrolling, SIMD-128 vectorization, and inlined ARX rotations.

---

## 3. Cryptographic Test Vector Verification

Official NIST SP 800-38D, RFC 8439, and NESSIE test vectors can be executed directly within the web interface under the **NIST / RFC Verification** tab, or run programmatically via:

```typescript
import { runSelfVerificationTests } from './src/crypto/testVectors';

const results = await runSelfVerificationTests();
results.forEach((r) => console.log(`${r.suite} - ${r.name}: ${r.passed ? 'PASS' : 'FAIL'}`));
```
