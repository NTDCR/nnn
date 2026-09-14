import React, { useEffect } from 'react';
import { X, Shield, FileText, Layers, Lock, Cpu, EyeOff } from 'lucide-react';

interface SpecModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SpecModal: React.FC<SpecModalProps> = ({ isOpen, onClose }) => {
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      id="spec-modal-backdrop"
      onClick={onClose}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-2 sm:p-4 overflow-y-auto"
    >
      <div
        id="spec-modal-content"
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-3xl max-h-[92vh] sm:max-h-[90vh] overflow-y-auto rounded-2xl bg-slate-900 border border-slate-800 p-4 sm:p-6 shadow-2xl text-slate-200"
      >
        <div className="flex items-center justify-between pb-3 sm:pb-4 border-b border-slate-800 sticky top-0 bg-slate-900 z-10">
          <div className="flex items-center gap-2 sm:gap-2.5 min-w-0">
            <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-indigo-400 shrink-0" />
            <h3 className="text-sm sm:text-lg font-bold text-white truncate">Architecture & Specification</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 sm:p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer active:scale-95 shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="mt-5 space-y-6 text-sm text-slate-300 leading-relaxed">
          {/* Section 1 */}
          <div>
            <h4 className="flex items-center gap-2 text-white font-semibold text-base mb-2">
              <Layers className="w-4 h-4 text-indigo-400" />
              1. Four-Layer Cascade Sequence
            </h4>
            <div className="rounded-xl bg-slate-950/70 border border-slate-800 p-3.5 font-mono text-xs text-slate-300 space-y-1">
              <div><strong>Encryption:</strong> Plaintext → [1] Threefish-1024 → [2] Serpent-256 → [3] ChaCha20-Poly1305 → [4] AES-256-GCM → Container</div>
              <div><strong>Decryption:</strong> Container → [4] AES-256-GCM → [3] ChaCha20-Poly1305 → [2] Serpent-256 → [1] Threefish-1024 → Plaintext</div>
            </div>
            <p className="mt-2 text-xs text-slate-400">
              Layer 1 operates with a strictly native 1024-bit key (128 bytes). Layers 2–4 operate with independent 256-bit keys (32 bytes), delivering 1792 bits of combined CSPRNG entropy. No single algorithm flaw can compromise the data.
            </p>
          </div>

          {/* Section 2 */}
          <div>
            <h4 className="flex items-center gap-2 text-white font-semibold text-base mb-2">
              <Cpu className="w-4 h-4 text-purple-400" />
              2. Zero-RAM Streaming Architecture
            </h4>
            <p className="text-xs text-slate-400">
              Files are processed in fixed 1 MB chunks. Utilizing <code>Transferable ArrayBuffers</code> with the Web Worker and the W3C <code>FileSystemWritableFileStream</code>, each chunk is written directly to disk and unallocated immediately. The application maintains an absolute maximum memory footprint of 2–3 MB, regardless of whether encrypting a 5 MB photo or a 50 GB database archive.
            </p>
          </div>

          {/* Section 3 */}
          <div>
            <h4 className="flex items-center gap-2 text-white font-semibold text-base mb-2">
              <EyeOff className="w-4 h-4 text-emerald-400" />
              3. Antiforensic Compact Container
            </h4>
            <p className="text-xs text-slate-400">
              The container format contains zero magic bytes, zero plaintext headers, and zero recognizable file signatures. The 512-byte metadata blob is encrypted and masked with an independent keystream and placed at a non-deterministic offset. The last 32 bytes contain an encrypted tail pointer that only Key 4 can decrypt. To an adversary, the entire container is indistinguishable from true white noise.
            </p>
          </div>

          {/* Section 4 */}
          <div>
            <h4 className="flex items-center gap-2 text-white font-semibold text-base mb-2">
              <Lock className="w-4 h-4 text-amber-400" />
              4. Side-Channel Resistance & Generic Error Handling
            </h4>
            <p className="text-xs text-slate-400">
              To prevent oracle attacks and side-channel leakage, decryption failures produce the uniform error message: <code>&quot;Decryption failed. Check all keys.&quot;</code>. The system never reveals which layer failed, nor whether authentication failed due to an invalid key or data corruption.
            </p>
          </div>

          {/* Section 5 */}
          <div>
            <h4 className="flex items-center gap-2 text-white font-semibold text-base mb-2">
              <FileText className="w-4 h-4 text-sky-400" />
              5. Library Provenance & Security Audits
            </h4>
            <div className="rounded-xl bg-slate-950/70 border border-slate-800 p-3.5 space-y-2 text-xs text-slate-400 font-mono">
              <div><strong className="text-emerald-300">@noble/ciphers & @noble/hashes:</strong> Audited by Cure53 & NCC Group, 0-dependency. Powers ChaCha20-Poly1305 (RFC 8439), HMAC-SHA256, and HKDF-SHA512.</div>
              <div><strong className="text-emerald-300">W3C WebCrypto API:</strong> Hardware-accelerated AES-NI via native Chromium/BoringSSL (Google) & Firefox/NSS (Mozilla) engines.</div>
              <div><strong className="text-emerald-300">@noble/post-quantum:</strong> NIST FIPS 203 (ML-KEM-1024), FIPS 204 (ML-DSA-87), FIPS 205 (SLH-DSA).</div>
              <div><strong className="text-indigo-300">In-House SIMD Core (Threefish & Serpent):</strong> High-performance 32-lane bit-slice SIMD Serpent-256 (NESSIE spec) & 64-bit vector ARX Threefish-1024 (Skein 1.3 spec). Open-source, mathematically verified against official reference vectors, and encapsulated inside the audited outer envelope.</div>
            </div>
          </div>
        </div>

        <div className="mt-6 pt-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="w-full sm:w-auto px-5 py-2.5 sm:py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition cursor-pointer active:scale-[0.98]"
          >
            Close Specification
          </button>
        </div>
      </div>
    </div>
  );
};
