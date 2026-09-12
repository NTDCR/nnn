import React, { useState } from 'react';
import {
  generateRandomKey,
  calculateEntropyScore,
} from '../crypto/cascade.ts';
import { CascadeKeys, LayerMetadata } from '../types/crypto.ts';
import {
  Key,
  RefreshCw,
  Eye,
  EyeOff,
  Copy,
  Check,
  AlertTriangle,
  Layers,
  Sparkles,
  Download,
  Upload,
} from 'lucide-react';

interface KeyManagerProps {
  keys: CascadeKeys;
  onChangeKeys: (newKeys: CascadeKeys) => void;
  disabled?: boolean;
}

const LAYERS_INFO: LayerMetadata[] = [
  {
    order: 1,
    name: 'Layer 1 (Innermost)',
    algorithm: 'Threefish-1024',
    mode: 'CTR Mode',
    auth: 'Inner Cascade Tag',
    keySizeBits: 256,
    description: '1024-bit large-block ARX cipher (Skein spec) providing maximum post-quantum state diffusion.',
    library: 'RustCrypto threefish v0.6.0 (Rust / WASM)',
    auditStatus: 'RustCrypto Audited Spec / WASM-Compiled',
  },
  {
    order: 2,
    name: 'Layer 2',
    algorithm: 'Serpent-256',
    mode: 'CTR Mode',
    auth: 'Cascade Tag',
    keySizeBits: 256,
    description: '32-round bit-slice substitution-permutation network with highest conservative security margin.',
    library: 'RustCrypto serpent v0.4.0 (Rust / WASM)',
    auditStatus: 'RustCrypto Audited NESSIE Finalist / WASM-Compiled',
  },
  {
    order: 3,
    name: 'Layer 3',
    algorithm: 'ChaCha20-Poly1305',
    mode: 'AEAD (RFC 8439)',
    auth: '128-bit Poly1305 MAC',
    keySizeBits: 256,
    description: 'High-speed stream cipher with constant-time Carter-Wegman one-time polynomial authenticator.',
    library: '@noble/ciphers & RustCrypto (chacha20poly1305 v0.10.1)',
    auditStatus: 'Audited by Cure53 & NCC Group',
  },
  {
    order: 4,
    name: 'Layer 4 (Outermost)',
    algorithm: 'AES-256-GCM',
    mode: 'AEAD (NIST SP 800-38D)',
    auth: '128-bit GHASH Tag',
    keySizeBits: 256,
    description: 'Hardware-accelerated AES-NI authenticated envelope protecting outer container boundaries.',
    library: 'W3C WebCrypto API & RustCrypto (aes-gcm v0.10.3)',
    auditStatus: 'Hardware Accelerated / NCC Group Audited',
  },
];

export const KeyManager: React.FC<KeyManagerProps> = ({ keys, onChangeKeys, disabled }) => {
  const [showKey, setShowKey] = useState<[boolean, boolean, boolean, boolean]>([false, false, false, false]);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copyAllStatus, setCopyAllStatus] = useState(false);

  const keyList: { key: keyof CascadeKeys; label: string; index: number }[] = [
    { key: 'layer1ThreefishHex', label: 'Layer 1: Threefish-1024 Key', index: 0 },
    { key: 'layer2SerpentHex', label: 'Layer 2: Serpent-256 Key', index: 1 },
    { key: 'layer3ChaChaHex', label: 'Layer 3: ChaCha20-Poly1305 Key', index: 2 },
    { key: 'layer4AesHex', label: 'Layer 4: AES-256-GCM Key', index: 3 },
  ];

  const handleGenerateKey = (keyName: keyof CascadeKeys) => {
    const newHex = generateRandomKey();
    onChangeKeys({
      ...keys,
      [keyName]: newHex,
    });
  };

  const handleGenerateAll = () => {
    onChangeKeys({
      layer1ThreefishHex: generateRandomKey(),
      layer2SerpentHex: generateRandomKey(),
      layer3ChaChaHex: generateRandomKey(),
      layer4AesHex: generateRandomKey(),
    });
  };

  const handleCopy = async (val: string, index: number) => {
    if (!val) return;
    await navigator.clipboard.writeText(val);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCopyAll = async () => {
    const backupText = JSON.stringify(
      {
        format: 'Fort-Knox-Cascade-v1',
        createdAt: new Date().toISOString(),
        warning: 'Keep this backup strictly offline. Anyone with these keys can decrypt your files.',
        keys: {
          layer1_threefish_256bit: keys.layer1ThreefishHex,
          layer2_serpent_256bit: keys.layer2SerpentHex,
          layer3_chacha20_256bit: keys.layer3ChaChaHex,
          layer4_aes_256bit: keys.layer4AesHex,
        },
      },
      null,
      2
    );
    await navigator.clipboard.writeText(backupText);
    setCopyAllStatus(true);
    setTimeout(() => setCopyAllStatus(false), 2500);
  };

  const handleExportJson = () => {
    const data = {
      format: 'Fort-Knox-Cascade-v1',
      exportedAt: new Date().toISOString(),
      keys,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `fortknox_keys_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImportJson = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const parsed = JSON.parse(ev.target?.result as string);
        if (parsed.keys) {
          const sanitize = (val: unknown) =>
            typeof val === 'string'
              ? val.trim().replace(/^0x/i, '').replace(/[\s\-_:]/g, '')
              : '';
          onChangeKeys({
            layer1ThreefishHex: sanitize(parsed.keys.layer1ThreefishHex || parsed.keys.layer1_threefish_256bit),
            layer2SerpentHex: sanitize(parsed.keys.layer2SerpentHex || parsed.keys.layer2_serpent_256bit),
            layer3ChaChaHex: sanitize(parsed.keys.layer3ChaChaHex || parsed.keys.layer3_chacha20_256bit),
            layer4AesHex: sanitize(parsed.keys.layer4AesHex || parsed.keys.layer4_aes_256bit),
          });
        }
      } catch {
        alert('Invalid keys JSON file format');
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const toggleShow = (idx: number) => {
    setShowKey((prev) => {
      const next = [...prev] as [boolean, boolean, boolean, boolean];
      next[idx] = !next[idx];
      return next;
    });
  };

  return (
    <div id="key-manager-section" className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 md:p-6 shadow-xl backdrop-blur-sm">
      {/* Header with Quick Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-5 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <Key className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              4-Layer Cascade Key Management
              <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-950/80 border border-indigo-800/60 text-indigo-300 font-mono">
                1024-bit Combined Entropy
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Each layer requires an independent 256-bit key (CSPRNG generated). No KDF overhead by default.
            </p>
          </div>
        </div>

        {/* Global Key Actions */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            id="generate-all-keys-btn"
            onClick={handleGenerateAll}
            disabled={disabled}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-medium shadow-sm transition-all cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Generate All 4 Keys
          </button>
          <button
            id="copy-all-keys-btn"
            onClick={handleCopyAll}
            disabled={disabled}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-medium border border-slate-700 transition"
          >
            {copyAllStatus ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copyAllStatus ? 'Copied All!' : 'Copy All'}
          </button>
          <button
            id="export-keys-btn"
            onClick={handleExportJson}
            title="Export keys to JSON backup"
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            <Download className="w-3.5 h-3.5" />
          </button>
          <label
            id="import-keys-label"
            title="Import keys from JSON"
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer"
          >
            <Upload className="w-3.5 h-3.5" />
            <input type="file" accept=".json" onChange={handleImportJson} className="hidden" />
          </label>
        </div>
      </div>

      {/* Warning Notice */}
      <div id="no-recovery-warning" className="mt-4 flex items-start gap-3 p-3 rounded-xl bg-amber-950/40 border border-amber-800/50 text-amber-200/90 text-xs">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <strong className="font-semibold text-amber-300">Mandatory Security Warning:</strong> Store your keys safely. There is <em>NO recovery</em>.
          Without all 4 independent 256-bit keys, data recovery is mathematically impossible for anyone.
        </div>
      </div>

      {/* 4 Key Inputs */}
      <div className="mt-5 space-y-4">
        {keyList.map((item, idx) => {
          const val = keys[item.key];
          const isVisible = showKey[idx];
          const layerInfo = LAYERS_INFO[idx];
          const entropy = calculateEntropyScore(val);

          return (
            <div
              key={item.key}
              id={`key-card-layer-${idx + 1}`}
              className="rounded-xl bg-slate-950/60 border border-slate-800/80 p-3.5 transition hover:border-slate-700"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="flex h-5 w-5 items-center justify-center rounded-full bg-slate-800 text-[11px] font-mono font-bold text-slate-300">
                    {idx + 1}
                  </span>
                  <span className="text-xs font-semibold text-slate-200">
                    {layerInfo.name}: <span className="text-indigo-300 font-mono">{layerInfo.algorithm}</span>
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800/90 text-slate-400 font-mono">
                    {layerInfo.mode}
                  </span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-950/70 border border-indigo-800/60 text-indigo-300 font-mono">
                    {layerInfo.library}
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded font-mono border ${
                    layerInfo.auditStatus.includes('Cure53') || layerInfo.auditStatus.includes('Hardware')
                      ? 'bg-emerald-950/70 border-emerald-800/60 text-emerald-300'
                      : 'bg-amber-950/70 border-amber-800/60 text-amber-300'
                  }`}>
                    {layerInfo.auditStatus}
                  </span>
                </div>

                <div className="flex items-center gap-2 text-[11px]">
                  <span className="text-slate-500 font-mono text-[10px]">Entropy:</span>
                  <span className={`font-mono font-medium ${entropy.color}`}>
                    {entropy.label}
                  </span>
                </div>
              </div>

              {/* Input row */}
              <div className="relative flex items-center">
                <input
                  id={`key-input-layer-${idx + 1}`}
                  type={isVisible ? 'text' : 'password'}
                  value={val}
                  onChange={(e) =>
                    onChangeKeys({
                      ...keys,
                      [item.key]: e.target.value.trim().replace(/^0x/i, '').replace(/[\s\-_:]/g, ''),
                    })
                  }
                  placeholder="Paste or generate 64-character hex key (256 bits)..."
                  disabled={disabled}
                  className="w-full rounded-lg bg-slate-900 border border-slate-700/80 px-3 py-2 pr-28 text-xs font-mono text-slate-100 placeholder-slate-600 focus:outline-hidden focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 disabled:opacity-50"
                  spellCheck={false}
                />

                <div className="absolute right-1.5 flex items-center gap-1">
                  <button
                    type="button"
                    id={`generate-btn-layer-${idx + 1}`}
                    onClick={() => handleGenerateKey(item.key)}
                    disabled={disabled}
                    title="Generate 256-bit CSPRNG key"
                    className="p-1.5 text-slate-400 hover:text-indigo-300 hover:bg-slate-800 rounded transition"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    id={`toggle-vis-layer-${idx + 1}`}
                    onClick={() => toggleShow(idx)}
                    title={isVisible ? 'Hide key' : 'Show key'}
                    className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition"
                  >
                    {isVisible ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                  <button
                    type="button"
                    id={`copy-btn-layer-${idx + 1}`}
                    onClick={() => handleCopy(val, idx)}
                    title="Copy key to clipboard"
                    className="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded transition"
                  >
                    {copiedIndex === idx ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>

              <div className="mt-1.5 flex items-center justify-between text-[11px] text-slate-500 px-1">
                <span>{layerInfo.description}</span>
                <span className="font-mono">{val.length}/64 hex</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Sequence diagram banner */}
      <div id="cascade-sequence-diagram" className="mt-5 p-3 rounded-xl bg-slate-950/40 border border-slate-800/60 text-xs">
        <div className="flex items-center gap-1.5 text-slate-400 font-medium mb-1.5">
          <Layers className="w-3.5 h-3.5 text-indigo-400" />
          <span>Cascade Pipeline Order:</span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">File</span>
          <span className="text-slate-600">→</span>
          <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/50">1. Threefish-1024</span>
          <span className="text-slate-600">→</span>
          <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/50">2. Serpent-256</span>
          <span className="text-slate-600">→</span>
          <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/50">3. ChaCha20-Poly1305</span>
          <span className="text-slate-600">→</span>
          <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/50">4. AES-256-GCM</span>
          <span className="text-slate-600">→</span>
          <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800/50">Container Blob</span>
        </div>
      </div>
    </div>
  );
};
