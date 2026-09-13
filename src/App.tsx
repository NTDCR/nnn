import React, { useState } from 'react';
import { KeyManager } from './components/KeyManager.tsx';
import { FileProcessor } from './components/FileProcessor.tsx';
import { VerificationPanel } from './components/VerificationPanel.tsx';
import { PWAInstallButton } from './components/PWAInstallButton.tsx';
import { OfflineIndicator } from './components/OfflineIndicator.tsx';
import { SpecModal } from './components/SpecModal.tsx';
import { generateRandomKey } from './crypto/cascade.ts';
import { CascadeKeys } from './types/crypto.ts';
import {
  Shield,
  Layers,
  Cpu,
  BookOpen,
  Sparkles,
  Terminal,
  ExternalLink,
} from 'lucide-react';

export default function App() {
  // Initialize with 4 fresh CSPRNG keys (Layer 1: 1024-bit/128-byte, Layers 2-4: 256-bit/32-byte)
  const [keys, setKeys] = useState<CascadeKeys>(() => ({
    layer1ThreefishHex: generateRandomKey(128),
    layer2SerpentHex: generateRandomKey(32),
    layer3ChaChaHex: generateRandomKey(32),
    layer4AesHex: generateRandomKey(32),
  }));

  const [activeTab, setActiveTab] = useState<'processor' | 'verification'>('processor');
  const [isSpecModalOpen, setIsSpecModalOpen] = useState(false);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {/* Top Navigation Bar */}
      <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-slate-950/85 backdrop-blur-md">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 shadow-md shadow-indigo-500/20 text-white">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-tight text-white">Fort-Knox</span>
                <span className="rounded-md bg-indigo-950/80 px-2 py-0.5 text-[10px] font-semibold text-indigo-300 border border-indigo-800/50">
                  v1.0 PWA
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                4-Layer Cascade File Encryption • Zero-RAM Streaming
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              id="open-specs-nav-btn"
              onClick={() => setIsSpecModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-xs font-medium text-slate-300 transition cursor-pointer"
            >
              <BookOpen className="w-3.5 h-3.5 text-indigo-400" />
              <span className="hidden sm:inline">Specifications</span>
            </button>

            <PWAInstallButton />
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-6 sm:py-8 flex-1 w-full space-y-6 sm:space-y-8">
        {/* Hero Features Bar */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="flex items-center gap-3 p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
            <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
              <Layers className="w-4 h-4" />
            </div>
            <div className="text-xs">
              <strong className="text-white block font-semibold">1792-bit Cascade</strong>
              <span className="text-slate-400 font-mono text-[11px]">Threefish-1024 → Serpent → ChaCha → AES</span>
            </div>
          </div>

          <div className="flex items-center gap-3 p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
              <Cpu className="w-4 h-4" />
            </div>
            <div className="text-xs">
              <strong className="text-white block font-semibold">Zero-RAM Streaming</strong>
              <span className="text-slate-400 font-mono text-[11px]">1 MB chunks • 2–3 MB memory ceiling</span>
            </div>
          </div>

          <div className="flex items-center gap-3 p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div className="text-xs">
              <strong className="text-white block font-semibold">Antiforensic Container</strong>
              <span className="text-slate-400 font-mono text-[11px]">Zero magic bytes • Hidden metadata blob</span>
            </div>
          </div>
        </div>

        {/* Tab Selection */}
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
          <div className="flex items-center gap-2">
            <button
              id="tab-processor-btn"
              onClick={() => setActiveTab('processor')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'processor'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              File Encryption & Decryption
            </button>

            <button
              id="tab-verification-btn"
              onClick={() => setActiveTab('verification')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'verification'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white hover:bg-slate-900'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              NIST / RFC Verification
            </button>
          </div>

          <button
            onClick={() => setIsSpecModalOpen(true)}
            className="text-xs text-indigo-400 hover:text-indigo-300 font-medium inline-flex items-center gap-1 cursor-pointer"
          >
            View Specification Document <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        {/* Tab Content - rendered with CSS visibility to prevent unmounting active file streams */}
        <div className={activeTab === 'processor' ? 'space-y-6' : 'hidden'}>
          {/* Key Manager Component */}
          <KeyManager keys={keys} onChangeKeys={setKeys} />

          {/* File Processor Component */}
          <FileProcessor keys={keys} />
        </div>

        <div className={activeTab === 'verification' ? 'space-y-6' : 'hidden'}>
          <VerificationPanel />
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-800/80 bg-slate-950 py-6 text-xs text-slate-500">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-indigo-500" />
            <span>Fort-Knox Cryptographic Educational & Security Research Platform</span>
          </div>

          <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono">
            <span>FIPS 197</span>
            <span>•</span>
            <span>RFC 8439</span>
            <span>•</span>
            <span>Skein v1.3</span>
            <span>•</span>
            <span>MIT License</span>
          </div>
        </div>
      </footer>

      {/* Specification Modal */}
      <SpecModal isOpen={isSpecModalOpen} onClose={() => setIsSpecModalOpen(false)} />

      {/* Offline Status Floating Banner */}
      <OfflineIndicator />
    </div>
  );
}
