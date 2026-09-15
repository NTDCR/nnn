import { useState, useEffect } from 'react';
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
  Eye,
  EyeOff,
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
  const [isProcessing, setIsProcessing] = useState(false);
  const [isCloaked, setIsCloaked] = useState(false);

  // Anti-Forensics: Emergency Stealth Cloak Mode (Esc / Alt+C)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (isSpecModalOpen && e.key === 'Escape') return;
      if (e.key === 'Escape' || (e.altKey && (e.key === 'c' || e.key === 'C'))) {
        setIsCloaked((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSpecModalOpen]);

  useEffect(() => {
    if (isCloaked) {
      document.title = 'Storage Diagnostic & Stream Verifier';
    } else {
      document.title = 'Fort-Knox: Cascaded Post-Quantum Cipher & Anti-Forensics';
    }
  }, [isCloaked]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {/* Top Navigation Bar */}
      <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md pt-[env(safe-area-inset-top)]">
        <div className="mx-auto max-w-7xl px-3 sm:px-6 lg:px-8 h-14 sm:h-16 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className={`flex h-9 w-9 sm:h-10 sm:w-10 shrink-0 items-center justify-center rounded-xl shadow-md text-white ${
              isCloaked
                ? 'bg-gradient-to-br from-emerald-600 to-teal-700 shadow-emerald-500/20'
                : 'bg-gradient-to-br from-indigo-500 to-purple-600 shadow-indigo-500/20'
            }`}>
              <Shield className="w-4 h-4 sm:w-5 sm:h-5" />
            </div>
            <div className="truncate">
              <div className="flex items-center gap-1.5">
                <span className="text-sm sm:text-base font-bold tracking-tight text-white">
                  {isCloaked ? 'StorageDiag' : 'Fort-Knox'}
                </span>
                <span className={`rounded-md px-1.5 py-0.5 text-[9px] sm:text-[10px] font-semibold border ${
                  isCloaked
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800/50'
                    : 'bg-indigo-950/80 text-indigo-300 border-indigo-800/50'
                }`}>
                  {isCloaked ? 'v2.4 Diag' : 'v1.0 PWA'}
                </span>
              </div>
              <p className="text-[10px] sm:text-[11px] text-slate-400 hidden sm:block truncate">
                {isCloaked
                  ? 'Storage Diagnostics & Stream Integrity Verifier'
                  : '4-Layer Cascade File Encryption • Zero-RAM Streaming'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              id="toggle-stealth-cloak-btn"
              onClick={() => setIsCloaked((c) => !c)}
              title={isCloaked ? 'Disable Cloak Mode (Esc)' : 'Emergency Stealth Cloak Mode (Esc / Alt+C)'}
              className={`inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg border text-xs font-medium transition cursor-pointer ${
                isCloaked
                  ? 'border-emerald-600/70 bg-emerald-950/60 text-emerald-300'
                  : 'border-slate-800 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {isCloaked ? <EyeOff className="w-3.5 h-3.5 text-emerald-400" /> : <Eye className="w-3.5 h-3.5" />}
              <span className="hidden sm:inline">{isCloaked ? 'Cloaked' : 'Cloak (Esc)'}</span>
            </button>
            <button
              id="open-specs-nav-btn"
              onClick={() => setIsSpecModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-xs font-medium text-slate-300 transition cursor-pointer"
            >
              <BookOpen className="w-3.5 h-3.5 text-indigo-400" />
              <span className="hidden sm:inline">Specifications</span>
              <span className="sm:hidden text-[11px]">Specs</span>
            </button>

            <PWAInstallButton />
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="mx-auto max-w-7xl px-3 sm:px-6 lg:px-8 py-4 sm:py-8 flex-1 w-full space-y-4 sm:space-y-6">
        {/* Hero Features Bar - Mobile-First compact responsive pills */}
        <div className="grid grid-cols-3 gap-1.5 sm:gap-3">
          <div className="flex flex-col sm:flex-row items-center sm:items-center gap-1 sm:gap-3 p-2 sm:p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 text-center sm:text-left">
            <div className="p-1.5 sm:p-2 rounded-lg bg-indigo-500/10 text-indigo-400 shrink-0">
              <Layers className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
            </div>
            <div className="min-w-0">
              <strong className="text-white block font-semibold text-[11px] sm:text-xs truncate">
                {isCloaked ? 'Block Matrix' : '1792-bit Cascade'}
              </strong>
              <span className="text-slate-400 font-mono text-[9px] sm:text-[11px] hidden sm:block truncate">
                {isCloaked ? 'Block-4 Vector Stream Pipeline' : 'Threefish → Serpent → ChaCha → AES'}
              </span>
              <span className="text-slate-400 font-mono text-[9px] sm:hidden">
                {isCloaked ? 'Pipeline' : '4 Layers'}
              </span>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-center sm:items-center gap-1 sm:gap-3 p-2 sm:p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 text-center sm:text-left">
            <div className="p-1.5 sm:p-2 rounded-lg bg-purple-500/10 text-purple-400 shrink-0">
              <Cpu className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
            </div>
            <div className="min-w-0">
              <strong className="text-white block font-semibold text-[11px] sm:text-xs truncate">
                {isCloaked ? 'Stream Buffer' : 'Zero-RAM Stream'}
              </strong>
              <span className="text-slate-400 font-mono text-[9px] sm:text-[11px] hidden sm:block truncate">
                {isCloaked ? '1 MB I/O chunks • Sub-5MB ceiling' : '1 MB chunks • 2–3 MB ceiling'}
              </span>
              <span className="text-slate-400 font-mono text-[9px] sm:hidden">
                {isCloaked ? 'Sub-5MB' : 'No OOM'}
              </span>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-center sm:items-center gap-1 sm:gap-3 p-2 sm:p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 text-center sm:text-left">
            <div className="p-1.5 sm:p-2 rounded-lg bg-emerald-500/10 text-emerald-400 shrink-0">
              <Sparkles className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
            </div>
            <div className="min-w-0">
              <strong className="text-white block font-semibold text-[11px] sm:text-xs truncate">
                {isCloaked ? 'Parity Verify' : 'Antiforensic'}
              </strong>
              <span className="text-slate-400 font-mono text-[9px] sm:text-[11px] hidden sm:block truncate">
                {isCloaked ? 'Stream Parity • Masked Diagnostics' : 'Zero magic • Masked metadata'}
              </span>
              <span className="text-slate-400 font-mono text-[9px] sm:hidden">
                {isCloaked ? 'Parity' : 'Masked'}
              </span>
            </div>
          </div>
        </div>

        {/* Mobile-First Segmented Tab Selection */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 border-b border-slate-800/80 pb-3">
          <div className="grid grid-cols-2 p-1 rounded-xl bg-slate-900 border border-slate-800/90 gap-1 w-full sm:w-auto">
            <button
              id="tab-processor-btn"
              onClick={() => setActiveTab('processor')}
              className={`flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'processor'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Shield className="w-3.5 h-3.5 shrink-0" />
              <span>Encrypt & Decrypt</span>
            </button>

            <button
              id="tab-verification-btn"
              onClick={() => setActiveTab('verification')}
              className={`flex items-center justify-center gap-2 py-2.5 px-3 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'verification'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Terminal className="w-3.5 h-3.5 shrink-0" />
              <span>NIST / RFC Verify</span>
            </button>
          </div>

          <button
            onClick={() => setIsSpecModalOpen(true)}
            className="text-xs text-indigo-400 hover:text-indigo-300 font-medium inline-flex items-center justify-center gap-1 cursor-pointer py-1"
          >
            <span>View Specification Document</span> <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        {/* Tab Content - rendered with CSS visibility to prevent unmounting active file streams */}
        <div className={activeTab === 'processor' ? 'space-y-6' : 'hidden'}>
          {/* Key Manager Component */}
          <KeyManager keys={keys} onChangeKeys={setKeys} disabled={isProcessing} />

          {/* File Processor Component */}
          <FileProcessor keys={keys} onProcessingChange={setIsProcessing} />
        </div>

        <div className={activeTab === 'verification' ? 'space-y-6' : 'hidden'}>
          <VerificationPanel />
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-800/80 bg-slate-950 py-6 text-xs text-slate-500">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className={`w-4 h-4 ${isCloaked ? 'text-emerald-500' : 'text-indigo-500'}`} />
            <span>
              {isCloaked
                ? 'Storage Diagnostic & Stream Verification Platform'
                : 'Fort-Knox Cryptographic Educational & Security Research Platform'}
            </span>
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
