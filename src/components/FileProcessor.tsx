import React, { useState, useRef, useEffect } from 'react';
import { CascadeKeys, WorkerProgressMessage, WorkerSuccessMessage } from '../types/crypto.ts';
import { processFileWithPool } from '../workers/cascadePool.ts';
import { CompositeFileReader } from '../crypto/compositeReader.ts';
import { createStreamDownloadSession, StreamDownloadSession } from '../crypto/streamDownloadClient.ts';
import { ProgressBar } from './ProgressBar.tsx';
import {
  FileCode,
  Lock,
  Unlock,
  CheckCircle2,
  AlertCircle,
  HardDrive,
  Download,
  Info,
  EyeOff,
} from 'lucide-react';

interface FileProcessorProps {
  keys: CascadeKeys;
  onProcessingChange?: (isProcessing: boolean) => void;
}

export const FileProcessor: React.FC<FileProcessorProps> = ({ keys, onProcessingChange }) => {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [progress, setProgress] = useState<WorkerProgressMessage | null>(null);
  const [result, setResult] = useState<WorkerSuccessMessage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [useDirectDiskWrite, setUseDirectDiskWrite] = useState<boolean>(true);
  const [downloadBlobUrl, setDownloadBlobUrl] = useState<string | null>(null);
  const [streamedDirectToDisk, setStreamedDirectToDisk] = useState<boolean>(false);
  const [streamedToDownloads, setStreamedToDownloads] = useState<boolean>(false);
  const [coreMode, setCoreMode] = useState<'auto' | 'webgpu' | 2 | 4 | 6 | 8>(() => {
    if (typeof window !== 'undefined' && window.localStorage) {
      const saved = localStorage.getItem('sys_io_core_mode') || localStorage.getItem('fortknox_core_mode');
      if (saved === 'webgpu') return 'webgpu';
      if (saved === '2') return 2;
      if (saved === '4') return 4;
      if (saved === '6') return 6;
      if (saved === '8') return 8;
    }
    return 'auto';
  });

  const [stealthExtension, setStealthExtension] = useState<string>(() => {
    if (typeof window !== 'undefined' && window.localStorage) {
      const saved = localStorage.getItem('sys_io_format_ext');
      if (saved && ['.bin', '.iso', '.wav', '.mp4'].includes(saved)) {
        return saved;
      }
    }
    return '.bin'; // Default 4-carrier standard extension
  });

  // Anti-Forensics: actively scrub legacy identifiable keys from browser LevelDB storage
  useEffect(() => {
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        const toScrub: string[] = [];
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (k && k.startsWith('fortknox_')) toScrub.push(k);
        }
        toScrub.forEach((k) => localStorage.removeItem(k));
      }
    } catch {
      // Ignore
    }
  }, []);

  const abortControllerRef = useRef<AbortController | null>(null);
  const writableStreamRef = useRef<FileSystemWritableFileStream | null>(null);
  const currentPartChunksRef = useRef<Uint8Array[]>([]);
  const activeBlobUrlsRef = useRef<Set<string>>(new Set());
  const wakeLockRef = useRef<{ release: () => Promise<void> } | null>(null);

  const hasFileSystemAccess = typeof window !== 'undefined' && 'showSaveFilePicker' in window;

  const acquireWakeLock = async () => {
    if (typeof navigator !== 'undefined' && 'wakeLock' in navigator && (navigator as unknown as { wakeLock?: { request: (type: string) => Promise<{ release: () => Promise<void> }> } }).wakeLock) {
      try {
        wakeLockRef.current = await (navigator as unknown as { wakeLock: { request: (type: string) => Promise<{ release: () => Promise<void> }> } }).wakeLock.request('screen');
      } catch (err) {
        console.debug('Screen wake lock could not be acquired:', err);
      }
    }
  };

  const releaseWakeLock = async () => {
    if (wakeLockRef.current) {
      try {
        await wakeLockRef.current.release();
      } catch {
        // Ignore wake lock release error
      }
      wakeLockRef.current = null;
    }
  };

  const safeRevokeBlobUrl = (urlToRevoke: string, delayMs: number = 90000) => {
    if (!urlToRevoke) return;
    activeBlobUrlsRef.current.add(urlToRevoke);
    setTimeout(() => {
      try {
        URL.revokeObjectURL(urlToRevoke);
      } catch {
        // Ignore revocation errors
      }
      activeBlobUrlsRef.current.delete(urlToRevoke);
    }, delayMs);
  };

  // Comprehensive unmount cleanup for active worker, pool, wake lock and open file streams
  useEffect(() => {
    return () => {
      releaseWakeLock();
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
        abortControllerRef.current = null;
      }
      if (writableStreamRef.current) {
        try {
          writableStreamRef.current.abort().catch(() => {});
        } catch {
          // Ignore abort errors on unmount
        }
        writableStreamRef.current = null;
      }
      for (const c of currentPartChunksRef.current) {
        c.fill(0);
      }
      currentPartChunksRef.current = [];
      activeBlobUrlsRef.current.forEach((url) => {
        setTimeout(() => {
          try {
            URL.revokeObjectURL(url);
          } catch {
            // Ignore
          }
        }, 60000);
      });
      activeBlobUrlsRef.current.clear();
    };
  }, []);

  // Safeguard against accidental tab close or reload during multi-gigabyte encryption/decryption
  useEffect(() => {
    if (!isProcessing) return;
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
      return '';
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [isProcessing]);

  useEffect(() => {
    onProcessingChange?.(isProcessing);
  }, [isProcessing, onProcessingChange]);

  const clearDownloadUrl = () => {
    setDownloadBlobUrl((prev) => {
      if (prev) safeRevokeBlobUrl(prev, 60000);
      return null;
    });
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (isProcessing) return;
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (isProcessing) return;
    const item = e.dataTransfer.items?.[0];
    const entry = (item as unknown as { webkitGetAsEntry?: () => { isDirectory?: boolean } | null })?.webkitGetAsEntry?.();
    if (entry && entry.isDirectory) {
      setError('Folders are not supported. Please select or drop files.');
      return;
    }
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setSelectedFiles(Array.from(e.dataTransfer.files));
      setResult(null);
      setError(null);
      clearDownloadUrl();
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (isProcessing) return;
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFiles(Array.from(e.target.files));
      setResult(null);
      setError(null);
      clearDownloadUrl();
    }
    e.target.value = '';
  };

  const sanitizeHexKey = (k?: string) => (k ?? '').trim().replace(/^0x/i, '').replace(/[\s\-_:"']/g, '');

  const validateKeys = (): boolean => {
    const hexPattern256 = /^[0-9a-fA-F]{64}$/;
    const hexPattern1024 = /^[0-9a-fA-F]{256}$/;
    const k1 = sanitizeHexKey(keys.layer1ThreefishHex);
    const k2 = sanitizeHexKey(keys.layer2SerpentHex);
    const k3 = sanitizeHexKey(keys.layer3ChaChaHex);
    const k4 = sanitizeHexKey(keys.layer4AesHex);

    if (!hexPattern1024.test(k1)) {
      setError('Layer 1 (Threefish-1024) key must be strictly 256 hexadecimal characters (1024 bits). Legacy 256-bit keys are not supported.');
      return false;
    }

    if (!hexPattern256.test(k2) || !hexPattern256.test(k3) || !hexPattern256.test(k4)) {
      setError('Layers 2, 3, and 4 keys must be exactly 64 hexadecimal characters (256 bits). Please generate or input valid keys.');
      return false;
    }
    return true;
  };

  const startProcessing = async (action: 'ENCRYPT' | 'DECRYPT') => {
    if (selectedFiles.length === 0) {
      setError('Please select or drop file(s) to process.');
      return;
    }
    if (!validateKeys()) return;

    const k1 = sanitizeHexKey(keys.layer1ThreefishHex);
    const k2 = sanitizeHexKey(keys.layer2SerpentHex);
    const k3 = sanitizeHexKey(keys.layer3ChaChaHex);
    const k4 = sanitizeHexKey(keys.layer4AesHex);

    const isMultiPart = selectedFiles.length > 1;
    let inputSource: File | CompositeFileReader;

    if (isMultiPart) {
      if (action === 'ENCRYPT') {
        setError('Multi-file selection is for decrypting multi-part containers (.part001, .part002...). Please select a single file to encrypt.');
        return;
      }
      const val = CompositeFileReader.validatePartSequence(selectedFiles);
      if (!val.valid) {
        setError(val.error || 'Invalid multi-part sequence. Please ensure all parts are selected.');
        return;
      }
      inputSource = new CompositeFileReader(selectedFiles);
    } else {
      inputSource = selectedFiles[0];
    }

    setError(null);
    setResult(null);
    setStreamedDirectToDisk(false);
    setStreamedToDownloads(false);
    clearDownloadUrl();
    writableStreamRef.current = null;

    // Output target naming
    const baseRawName = inputSource.name.replace(/^.*[\\/]/, '').replace(/[/\\?%*:|"<>]/g, '_');
    const safeRawName = baseRawName.replace(/\.part[-_]?\d+$/i, '');
    let targetFileName: string;
    if (action === 'ENCRYPT') {
      targetFileName = stealthExtension ? `${safeRawName}${stealthExtension}` : `${safeRawName}.bin`;
    } else {
      const stripped = safeRawName.replace(/\.(bin|iso|wav|mp4)$/i, '');
      if (stripped.length > 0 && stripped !== safeRawName) {
        targetFileName = stripped;
      } else {
        targetFileName = `decrypted_${safeRawName.length > 0 ? safeRawName : 'file'}`;
      }
    }

    if (hasFileSystemAccess && useDirectDiskWrite) {
      try {
        const handle = await (window as unknown as {
          showSaveFilePicker: (options: { suggestedName: string }) => Promise<FileSystemFileHandle>;
        }).showSaveFilePicker({
          suggestedName: targetFileName,
        });
        const writable = await handle.createWritable();
        writableStreamRef.current = writable;
        setStreamedDirectToDisk(true);
      } catch (pickerErr: unknown) {
        if ((pickerErr as { name?: string })?.name === 'AbortError') {
          return;
        }
        console.warn('Direct disk stream picker cancelled or unsupported, falling back to stream download:', pickerErr);
        setStreamedDirectToDisk(false);
      }
    }

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    let streamSession: StreamDownloadSession | null = null;
    let memoryChunks: Uint8Array[] = [];

    // If not streaming direct to disk via File System Access API, stream via Service Worker download
    if (!writableStreamRef.current) {
      const estimatedTotalSize =
        action === 'ENCRYPT'
          ? Math.ceil(inputSource.size / (1024 * 1024)) * 1048608 + 512 + 32
          : undefined;

      streamSession = await createStreamDownloadSession({
        filename: targetFileName,
        totalSize: estimatedTotalSize,
        signal: abortController.signal,
      });

      if (streamSession) {
        setStreamedToDownloads(true);
      }
    }

    setIsProcessing(true);
    await acquireWakeLock();

    // Disk write batching to minimize Chromium IPC context switches by 75%
    let diskWriteBuffer: Uint8Array[] = [];
    let diskBufferedBytes = 0;
    const flushDiskBuffer = async () => {
      if (diskWriteBuffer.length === 0 || !writableStreamRef.current) return;
      if (diskWriteBuffer.length === 1) {
        const single = diskWriteBuffer[0];
        diskWriteBuffer = [];
        diskBufferedBytes = 0;
        try {
          await writableStreamRef.current.write(single);
        } finally {
          single.fill(0);
        }
        return;
      }
      const coalesced = new Uint8Array(diskBufferedBytes);
      let offset = 0;
      for (let b = 0; b < diskWriteBuffer.length; b++) {
        coalesced.set(diskWriteBuffer[b], offset);
        offset += diskWriteBuffer[b].length;
        diskWriteBuffer[b].fill(0);
      }
      diskWriteBuffer = [];
      diskBufferedBytes = 0;
      try {
        await writableStreamRef.current.write(coalesced);
      } finally {
        coalesced.fill(0);
      }
    };

    const triggerSingleDownload = (url: string, fileName: string) => {
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = fileName;
      anchor.rel = 'noopener';
      anchor.style.position = 'fixed';
      anchor.style.left = '-9999px';
      anchor.style.top = '-9999px';
      anchor.style.opacity = '0';
      anchor.style.pointerEvents = 'none';
      document.body.appendChild(anchor);

      const clickEvent = new MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: window,
      });
      anchor.dispatchEvent(clickEvent);

      setTimeout(() => {
        if (document.body.contains(anchor)) {
          document.body.removeChild(anchor);
        }
        setTimeout(() => {
          try {
            URL.revokeObjectURL(url);
          } catch {
            // Ignore
          }
          activeBlobUrlsRef.current.delete(url);
        }, 60000);
      }, 3000);
    };

    let calculatedPadding = 0;
    if (action === 'ENCRYPT') {
      // 1 KB to 64 KB CSPRNG jitter noise to destroy the mathematical file size modulo signature (Mandatory V2 invariant)
      const randBuf = new Uint16Array(1);
      crypto.getRandomValues(randBuf);
      calculatedPadding = 1024 + (randBuf[0] % 64512);
    }

    try {
      const res = await processFileWithPool({
        action,
        file: inputSource,
        keys: {
          layer1ThreefishHex: k1,
          layer2SerpentHex: k2,
          layer3ChaChaHex: k3,
          layer4AesHex: k4,
        },
        coreConcurrency: coreMode,
        antiForensicPadding: calculatedPadding,
        outputFileName: targetFileName,
        onProgress: (() => {
          let lastProgressTime = 0;
          return (p: Parameters<NonNullable<Parameters<typeof processFileWithPool>[0]['onProgress']>>[0]) => {
            const now = performance.now();
            if (p.currentChunk === p.totalChunks || now - lastProgressTime >= 100) {
              lastProgressTime = now;
              setProgress(p);
            }
          };
        })(),
        onChunkOutput: async (chunkBytes: Uint8Array) => {
          if (writableStreamRef.current) {
            diskWriteBuffer.push(chunkBytes);
            diskBufferedBytes += chunkBytes.length;
            if (diskBufferedBytes >= 4 * 1024 * 1024) {
              await flushDiskBuffer();
            }
          } else if (streamSession) {
            await streamSession.write(chunkBytes);
            chunkBytes.fill(0);
          } else {
            memoryChunks.push(chunkBytes);
          }
        },
        signal: abortController.signal,
      });

      if (writableStreamRef.current) {
        if (!abortController.signal.aborted) {
          await flushDiskBuffer();
          await writableStreamRef.current.close();
        }
        writableStreamRef.current = null;
      } else if (streamSession) {
        await streamSession.close();
        streamSession = null;
      } else if (memoryChunks.length > 0) {
        const blob = new Blob(memoryChunks, { type: 'application/octet-stream' });
        for (const c of memoryChunks) {
          c.fill(0);
        }
        memoryChunks = [];
        const url = URL.createObjectURL(blob);
        activeBlobUrlsRef.current.add(url);
        setDownloadBlobUrl(url);
        triggerSingleDownload(url, targetFileName);
      }

      setResult(res);
      setIsProcessing(false);
      setProgress(null);
    } catch (err: unknown) {
      if (writableStreamRef.current) {
        try {
          await writableStreamRef.current.abort();
        } catch {
          // Ignore stream abort errors
        }
        writableStreamRef.current = null;
      }
      if (streamSession) {
        try {
          await streamSession.abort(err instanceof Error ? err.message : String(err));
        } catch {
          // Ignore
        }
        streamSession = null;
      }
      for (const c of diskWriteBuffer) {
        c.fill(0);
      }
      diskWriteBuffer = [];
      diskBufferedBytes = 0;
      for (const c of memoryChunks) {
        c.fill(0);
      }
      memoryChunks = [];
      setIsProcessing(false);
      setProgress(null);

      const isUserAborted =
        abortController.signal.aborted ||
        (err instanceof Error && (err.message === 'Aborted' || err.name === 'AbortError' || /abort|closed/i.test(err.message)));

      if (isUserAborted) {
        setError('Operation cancelled by user.');
      } else {
        const fallbackMsg = action === 'ENCRYPT' ? 'Encryption failed during cascade execution.' : 'Decryption failed. Check all keys.';
        setError(err instanceof Error && err.message ? err.message : fallbackMsg);
      }
    } finally {
      abortControllerRef.current = null;
      await releaseWakeLock();
    }
  };

  const handleAbort = () => {
    releaseWakeLock();
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    if (writableStreamRef.current) {
      writableStreamRef.current.abort().catch(() => {});
      writableStreamRef.current = null;
    }
    for (const c of currentPartChunksRef.current) {
      c.fill(0);
    }
    currentPartChunksRef.current = [];
    clearDownloadUrl();
    setIsProcessing(false);
    setProgress(null);
    setError('Operation cancelled by user.');
  };

  const totalSelectedBytes = selectedFiles.reduce((acc, f) => acc + f.size, 0);

  return (
    <div id="file-processor-card" className="rounded-2xl bg-slate-900/90 border border-slate-800 p-3.5 sm:p-5 md:p-6 shadow-xl backdrop-blur-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3.5 sm:pb-4 border-b border-slate-800/80">
        <div>
          <h2 className="text-sm sm:text-base font-semibold text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-indigo-400" />
            <span>Cascade File Processor</span>
          </h2>
          <p className="text-[11px] sm:text-xs text-slate-400 mt-0.5">
            4-Layer Cascaded Streaming with Uncapped File Sizes
          </p>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center gap-2 w-full sm:w-auto">
          {/* Multi-core CPU Concurrency Selector */}
          <div
            className="flex items-center justify-between sm:justify-start gap-1.5 text-xs text-indigo-300 font-mono bg-indigo-950/40 px-2.5 py-1.5 sm:py-1 rounded-lg border border-indigo-800/50"
            title="Multi-core CPU Thread Dispatcher"
          >
            <span className="text-slate-400 text-[10px] sm:text-[10px]">P-Cores:</span>
            <select
              value={coreMode}
              onChange={(e) => {
                const val = e.target.value;
                const nextMode = val === 'auto' ? 'auto' : val === 'webgpu' ? 'webgpu' : (Number(val) as 2 | 4 | 6 | 8);
                setCoreMode(nextMode);
                try {
                  if (typeof window !== 'undefined' && window.localStorage) {
                    localStorage.setItem('sys_io_core_mode', String(nextMode));
                  }
                } catch {
                  // Ignore quota or security restrictions in private browsing
                }
              }}
              disabled={isProcessing}
              className="bg-transparent text-indigo-300 font-mono text-[11px] outline-none cursor-pointer"
            >
              <option value="auto" className="bg-slate-900 text-slate-200">Auto (Strict P-Cores)</option>
              <option value="webgpu" className="bg-slate-900 text-slate-200">WebGPU (Multi-Core)</option>
              <option value="2" className="bg-slate-900 text-slate-200">2 Cores (Mobile)</option>
              <option value="4" className="bg-slate-900 text-slate-200">4 Cores (Quad)</option>
              <option value="6" className="bg-slate-900 text-slate-200">6 Cores (Hexa)</option>
              <option value="8" className="bg-slate-900 text-slate-200">8 Cores (Octa)</option>
            </select>
          </div>

          {/* Disk streaming toggle or Safe Streamed Download indicator */}
          {hasFileSystemAccess ? (
            <label
              className="flex items-center gap-2 cursor-pointer text-xs text-slate-300 px-1 py-1"
              title="Checked: Saves single file directly on disk via File System Access API. Unchecked: Streams single file directly into your Downloads folder via Service Worker (zero RAM overflow)."
            >
              <input
                type="checkbox"
                checked={useDirectDiskWrite}
                onChange={(e) => setUseDirectDiskWrite(e.target.checked)}
                disabled={isProcessing}
                className="rounded border-slate-700 bg-slate-800 text-indigo-600 focus:ring-indigo-500"
              />
              <span className="flex items-center gap-1 font-mono text-[11px] text-indigo-300">
                <HardDrive className="w-3.5 h-3.5 text-indigo-400" />
                Direct-to-Disk Stream
              </span>
            </label>
          ) : (
            <div
              className="flex items-center gap-1.5 text-xs text-emerald-300/90 font-mono bg-emerald-950/40 px-2.5 py-1 rounded-lg border border-emerald-800/50"
              title="Streams single file safely to your Downloads folder via Service Worker (uncapped file size, zero RAM accumulation)."
            >
              <Download className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Safe Streamed Download</span>
            </div>
          )}
        </div>
      </div>

      {/* 2X Anti-Forensic / Plausible Deniability Bar */}
      <div id="antiforensic-bar" className="mt-3.5 flex flex-wrap items-center justify-between gap-2.5 p-2.5 sm:p-3 rounded-xl bg-slate-950/70 border border-purple-900/60 shadow-inner">
        <div className="flex items-center gap-2 text-xs text-slate-300 select-none">
          <span className="flex items-center gap-1.5 font-mono text-[11px] sm:text-xs text-purple-300 font-medium">
            <EyeOff className="w-3.5 h-3.5 text-purple-400 shrink-0" />
            <span>2X Anti-Forensics: Permanent Active</span>
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950/80 border border-purple-700/60 text-purple-200 font-mono">
            V2 Blind KDF • Jitter Noise
          </span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1.5 bg-purple-950/40 border border-purple-800/50 rounded-lg px-2.5 py-1">
            <span className="text-[10px] sm:text-[11px] text-purple-300 font-mono">Format:</span>
            <select
              id="stealth-extension-select"
              value={stealthExtension}
              onChange={(e) => {
                const ext = e.target.value;
                setStealthExtension(ext);
                try {
                  if (typeof window !== 'undefined' && window.localStorage) {
                    localStorage.setItem('sys_io_format_ext', ext);
                  }
                } catch {
                  // Ignore
                }
              }}
              disabled={isProcessing}
              className="bg-transparent text-purple-200 font-mono text-[11px] outline-none cursor-pointer"
            >
              <option value=".bin" className="bg-slate-900 text-slate-200">.bin (High-Entropy Binary Container)</option>
              <option value=".iso" className="bg-slate-900 text-slate-200">.iso (ISO-9660 Disc Polyglot &gt;1GB)</option>
              <option value=".wav" className="bg-slate-900 text-slate-200">.wav (Playable Audio Polyglot)</option>
              <option value=".mp4" className="bg-slate-900 text-slate-200">.mp4 (MP4 Video Polyglot - Cloud &amp; Mobile)</option>
            </select>
          </div>
          <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950/70 border border-purple-800/60 text-purple-300 font-mono hidden lg:inline-flex items-center gap-1">
            {stealthExtension === '.mp4'
              ? 'MP4 Video Polyglot Active • Displays in Media Players'
              : stealthExtension === '.wav'
              ? 'Audio Polyglot Active • Plays in Media Players'
              : stealthExtension === '.iso'
              ? 'ISO-9660 Virtual Disc Polyglot • Mounts in Windows Explorer'
              : 'Blind Pointer Offset • Modulo Annihilated • 0 Magic Bytes'}
          </span>
        </div>
      </div>

      {/* Drag & Drop Target - Mobile-optimized tap target */}
      <div
        id="file-drop-zone"
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`mt-4 sm:mt-5 relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-5 sm:p-8 text-center transition-all ${
          isDragging
            ? 'border-indigo-500 bg-indigo-950/20'
            : 'border-slate-800 bg-slate-950/50 hover:border-slate-700'
        }`}
      >
        <input
          id="file-input-element"
          type="file"
          multiple
          onChange={handleFileChange}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          disabled={isProcessing}
          className="absolute inset-0 opacity-0 cursor-pointer disabled:cursor-not-allowed"
        />

        <div className="flex h-11 w-11 sm:h-12 sm:w-12 items-center justify-center rounded-full bg-slate-900 border border-slate-800 text-slate-300 mb-2.5 sm:mb-3 shadow-inner">
          <FileCode className="w-5 h-5 sm:w-6 sm:h-6 text-indigo-400" />
        </div>

        {selectedFiles.length > 0 ? (
          <div>
            {selectedFiles.length === 1 ? (
              <>
                <p className="text-xs sm:text-sm font-semibold text-white truncate max-w-[260px] sm:max-w-md">
                  {selectedFiles[0].name}
                </p>
                <p className="text-[11px] sm:text-xs font-mono text-indigo-300 mt-1">
                  {(selectedFiles[0].size / (1024 * 1024)).toFixed(2)} MB ({selectedFiles[0].size.toLocaleString()} bytes)
                </p>
              </>
            ) : (
              <>
                <p className="text-xs sm:text-sm font-semibold text-white truncate max-w-[260px] sm:max-w-md">
                  {CompositeFileReader.sortParts([...selectedFiles])[0].name.replace(/\.part[-_]?\d+$/i, '')}
                </p>
                <p className="text-[11px] sm:text-xs font-mono text-indigo-300 mt-1">
                  Multi-part Container ({selectedFiles.length} parts, {(totalSelectedBytes / (1024 * 1024)).toFixed(2)} MB total)
                </p>
              </>
            )}
            <p className="text-[10px] sm:text-[11px] text-slate-500 mt-1.5 sm:mt-2">Tap or drag file(s) to change</p>
          </div>
        ) : (
          <div>
            <p className="text-xs sm:text-sm font-medium text-slate-200">
              <span className="text-indigo-400 font-semibold underline">Tap to browse file(s)</span> or drag & drop
            </p>
            <p className="text-[11px] sm:text-xs text-slate-500 mt-1">
              Supports arbitrary file sizes (uncapped). Single or multi-part .part files.
            </p>
          </div>
        )}
      </div>

      {/* Error Message Box */}
      {error && (
        <div id="crypto-error-banner" className="mt-4 flex items-center gap-2.5 p-3 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-200 text-xs font-mono">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Live Progress Bar */}
      {isProcessing && progress && (
        <div className="mt-5">
          <ProgressBar progress={progress} onCancel={handleAbort} />
        </div>
      )}

      {/* Success Result Card */}
      {result && (
        <div id="crypto-success-card" className="mt-5 rounded-xl bg-emerald-950/40 border border-emerald-800/60 p-4 text-emerald-100">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <span className="text-sm font-semibold text-white">
                {result.mode === 'ENCRYPT' ? 'Cascade Encryption Successful' : 'Cascade Decryption Successful'}
              </span>
            </div>
            <span className="text-xs font-mono text-emerald-300 bg-emerald-900/60 px-2.5 py-0.5 rounded-full border border-emerald-700/50">
              {result.averageSpeedMBs} MB/s
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-mono text-slate-300 my-3 pt-2 border-t border-emerald-900/50">
            <div>
              <span className="text-slate-400 block text-[10px]">Output File:</span>
              <strong className="text-white truncate block">
                {result.fileName}
              </strong>
            </div>
            <div>
              <span className="text-slate-400 block text-[10px]">Final Size:</span>
              <span>{(result.finalSize / (1024 * 1024)).toFixed(2)} MB</span>
            </div>
            <div>
              <span className="text-slate-400 block text-[10px]">Elapsed Time:</span>
              <span>{(result.totalTimeMs / 1000).toFixed(2)}s</span>
            </div>
          </div>

          {streamedToDownloads && (
            <div className="mt-2 pt-2 border-t border-emerald-900/50 text-[11px] font-mono text-emerald-200/90">
              💡 <strong>Streamed safely to your Downloads folder as 1 complete file</strong> (zero RAM overflow).
            </div>
          )}

          {result.mode === 'DECRYPT' && result.lastModified && (
            <div className="mt-2 pt-2 border-t border-emerald-900/50 flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[11px] font-mono text-emerald-200/90">
              <span>
                🕒 <strong>Original Timestamp:</strong> {new Date(result.lastModified).toLocaleString()}
              </span>
              <button
                type="button"
                onClick={() => {
                  const psCmd = `(Get-Item "${result.fileName}").LastWriteTime = "${new Date(result.lastModified!).toISOString()}"`;
                  if (typeof navigator !== 'undefined' && navigator.clipboard) {
                    navigator.clipboard.writeText(psCmd);
                  }
                }}
                title="Copy PowerShell command to apply original timestamp to local file"
                className="text-emerald-400 hover:text-emerald-300 underline cursor-pointer text-[10px] self-start sm:self-auto"
              >
                Copy Anti-Timestomp Command
              </button>
            </div>
          )}

          {downloadBlobUrl && (
            <div className="mt-3 pt-3 border-t border-emerald-900/50 flex flex-wrap items-center justify-between gap-2">
              <span className="text-[11px] text-emerald-300/90 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                Downloaded automatically. Click below if not prompted:
              </span>
              <a
                href={downloadBlobUrl}
                download={result.fileName}
                rel="noopener"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-md transition"
              >
                <Download className="w-3.5 h-3.5" />
                Download Again
              </a>
            </div>
          )}

          {streamedDirectToDisk && (
            <p className="text-[11px] text-emerald-300/80 mt-2 flex items-center gap-1">
              <Info className="w-3.5 h-3.5 text-emerald-400" />
              File was streamed directly to disk at chosen destination.
            </p>
          )}
        </div>
      )}

      {/* Action Buttons */}
      <div className="mt-4 sm:mt-5 grid grid-cols-1 sm:grid-cols-2 gap-2.5 sm:gap-3">
        <button
          id="encrypt-action-btn"
          onClick={() => startProcessing('ENCRYPT')}
          disabled={isProcessing || selectedFiles.length === 0}
          className="flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:opacity-50 text-white py-3.5 sm:py-3 px-4 text-xs font-semibold shadow-lg shadow-indigo-900/20 transition-all cursor-pointer active:scale-[0.98]"
        >
          <Lock className="w-4 h-4 shrink-0" />
          <span>Encrypt File (4-Layer Cascade)</span>
        </button>

        <button
          id="decrypt-action-btn"
          onClick={() => startProcessing('DECRYPT')}
          disabled={isProcessing || selectedFiles.length === 0}
          className="flex items-center justify-center gap-2 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-100 py-3.5 sm:py-3 px-4 text-xs font-semibold border border-slate-700 shadow-md transition-all cursor-pointer active:scale-[0.98]"
        >
          <Unlock className="w-4 h-4 shrink-0" />
          <span>Decrypt File (Reverse Cascade)</span>
        </button>
      </div>
    </div>
  );
};
