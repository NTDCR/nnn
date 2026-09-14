import React, { useState, useRef, useEffect } from 'react';
import { CascadeKeys, WorkerProgressMessage, WorkerSuccessMessage } from '../types/crypto.ts';
import { processFileWithPool } from '../workers/cascadePool.ts';
import { CompositeFileReader } from '../crypto/compositeReader.ts';
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
  const [downloadedPartsCount, setDownloadedPartsCount] = useState<number>(0);
  const [chunkPartSizeMb, setChunkPartSizeMb] = useState<10 | 25 | 50 | 100>(() => {
    if (typeof window !== 'undefined' && window.localStorage) {
      const saved = localStorage.getItem('fortknox_chunk_part_size');
      if (saved === '10') return 10;
      if (saved === '25') return 25;
      if (saved === '50') return 50;
      if (saved === '100') return 100;
    }
    return 25;
  });
  const [coreMode, setCoreMode] = useState<'auto' | 'webgpu' | 2 | 4 | 6 | 8>(() => {
    if (typeof window !== 'undefined' && window.localStorage) {
      const saved = localStorage.getItem('fortknox_core_mode');
      if (saved === 'webgpu') return 'webgpu';
      if (saved === '2') return 2;
      if (saved === '4') return 4;
      if (saved === '6') return 6;
      if (saved === '8') return 8;
    }
    return 'auto';
  });

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
    setDownloadedPartsCount(0);
    clearDownloadUrl();
    currentPartChunksRef.current = [];
    writableStreamRef.current = null;

    // Output target naming
    const baseRawName = inputSource.name.replace(/^.*[\\/]/, '').replace(/[/\\?%*:|"<>]/g, '_');
    const safeRawName = baseRawName.replace(/\.part[-_]?\d+$/i, '');
    let targetFileName: string;
    if (action === 'ENCRYPT') {
      targetFileName = `${safeRawName}.fortknox`;
    } else {
      const stripped = safeRawName.replace(/\.fortknox$/i, '');
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
        console.warn('Falling back to safe chunked streaming:', pickerErr);
        setStreamedDirectToDisk(false);
      }
    }

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

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

    // Safe chunked part streaming emitter:
    // Strictly bounds memory to chunkPartSizeMb chunks in RAM.
    const PART_CHUNKS_LIMIT = Math.max(1, chunkPartSizeMb);
    let currentPartIndex = 1;
    let partsEmitted = 0;

    const emitPartDownload = (chunks: Uint8Array[], fileName: string) => {
      const blob = new Blob(chunks, { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      activeBlobUrlsRef.current.add(url);
      setDownloadBlobUrl(url);

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
          } else {
            currentPartChunksRef.current.push(chunkBytes);
            if (currentPartChunksRef.current.length >= PART_CHUNKS_LIMIT) {
              const partName = `${targetFileName}.part${String(currentPartIndex).padStart(3, '0')}`;
              emitPartDownload(currentPartChunksRef.current, partName);
              partsEmitted++;
              for (const c of currentPartChunksRef.current) {
                c.fill(0);
              }
              currentPartChunksRef.current = [];
              currentPartIndex++;
            }
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
      } else {
        if (currentPartChunksRef.current.length > 0) {
          const finalName =
            action === 'DECRYPT' && partsEmitted === 0
              ? targetFileName
              : `${targetFileName}.part${String(currentPartIndex).padStart(3, '0')}`;
          emitPartDownload(currentPartChunksRef.current, finalName);
          partsEmitted++;
          for (const c of currentPartChunksRef.current) {
            c.fill(0);
          }
          currentPartChunksRef.current = [];
        }
        setDownloadedPartsCount(partsEmitted);
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
      for (const c of diskWriteBuffer) {
        c.fill(0);
      }
      diskWriteBuffer = [];
      diskBufferedBytes = 0;
      for (const c of currentPartChunksRef.current) {
        c.fill(0);
      }
      currentPartChunksRef.current = [];
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
    <div id="file-processor-card" className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 md:p-6 shadow-xl backdrop-blur-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
        <div>
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-indigo-400" />
            Fort-Knox Cascade File Processor
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            4-Layer Cascaded Streaming Architecture with Uncapped File Sizes
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Multi-core CPU Concurrency Selector */}
          <div
            className="flex items-center gap-1.5 text-xs text-indigo-300 font-mono bg-indigo-950/40 px-2.5 py-1 rounded-lg border border-indigo-800/50"
            title="Multi-core CPU Thread Dispatcher"
          >
            <span className="text-slate-400 text-[10px]">P-Cores:</span>
            <select
              value={coreMode}
              onChange={(e) => {
                const val = e.target.value;
                const nextMode = val === 'auto' ? 'auto' : val === 'webgpu' ? 'webgpu' : (Number(val) as 2 | 4 | 6 | 8);
                setCoreMode(nextMode);
                try {
                  if (typeof window !== 'undefined' && window.localStorage) {
                    localStorage.setItem('fortknox_core_mode', String(nextMode));
                  }
                } catch {
                  // Ignore quota or security restrictions in private browsing
                }
              }}
              disabled={isProcessing}
              className="bg-transparent text-indigo-300 font-mono text-[11px] outline-none cursor-pointer"
            >
              <option value="auto" className="bg-slate-900 text-slate-200">Auto (Strict P-Cores Only)</option>
              <option value="webgpu" className="bg-slate-900 text-slate-200">WebGPU (Multi-Core CPU Fallback)</option>
              <option value="2" className="bg-slate-900 text-slate-200">2 P-Cores (Dual P-Core / Mobile Big.LITTLE)</option>
              <option value="4" className="bg-slate-900 text-slate-200">4 P-Cores (Quad P-Core)</option>
              <option value="6" className="bg-slate-900 text-slate-200">6 P-Cores (Hexa P-Core)</option>
              <option value="8" className="bg-slate-900 text-slate-200">8 P-Cores (Octa P-Core Ultra)</option>
            </select>
          </div>

          {/* Disk streaming toggle or Safe Chunked Streaming indicator */}
          {hasFileSystemAccess ? (
            <label
              className="flex items-center gap-2 cursor-pointer text-xs text-slate-300"
              title="Checked: Saves single file directly on disk via File System Access API. Unchecked: Streams safely in chunk parts with zero RAM overflow (never crashes)."
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
              title="Streams chunks safely to your Downloads folder in bounded parts with zero RAM accumulation (uncapped file size)."
            >
              <Download className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Safe Chunked Streaming</span>
            </div>
          )}

          {/* Part Size selector for chunked streaming */}
          {(!hasFileSystemAccess || !useDirectDiskWrite) && (
            <div
              className="flex items-center gap-1.5 text-xs text-amber-300 font-mono bg-amber-950/40 px-2.5 py-1 rounded-lg border border-amber-800/50"
              title="Chunk part size for streaming downloads (prevents browser RAM exhaustion / Aw Snap crashes)"
            >
              <span className="text-slate-400 text-[10px]">Part Size:</span>
              <select
                value={chunkPartSizeMb}
                onChange={(e) => {
                  const val = Number(e.target.value) as 10 | 25 | 50 | 100;
                  setChunkPartSizeMb(val);
                  try {
                    if (typeof window !== 'undefined' && window.localStorage) {
                      localStorage.setItem('fortknox_chunk_part_size', String(val));
                    }
                  } catch {
                    // Ignore storage quota
                  }
                }}
                disabled={isProcessing}
                className="bg-transparent text-amber-300 font-mono text-[11px] outline-none cursor-pointer"
              >
                <option value="10" className="bg-slate-900 text-slate-200">10 MB (Ultra-Safe)</option>
                <option value="25" className="bg-slate-900 text-slate-200">25 MB (Balanced)</option>
                <option value="50" className="bg-slate-900 text-slate-200">50 MB (Fast)</option>
                <option value="100" className="bg-slate-900 text-slate-200">100 MB (Max)</option>
              </select>
            </div>
          )}
        </div>
      </div>

      {/* Drag & Drop Target */}
      <div
        id="file-drop-zone"
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`mt-5 relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-6 sm:p-8 text-center transition-all ${
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

        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-slate-900 border border-slate-800 text-slate-300 mb-3 shadow-inner">
          <FileCode className="w-6 h-6 text-indigo-400" />
        </div>

        {selectedFiles.length > 0 ? (
          <div>
            {selectedFiles.length === 1 ? (
              <>
                <p className="text-sm font-semibold text-white truncate max-w-xs sm:max-w-md">
                  {selectedFiles[0].name}
                </p>
                <p className="text-xs font-mono text-indigo-300 mt-1">
                  {(selectedFiles[0].size / (1024 * 1024)).toFixed(2)} MB ({selectedFiles[0].size.toLocaleString()} bytes)
                </p>
              </>
            ) : (
              <>
                <p className="text-sm font-semibold text-white truncate max-w-xs sm:max-w-md">
                  {CompositeFileReader.sortParts([...selectedFiles])[0].name.replace(/\.part[-_]?\d+$/i, '')}
                </p>
                <p className="text-xs font-mono text-indigo-300 mt-1">
                  Multi-part Container ({selectedFiles.length} parts detected, {(totalSelectedBytes / (1024 * 1024)).toFixed(2)} MB total)
                </p>
              </>
            )}
            <p className="text-[11px] text-slate-500 mt-2">Click or drag file(s) to replace</p>
          </div>
        ) : (
          <div>
            <p className="text-sm font-medium text-slate-200">
              Drag & drop file(s) here, or <span className="text-indigo-400 font-semibold underline">browse</span>
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Supports arbitrary file sizes (uncapped). Multi-part .part files supported for decryption.
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
                {downloadedPartsCount > 1 ? ` (${downloadedPartsCount} parts)` : ''}
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

          {downloadedPartsCount > 1 ? (
            <div className="mt-2 pt-2 border-t border-emerald-900/50 text-[11px] font-mono text-emerald-200/90">
              💡 <strong>Downloaded in {downloadedPartsCount} safe parts</strong> ({chunkPartSizeMb} MB per part, zero RAM overflow).
              To decrypt, drop all {downloadedPartsCount} parts into Fort-Knox, or combine offline using:
              <code className="block mt-1 p-1 bg-emerald-950/80 rounded text-emerald-300">
                copy /b {result.fileName}.part* {result.fileName} (Windows)
              </code>
            </div>
          ) : downloadedPartsCount === 1 && !streamedDirectToDisk ? (
            <div className="mt-2 pt-2 border-t border-emerald-900/50 text-[11px] font-mono text-emerald-200/90">
              💡 <strong>Streamed safely in 1 chunk part</strong> ({chunkPartSizeMb} MB limit, zero RAM overflow).
            </div>
          ) : null}

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
      <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-3">
        <button
          id="encrypt-action-btn"
          onClick={() => startProcessing('ENCRYPT')}
          disabled={isProcessing || selectedFiles.length === 0}
          className="flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:opacity-50 text-white py-3 px-4 text-xs font-semibold shadow-lg shadow-indigo-900/20 transition-all cursor-pointer"
        >
          <Lock className="w-4 h-4" />
          Encrypt File (4-Layer Cascade)
        </button>

        <button
          id="decrypt-action-btn"
          onClick={() => startProcessing('DECRYPT')}
          disabled={isProcessing || selectedFiles.length === 0}
          className="flex items-center justify-center gap-2 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-100 py-3 px-4 text-xs font-semibold border border-slate-700 shadow-md transition-all cursor-pointer"
        >
          <Unlock className="w-4 h-4" />
          Decrypt File (Reverse Cascade)
        </button>
      </div>
    </div>
  );
};
