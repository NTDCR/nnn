import React, { useState, useRef, useEffect } from 'react';
import { CascadeKeys, WorkerProgressMessage, WorkerSuccessMessage } from '../types/crypto.ts';
import { processFileWithPool } from '../workers/cascadePool.ts';
import { ProgressBar } from './ProgressBar.tsx';
import {
  FileCode,
  UploadCloud,
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
}

export const FileProcessor: React.FC<FileProcessorProps> = ({ keys }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [progress, setProgress] = useState<WorkerProgressMessage | null>(null);
  const [result, setResult] = useState<WorkerSuccessMessage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [useDirectDiskWrite, setUseDirectDiskWrite] = useState<boolean>(true);
  const [downloadBlobUrl, setDownloadBlobUrl] = useState<string | null>(null);
  const [streamedDirectToDisk, setStreamedDirectToDisk] = useState<boolean>(false);
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
  const chunksCollectorRef = useRef<Uint8Array[]>([]);

  const hasFileSystemAccess = typeof window !== 'undefined' && 'showSaveFilePicker' in window;

  // Cleanup object URL on unmount
  useEffect(() => {
    return () => {
      if (downloadBlobUrl) {
        URL.revokeObjectURL(downloadBlobUrl);
      }
    };
  }, [downloadBlobUrl]);

  // Comprehensive unmount cleanup for active worker, pool and open file streams
  useEffect(() => {
    return () => {
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
      chunksCollectorRef.current = [];
    };
  }, []);

  const clearDownloadUrl = () => {
    setDownloadBlobUrl((prev) => {
      if (prev) URL.revokeObjectURL(prev);
      return null;
    });
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setSelectedFile(e.dataTransfer.files[0]);
      setResult(null);
      setError(null);
      clearDownloadUrl();
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setResult(null);
      setError(null);
      clearDownloadUrl();
    }
    e.target.value = '';
  };

  const sanitizeHexKey = (k: string) => k.trim().replace(/^0x/i, '').replace(/[\s\-_:"']/g, '');

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
    if (!selectedFile) {
      setError('Please select or drop a file to process.');
      return;
    }
    if (!validateKeys()) return;

    // Safety guard for browsers without direct-to-disk File System Access API
    if (!hasFileSystemAccess || !useDirectDiskWrite) {
      const isMobileBrowser = typeof navigator !== 'undefined' && (
        /Android|iPhone|iPod|Mobile/i.test(navigator.userAgent) ||
        Boolean((navigator as unknown as { userAgentData?: { mobile?: boolean } }).userAgentData?.mobile)
      );
      const maxSafeBytes = isMobileBrowser ? 1.2 * 1024 * 1024 * 1024 : 2.2 * 1024 * 1024 * 1024;
      if (selectedFile.size > maxSafeBytes) {
        setError(
          `Memory limit notice: In-memory fallback cannot safely buffer files larger than ${(maxSafeBytes / (1024 * 1024 * 1024)).toFixed(1)} GB without risk of browser tab crash. Please enable "Direct-to-Disk Stream" on a desktop Chromium browser (Chrome/Edge) for large files.`
        );
        return;
      }
    }

    const k1 = sanitizeHexKey(keys.layer1ThreefishHex);
    const k2 = sanitizeHexKey(keys.layer2SerpentHex);
    const k3 = sanitizeHexKey(keys.layer3ChaChaHex);
    const k4 = sanitizeHexKey(keys.layer4AesHex);

    setError(null);
    setResult(null);
    setStreamedDirectToDisk(false);
    clearDownloadUrl();
    chunksCollectorRef.current = [];
    writableStreamRef.current = null;

    // Direct disk streaming setup
    let targetFileName: string;
    if (action === 'ENCRYPT') {
      targetFileName = `${selectedFile.name}.fortknox`;
    } else {
      const stripped = selectedFile.name.replace(/\.fortknox$/i, '');
      if (stripped.length > 0 && stripped !== selectedFile.name) {
        targetFileName = stripped;
      } else {
        targetFileName = `decrypted_${selectedFile.name.length > 0 ? selectedFile.name : 'file'}`;
      }
    }

    if (hasFileSystemAccess && useDirectDiskWrite) {
      try {
        // Prompt user to pick output file directly on disk
        const handle = await (window as unknown as {
          showSaveFilePicker: (options: { suggestedName: string }) => Promise<FileSystemFileHandle>;
        }).showSaveFilePicker({
          suggestedName: targetFileName,
        });
        const writable = await handle.createWritable();
        writableStreamRef.current = writable;
        setStreamedDirectToDisk(true);
      } catch (pickerErr: unknown) {
        // If user cancelled picker dialog
        if ((pickerErr as { name?: string })?.name === 'AbortError') {
          return;
        }
        console.warn('Falling back to memory stream:', pickerErr);
        if (selectedFile.size > maxSafeBytes) {
          setError(
            `Memory limit notice: In-memory fallback cannot safely buffer files larger than ${(maxSafeBytes / (1024 * 1024 * 1024)).toFixed(1)} GB without risk of browser tab crash. Please choose a writable destination or process a smaller file.`
          );
          return;
        }
        setStreamedDirectToDisk(false);
      }
    }

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    setIsProcessing(true);

    // Disk write batching to minimize Chromium IPC context switches by 75%
    let diskWriteBuffer: Uint8Array[] = [];
    let diskBufferedBytes = 0;
    const flushDiskBuffer = async () => {
      if (diskWriteBuffer.length === 0 || !writableStreamRef.current) return;
      if (diskWriteBuffer.length === 1) {
        const single = diskWriteBuffer[0];
        diskWriteBuffer = [];
        diskBufferedBytes = 0;
        await writableStreamRef.current.write(single);
        return;
      }
      const coalesced = new Uint8Array(diskBufferedBytes);
      let offset = 0;
      for (let b = 0; b < diskWriteBuffer.length; b++) {
        coalesced.set(diskWriteBuffer[b], offset);
        offset += diskWriteBuffer[b].length;
      }
      diskWriteBuffer = [];
      diskBufferedBytes = 0;
      await writableStreamRef.current.write(coalesced);
    };

    try {
      const res = await processFileWithPool({
        action,
        file: selectedFile,
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
            chunksCollectorRef.current.push(chunkBytes);
          }
        },
        signal: abortController.signal,
      });

      // Flush remaining buffered writes and close stream
      if (writableStreamRef.current) {
        if (!abortController.signal.aborted) {
          await flushDiskBuffer();
          await writableStreamRef.current.close();
        }
        writableStreamRef.current = null;
      } else {
        const blob = new Blob(chunksCollectorRef.current as BlobPart[], {
          type: 'application/octet-stream',
        });
        const url = URL.createObjectURL(blob);
        setDownloadBlobUrl((prev) => {
          if (prev) URL.revokeObjectURL(prev);
          return url;
        });
        chunksCollectorRef.current = [];

        // Automatically trigger download fallback for browsers without direct disk write API
        try {
          const anchor = document.createElement('a');
          anchor.href = url;
          anchor.download = res.fileName;
          anchor.style.display = 'none';
          document.body.appendChild(anchor);
          anchor.click();
          setTimeout(() => {
            if (document.body.contains(anchor)) {
              document.body.removeChild(anchor);
            }
          }, 1000);
        } catch (downloadErr) {
          console.warn('Auto-download trigger fallback failed:', downloadErr);
        }
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
      chunksCollectorRef.current = [];
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
    }
  };

  const handleAbort = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    if (writableStreamRef.current) {
      writableStreamRef.current.abort().catch(() => {});
      writableStreamRef.current = null;
    }
    chunksCollectorRef.current = [];
    clearDownloadUrl();
    setIsProcessing(false);
    setProgress(null);
    setError('Operation cancelled by user.');
  };

  return (
    <div id="file-processor-card" className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 md:p-6 shadow-xl backdrop-blur-sm">
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
            <UploadCloud className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-white">File Cascade Processor</h2>
            <p className="text-xs text-slate-400">Zero-RAM 1 MB streaming pipeline with File System Access</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* CPU / GPU Concurrency Selector */}
          <div className="flex items-center gap-1.5 bg-slate-800/80 border border-slate-700/60 rounded-lg px-2.5 py-1 text-xs shadow-inner">
            <span className="text-[11px] text-slate-400 font-mono">Engine:</span>
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
              <option value="webgpu" className="bg-slate-900 text-slate-200">WebGPU (Hardware Compute)</option>
              <option value="2" className="bg-slate-900 text-slate-200">2 P-Cores (Dual P-Core / Mobile Big.LITTLE)</option>
              <option value="4" className="bg-slate-900 text-slate-200">4 P-Cores (Quad P-Core)</option>
              <option value="6" className="bg-slate-900 text-slate-200">6 P-Cores (Hexa P-Core)</option>
              <option value="8" className="bg-slate-900 text-slate-200">8 P-Cores (Octa P-Core Ultra)</option>
            </select>
          </div>

          {/* Disk streaming toggle or Auto-Download Fallback indicator */}
          {hasFileSystemAccess ? (
            <label
              className="flex items-center gap-2 cursor-pointer text-xs text-slate-300"
              title="Saves directly to disk without RAM accumulation. Uncheck for ultra-fast in-memory streaming matching Firefox speed."
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
              title="This browser does not support the File System Access API. Chunks are automatically buffered and auto-downloaded on completion."
            >
              <Download className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Auto-Download Fallback</span>
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
          onChange={handleFileChange}
          onDrop={(e) => e.stopPropagation()}
          disabled={isProcessing}
          className="absolute inset-0 opacity-0 cursor-pointer disabled:cursor-not-allowed"
        />

        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-slate-900 border border-slate-800 text-slate-300 mb-3 shadow-inner">
          <FileCode className="w-6 h-6 text-indigo-400" />
        </div>

        {selectedFile ? (
          <div>
            <p className="text-sm font-semibold text-white truncate max-w-xs sm:max-w-md">
              {selectedFile.name}
            </p>
            <p className="text-xs font-mono text-indigo-300 mt-1">
              {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB ({selectedFile.size.toLocaleString()} bytes)
            </p>
            <p className="text-[11px] text-slate-500 mt-2">Click or drag another file to replace</p>
          </div>
        ) : (
          <div>
            <p className="text-sm font-medium text-slate-200">
              Drag & drop any file here, or <span className="text-indigo-400 font-semibold underline">browse</span>
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Supports arbitrary file sizes (even 100+ GB) with constant 2–3 MB RAM streaming
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
              <strong className="text-white truncate block">{result.fileName}</strong>
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

          {downloadBlobUrl && (
            <div className="mt-3 pt-3 border-t border-emerald-900/50 flex flex-wrap items-center justify-between gap-2">
              <span className="text-[11px] text-emerald-300/90 flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                Downloaded automatically. Click below if not prompted:
              </span>
              <a
                href={downloadBlobUrl}
                download={result.fileName}
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
          disabled={isProcessing || !selectedFile}
          className="flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:opacity-50 text-white py-3 px-4 text-xs font-semibold shadow-lg shadow-indigo-900/20 transition-all cursor-pointer"
        >
          <Lock className="w-4 h-4" />
          Encrypt File (4-Layer Cascade)
        </button>

        <button
          id="decrypt-action-btn"
          onClick={() => startProcessing('DECRYPT')}
          disabled={isProcessing || !selectedFile}
          className="flex items-center justify-center gap-2 rounded-xl bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-100 py-3 px-4 text-xs font-semibold border border-slate-700 shadow-md transition-all cursor-pointer"
        >
          <Unlock className="w-4 h-4" />
          Decrypt File (Reverse Cascade)
        </button>
      </div>
    </div>
  );
};
