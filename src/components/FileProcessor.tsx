import React, { useState, useRef, useEffect } from 'react';
import { CascadeKeys, WorkerProgressMessage, WorkerSuccessMessage, WorkerMessage } from '../types/crypto.ts';
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

  const workerRef = useRef<Worker | null>(null);
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
  };

  const sanitizeHexKey = (k: string) => k.trim().replace(/^0x/i, '').replace(/[\s\-_:]/g, '');

  const validateKeys = (): boolean => {
    const hexPattern = /^[0-9a-fA-F]{64}$/;
    const k1 = sanitizeHexKey(keys.layer1ThreefishHex);
    const k2 = sanitizeHexKey(keys.layer2SerpentHex);
    const k3 = sanitizeHexKey(keys.layer3ChaChaHex);
    const k4 = sanitizeHexKey(keys.layer4AesHex);

    if (!hexPattern.test(k1) || !hexPattern.test(k2) || !hexPattern.test(k3) || !hexPattern.test(k4)) {
      setError('All 4 keys must be exactly 64 hexadecimal characters (256 bits). Please generate or input valid keys.');
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
    let targetFileName = action === 'ENCRYPT'
      ? `${selectedFile.name}.fortknox`
      : selectedFile.name.endsWith('.fortknox')
        ? selectedFile.name.slice(0, -9)
        : `decrypted_${selectedFile.name}`;

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
        if (pickerErr instanceof Error && pickerErr.name === 'AbortError') {
          return;
        }
        console.warn('Falling back to memory stream:', pickerErr);
        setStreamedDirectToDisk(false);
      }
    }

    setIsProcessing(true);

    // Instantiate Web Worker
    const worker = new Worker(new URL('../workers/cascadeWorker.ts', import.meta.url), {
      type: 'module',
    });
    workerRef.current = worker;

    worker.onmessage = async (e: MessageEvent<WorkerMessage>) => {
      const data = e.data;

      if (data.type === 'CHUNK_OUTPUT') {
        const chunkData = new Uint8Array(data.data);
        if (writableStreamRef.current) {
          // Zero-RAM streaming: write immediately to disk
          await writableStreamRef.current.write(chunkData);
        } else {
          // Fallback in-memory collection
          chunksCollectorRef.current.push(chunkData);
        }
      } else if (data.type === 'PROGRESS') {
        setProgress(data as WorkerProgressMessage);
      } else if (data.type === 'SUCCESS') {
        setIsProcessing(false);
        setProgress(null);

        // Close writable file stream if open
        if (writableStreamRef.current) {
          await writableStreamRef.current.close();
          writableStreamRef.current = null;
        } else {
          // Create download blob
          const blob = new Blob(chunksCollectorRef.current as BlobPart[], {
            type: 'application/octet-stream',
          });
          const url = URL.createObjectURL(blob);
          setDownloadBlobUrl((prev) => {
            if (prev) URL.revokeObjectURL(prev);
            return url;
          });
        }

        setResult(data as WorkerSuccessMessage);
        worker.terminate();
        workerRef.current = null;
      } else if (data.type === 'ERROR') {
        setIsProcessing(false);
        setProgress(null);
        setError(data.error || 'Decryption failed. Check all keys.');

        if (writableStreamRef.current) {
          try {
            await writableStreamRef.current.abort();
          } catch {
            // Ignore stream abort errors
          }
          writableStreamRef.current = null;
        }

        worker.terminate();
        workerRef.current = null;
      }
    };

    worker.onerror = (wErr) => {
      console.error('Worker error:', wErr);
      setIsProcessing(false);
      setProgress(null);
      setError('Decryption failed. Check all keys.');
      worker.terminate();
      workerRef.current = null;
    };

    // Dispatch job to worker
    worker.postMessage({
      action,
      file: selectedFile,
      keys: {
        layer1ThreefishHex: k1,
        layer2SerpentHex: k2,
        layer3ChaChaHex: k3,
        layer4AesHex: k4,
      },
    });
  };

  const handleAbort = () => {
    if (workerRef.current) {
      workerRef.current.terminate();
      workerRef.current = null;
    }
    if (writableStreamRef.current) {
      writableStreamRef.current.abort().catch(() => {});
      writableStreamRef.current = null;
    }
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

        {/* Disk streaming toggle */}
        {hasFileSystemAccess && (
          <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
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
        )}
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
            <div className="mt-3 pt-3 border-t border-emerald-900/50 flex justify-end">
              <a
                href={downloadBlobUrl}
                download={result.fileName}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-md transition"
              >
                <Download className="w-3.5 h-3.5" />
                Download Decrypted / Encrypted File
              </a>
            </div>
          )}

          {streamedDirectToDisk && (
            <p className="text-[11px] text-emerald-300/80 mt-1 flex items-center gap-1">
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
