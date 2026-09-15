import React, { useState, useRef, useEffect } from 'react';
import {
  Ghost,
  Music,
  Film,
  Disc,
  Binary,
  FileText,
  Table,
  Download,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ShieldCheck,
  Zap,
  Clock,
  Gauge,
  Sparkles,
} from 'lucide-react';
import {
  DecoyProfile,
  getDecoyDefaultFilename,
  streamDecoyPayload,
  DecoyProgress,
} from '../crypto/decoyGenerator.ts';
import { createStreamDownloadSession, StreamDownloadSession } from '../crypto/streamDownloadClient.ts';

interface DecoyGeneratorProps {
  isCloaked?: boolean;
}

interface ProfileOption {
  id: DecoyProfile;
  label: string;
  ext: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  badge: string;
}

const PROFILES: ProfileOption[] = [
  {
    id: 'wav',
    label: 'Audio Polyglot',
    ext: '.wav',
    icon: Music,
    description: 'Compliant RIFF WAVE audio stream with 44.1 kHz acoustic PCM dithering. Plays in VLC & Media Players.',
    badge: 'Playable Audio',
  },
  {
    id: 'mp4',
    label: 'Video Polyglot',
    ext: '.mp4',
    icon: Film,
    description: 'ISO-BMFF MP4 video stream with valid ftyp, moov, and mdat boxes. Recognized by video players.',
    badge: 'Video Stream',
  },
  {
    id: 'iso',
    label: 'Virtual Optical Disc',
    ext: '.iso',
    icon: Disc,
    description: 'ISO-9660 filesystem image with Sector 16 Primary Volume Descriptor. Mounts in Windows Explorer.',
    badge: 'Mountable ISO',
  },
  {
    id: 'bin',
    label: 'Forensic Memory Dump',
    ext: '.bin',
    icon: Binary,
    description: 'Binary data container with configurable entropy matching drive-wipes or forensic core dumps.',
    badge: 'Raw Forensic',
  },
  {
    id: 'log',
    label: 'System Audit Log',
    ext: '.log',
    icon: FileText,
    description: 'Authentic enterprise syslog lines (kernel, systemd, sshd, postgres) with plausible timestamps.',
    badge: 'Syslog Text',
  },
  {
    id: 'csv',
    label: 'Financial Ledger',
    ext: '.csv',
    icon: Table,
    description: 'Corporate settlement ledger and transactional records with realistic account numbers and audit hashes.',
    badge: 'Tabular Data',
  },
];

const PRESETS = [
  { label: '1 MB', bytes: 1 * 1024 * 1024 },
  { label: '10 MB', bytes: 10 * 1024 * 1024 },
  { label: '50 MB', bytes: 50 * 1024 * 1024 },
  { label: '100 MB', bytes: 100 * 1024 * 1024 },
  { label: '500 MB', bytes: 500 * 1024 * 1024 },
  { label: '1 GB', bytes: 1024 * 1024 * 1024 },
];

export const DecoyGenerator: React.FC<DecoyGeneratorProps> = ({ isCloaked }) => {
  const [selectedProfile, setSelectedProfile] = useState<DecoyProfile>('wav');
  const [selectedBytes, setSelectedBytes] = useState<number>(10 * 1024 * 1024);
  const [customValue, setCustomValue] = useState<string>('10');
  const [customUnit, setCustomUnit] = useState<'MB' | 'GB'>('MB');
  const [useCustomSize, setUseCustomSize] = useState<boolean>(false);
  const [entropyShaped, setEntropyShaped] = useState<boolean>(false);
  const [filename, setFilename] = useState<string>(() => getDecoyDefaultFilename('wav'));

  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [progress, setProgress] = useState<DecoyProgress | null>(null);
  const [resultMessage, setResultMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const abortControllerRef = useRef<AbortController | null>(null);
  const activeChunksRef = useRef<Uint8Array[]>([]);
  const isMountedRef = useRef<boolean>(true);

  // Update default filename whenever profile changes
  const handleProfileChange = (profile: DecoyProfile) => {
    setSelectedProfile(profile);
    setFilename(getDecoyDefaultFilename(profile));
    setError(null);
    setResultMessage(null);
  };

  // Keep target bytes synced when custom input changes
  const handleCustomValueChange = (valStr: string, unit: 'MB' | 'GB') => {
    setCustomValue(valStr);
    setCustomUnit(unit);
    const num = parseFloat(valStr);
    if (!isNaN(num) && num > 0) {
      const multiplier = unit === 'GB' ? 1024 * 1024 * 1024 : 1024 * 1024;
      setSelectedBytes(Math.round(num * multiplier));
    }
  };

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      // Memory hygiene on unmount: abort in-flight stream and scrub any buffered chunks
      abortControllerRef.current?.abort();
      activeChunksRef.current.forEach((chunk) => {
        try {
          if (!chunk.buffer.detached) chunk.fill(0);
        } catch {
          // Ignore
        }
      });
      activeChunksRef.current = [];
    };
  }, []);

  const handleStartGeneration = async () => {
    setError(null);
    setResultMessage(null);
    setProgress(null);
    setIsGenerating(true);

    const abortController = new AbortController();
    abortControllerRef.current = abortController;
    activeChunksRef.current = [];

    const safeTargetBytes = Math.max(1024, selectedBytes);
    const safeFilename = filename.trim().replace(/[. ]+$/, '') || getDecoyDefaultFilename(selectedProfile);

    let writableStream: FileSystemWritableFileStream | null = null;
    let streamSession: StreamDownloadSession | null = null;
    let memoryFallbackChunks: Uint8Array[] = [];

    try {
      // 1. Check for File System Access API (Direct Disk Stream)
      if (typeof window !== 'undefined' && 'showSaveFilePicker' in window) {
        try {
          const handle = await (window as unknown as {
            showSaveFilePicker: (options: { suggestedName: string }) => Promise<FileSystemFileHandle>;
          }).showSaveFilePicker({ suggestedName: safeFilename });
          writableStream = await handle.createWritable();
        } catch (pickerErr: unknown) {
          if ((pickerErr as { name?: string })?.name === 'AbortError') {
            setIsGenerating(false);
            return;
          }
          console.debug('Save file picker dismissed or ungranted, using stream download:', pickerErr);
        }
      }

      // 2. If no direct disk handle, attempt Service Worker streamed download
      if (!writableStream) {
        streamSession = await createStreamDownloadSession({
          filename: safeFilename,
          totalSize: safeTargetBytes,
          signal: abortController.signal,
        });
      }

      // 3. Stream payload chunks in zero-RAM pipeline
      const { totalBytesWritten } = await streamDecoyPayload({
        options: {
          profile: selectedProfile,
          targetBytes: safeTargetBytes,
          entropyShaped: selectedProfile === 'bin' ? entropyShaped : false,
          customFilename: safeFilename,
        },
        signal: abortController.signal,
        onProgress: (p) => {
          if (isMountedRef.current) {
            setProgress(p);
          }
        },
        onChunk: async (chunk) => {
          if (abortController.signal.aborted) throw new Error('Aborted');

          if (writableStream) {
            await writableStream.write(chunk);
          } else if (streamSession) {
            await streamSession.write(chunk);
          } else {
            // Memory fallback for environments without SW or FS Access (clone slice to keep memory intact)
            const copy = new Uint8Array(chunk.length);
            copy.set(chunk);
            memoryFallbackChunks.push(copy);
            activeChunksRef.current.push(copy);
          }
        },
      });

      // 4. Finalize streams
      if (writableStream) {
        await writableStream.close();
      } else if (streamSession) {
        await streamSession.close();
      } else if (memoryFallbackChunks.length > 0) {
        const blob = new Blob(memoryFallbackChunks as BlobPart[], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = safeFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => {
          URL.revokeObjectURL(url);
          memoryFallbackChunks.forEach((c) => {
            if (!c.buffer.detached) c.fill(0);
          });
          memoryFallbackChunks = [];
          activeChunksRef.current = [];
        }, 2000);
      }

      if (isMountedRef.current) {
        setResultMessage(
          `Decoy file "${safeFilename}" (${(totalBytesWritten / (1024 * 1024)).toFixed(2)} MB) generated and streamed successfully!`
        );
      }
    } catch (err: unknown) {
      if (abortController.signal.aborted || (err as Error)?.message === 'Aborted') {
        if (isMountedRef.current) {
          setResultMessage('Decoy generation cancelled. All in-flight buffers zeroized.');
        }
      } else {
        console.error('Decoy generation error:', err);
        if (isMountedRef.current) {
          setError((err as Error)?.message || 'Decoy file generation failed.');
        }
      }
    } finally {
      // Memory hygiene
      activeChunksRef.current.forEach((c) => {
        try {
          if (!c.buffer.detached) c.fill(0);
        } catch {
          // Ignore
        }
      });
      activeChunksRef.current = [];
      abortControllerRef.current = null;
      if (isMountedRef.current) {
        setIsGenerating(false);
      }
    }
  };

  const handleAbort = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
  };

  const currentProfile = PROFILES.find((p) => p.id === selectedProfile) || PROFILES[0];
  const percentComplete = progress && progress.totalBytes > 0
    ? Math.min(100, Math.round((progress.processedBytes / progress.totalBytes) * 100))
    : 0;

  return (
    <div
      id="decoy-generator-panel"
      className="rounded-2xl bg-slate-900/90 border border-slate-800 p-3.5 sm:p-5 md:p-6 shadow-xl backdrop-blur-sm space-y-6"
    >
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-2.5 sm:gap-3">
          <div className="flex h-9 w-9 sm:h-10 sm:w-10 shrink-0 items-center justify-center rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
            <Ghost className="w-4 h-4 sm:w-5 sm:h-5" />
          </div>
          <div>
            <h2 className="text-sm sm:text-base font-semibold text-white flex items-center gap-2 flex-wrap">
              <span>{isCloaked ? 'Diagnostic Test Data Generator' : 'Decoy & Honeypot File Generator'}</span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-950 border border-purple-800 text-purple-400 font-mono">
                Plausible Deniability
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              {isCloaked
                ? 'Generate calibrated synthetic binary and media streams for storage diagnostics and benchmark validation.'
                : 'Produce authentic, playable, and mountable cover files to satisfy forensic audits or duress scenarios.'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 text-[11px] font-mono text-purple-300/80 bg-purple-950/40 px-2.5 py-1 rounded-lg border border-purple-900/50 self-start sm:self-auto">
          <ShieldCheck className="w-3.5 h-3.5 text-purple-400 shrink-0" />
          <span>Zero-RAM • Sub-2MB Ceiling</span>
        </div>
      </div>

      {/* Profile Selection Grid */}
      <div className="space-y-2">
        <label className="text-xs font-medium text-slate-300 block">
          Select Decoy Profile:
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
          {PROFILES.map((p) => {
            const Icon = p.icon;
            const isSelected = selectedProfile === p.id;
            return (
              <button
                key={p.id}
                type="button"
                id={`decoy-profile-${p.id}`}
                onClick={() => handleProfileChange(p.id)}
                disabled={isGenerating}
                className={`flex flex-col p-3 rounded-xl border text-left transition cursor-pointer select-none ${
                  isSelected
                    ? 'border-purple-600 bg-purple-950/40 shadow-sm ring-1 ring-purple-500/50'
                    : 'border-slate-800 bg-slate-950/50 hover:border-slate-700 text-slate-300'
                } ${isGenerating ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <div className={`p-1.5 rounded-lg ${isSelected ? 'bg-purple-500/20 text-purple-300' : 'bg-slate-800 text-slate-400'}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <span className="font-semibold text-xs text-white">{p.label}</span>
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-purple-300">
                    {p.ext}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-snug line-clamp-2">
                  {p.description}
                </p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Target Sizing Controls */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <label className="text-xs font-medium text-slate-300">
            Target Size: <span className="font-mono text-purple-300">{(selectedBytes / (1024 * 1024)).toFixed(1)} MB</span>
          </label>
          <button
            type="button"
            id="toggle-custom-size-btn"
            onClick={() => setUseCustomSize((c) => !c)}
            disabled={isGenerating}
            className="text-[11px] font-mono text-purple-400 hover:text-purple-300 cursor-pointer underline"
          >
            {useCustomSize ? 'Use Standard Presets' : 'Custom Size (MB/GB)'}
          </button>
        </div>

        {!useCustomSize ? (
          <div className="flex flex-wrap items-center gap-2">
            {PRESETS.map((pr) => (
              <button
                key={pr.label}
                type="button"
                id={`preset-size-${pr.label.replace(' ', '')}`}
                onClick={() => setSelectedBytes(pr.bytes)}
                disabled={isGenerating}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition cursor-pointer ${
                  selectedBytes === pr.bytes
                    ? 'bg-purple-600 text-white shadow-sm'
                    : 'bg-slate-850 bg-slate-800/80 hover:bg-slate-750 text-slate-300 border border-slate-700/60'
                } ${isGenerating ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                {pr.label}
              </button>
            ))}
          </div>
        ) : (
          <div className="flex items-center gap-2 max-w-xs">
            <input
              type="number"
              id="custom-size-input"
              min="1"
              max="100000"
              value={customValue}
              onChange={(e) => handleCustomValueChange(e.target.value, customUnit)}
              disabled={isGenerating}
              className="w-28 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-white focus:border-purple-500 focus:outline-none"
              placeholder="10"
            />
            <select
              id="custom-unit-select"
              value={customUnit}
              onChange={(e) => handleCustomValueChange(customValue, e.target.value as 'MB' | 'GB')}
              disabled={isGenerating}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-purple-300 focus:border-purple-500 focus:outline-none cursor-pointer"
            >
              <option value="MB">MB</option>
              <option value="GB">GB</option>
            </select>
            <span className="text-[11px] font-mono text-slate-400">
              ({(selectedBytes / (1024 * 1024)).toFixed(0)} MB)
            </span>
          </div>
        )}
      </div>

      {/* Target Filename & Options */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-slate-300">
            Output Decoy Filename:
          </label>
          <input
            type="text"
            id="decoy-filename-input"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            disabled={isGenerating}
            className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-white focus:border-purple-500 focus:outline-none"
          />
        </div>

        {selectedProfile === 'bin' && (
          <div className="space-y-1.5 flex flex-col justify-end">
            <label className="flex items-center gap-2 p-2 rounded-lg bg-slate-950 border border-slate-800 cursor-pointer select-none">
              <input
                type="checkbox"
                id="decoy-entropy-shaping-toggle"
                checked={entropyShaped}
                onChange={(e) => setEntropyShaped(e.target.checked)}
                disabled={isGenerating}
                className="rounded border-purple-700 bg-purple-950 text-purple-600 focus:ring-purple-500 cursor-pointer"
              />
              <span className="text-xs text-purple-200 font-mono">
                Apply ~6.90 b/B Prefix-Tree Entropy Shaping
              </span>
            </label>
          </div>
        )}
      </div>

      {/* Live Telemetry Progress Bar */}
      {isGenerating && progress && (
        <div id="decoy-telemetry-box" className="space-y-2 p-3.5 rounded-xl bg-slate-950/80 border border-purple-900/60 shadow-inner">
          <div className="flex items-center justify-between text-xs font-mono text-slate-300">
            <div className="flex items-center gap-2">
              <Sparkles className="w-3.5 h-3.5 text-purple-400 animate-spin" />
              <span className="text-purple-300 font-semibold">STREAMING DECOY FILE...</span>
            </div>
            <span>{percentComplete}%</span>
          </div>

          <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-purple-600 to-indigo-500 transition-all duration-150"
              style={{ width: `${percentComplete}%` }}
            />
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[11px] font-mono text-slate-400">
            <div className="flex items-center gap-1.5">
              <Gauge className="w-3.5 h-3.5 text-purple-400" />
              <span>Speed: {progress.speedMBs} MB/s</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-indigo-400" />
              <span>Elapsed: {progress.elapsedSeconds}s</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-emerald-400" />
              <span>ETA: {progress.etaSeconds}s</span>
            </div>
            <div className="text-right sm:text-right text-slate-300 truncate">
              {(progress.processedBytes / (1024 * 1024)).toFixed(1)} / {(progress.totalBytes / (1024 * 1024)).toFixed(1)} MB
            </div>
          </div>
        </div>
      )}

      {/* Success / Error Messages */}
      {resultMessage && (
        <div id="decoy-result-message" className="flex items-center gap-2 p-3 rounded-xl bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs font-mono">
          <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
          <span>{resultMessage}</span>
        </div>
      )}

      {error && (
        <div id="decoy-error-message" className="flex items-center gap-2 p-3 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs font-mono">
          <XCircle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Actions */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
        <div className="text-[11px] font-mono text-slate-500 text-center sm:text-left">
          Target: {currentProfile.badge} • Size: {(selectedBytes / (1024 * 1024)).toFixed(1)} MB
        </div>

        <div className="flex items-center gap-2.5 w-full sm:w-auto">
          {isGenerating ? (
            <button
              type="button"
              id="abort-decoy-generation-btn"
              onClick={handleAbort}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border border-rose-800/80 bg-rose-950/70 hover:bg-rose-900/90 text-rose-300 text-xs font-semibold shadow-sm transition active:scale-95 cursor-pointer"
            >
              <XCircle className="w-4 h-4" />
              <span>Cancel &amp; Scrub Buffers</span>
            </button>
          ) : (
            <button
              type="button"
              id="start-decoy-generation-btn"
              onClick={handleStartGeneration}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold shadow-md transition active:scale-95 cursor-pointer"
            >
              <Download className="w-4 h-4" />
              <span>Generate &amp; Stream Decoy File</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
