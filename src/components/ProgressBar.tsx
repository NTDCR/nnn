import React from 'react';
import { WorkerProgressMessage } from '../types/crypto.ts';
import { Gauge, Clock, HardDrive, Layers } from 'lucide-react';

interface ProgressBarProps {
  progress: WorkerProgressMessage;
  onCancel?: () => void;
}

const LAYER_NAMES = [
  'Threefish-1024 (Innermost)',
  'Serpent-256 (CTR)',
  'ChaCha20-Poly1305 (AEAD)',
  'AES-256-GCM (Outermost)',
];

export const ProgressBar: React.FC<ProgressBarProps> = ({ progress, onCancel }) => {
  const percent = progress.totalBytes > 0
    ? Math.min(100, Math.round((progress.processedBytes / progress.totalBytes) * 100))
    : (progress.currentChunk === progress.totalChunks ? 100 : 0);

  return (
    <div id="cascade-progress-card" className="rounded-xl bg-slate-900 border border-slate-800 p-3.5 sm:p-5 shadow-xl">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2.5 sm:mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <div className="h-2.5 w-2.5 rounded-full bg-indigo-500 animate-ping" />
          <span className="text-xs sm:text-sm font-semibold text-white capitalize">
            {progress.phase.toLowerCase()}...
          </span>
          <span className="text-[10px] sm:text-xs px-2 py-0.5 rounded-full bg-slate-800 text-indigo-300 font-mono">
            Chunk {progress.currentChunk} of {progress.totalChunks}
          </span>
        </div>

        <div className="flex items-center justify-between sm:justify-end gap-3 text-xs font-mono text-slate-400">
          <span className="flex items-center gap-1">
            <Gauge className="w-3.5 h-3.5 text-emerald-400" />
            <strong className="text-emerald-400 font-semibold">{progress.speedMBs}</strong> MB/s
          </span>
          <span className="flex items-center gap-1">
            <Clock className="w-3.5 h-3.5 text-sky-400" />
            ETA: {progress.etaSeconds}s
          </span>
          {onCancel && (
            <button
              onClick={onCancel}
              className="px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/80 text-xs text-rose-300 hover:text-rose-200 transition active:scale-95 cursor-pointer font-sans font-semibold"
            >
              Abort
            </button>
          )}
        </div>
      </div>

      {/* Main Progress Track */}
      <div className="relative h-3 w-full overflow-hidden rounded-full bg-slate-950 border border-slate-800">
        <div
          id="progress-fill-bar"
          className="h-full bg-gradient-to-r from-sky-500 via-indigo-500 to-purple-500 transition-all duration-300 ease-out"
          style={{ width: `${percent}%` }}
        />
      </div>

      {/* Bottom Metrics */}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400 font-mono">
        <div className="flex items-center gap-1.5">
          <HardDrive className="w-3.5 h-3.5 text-slate-500" />
          <span>
            {(progress.processedBytes / (1024 * 1024)).toFixed(1)} MB / {(progress.totalBytes / (1024 * 1024)).toFixed(1)} MB
          </span>
          <span className="text-slate-500">({percent}%)</span>
        </div>

        {/* 4-Layer visual status */}
        <div className="flex items-center gap-1">
          <Layers className="w-3.5 h-3.5 text-slate-500 mr-1" />
          {[1, 2, 3, 4].map((layerNum) => {
            const isFinished = percent >= 100;
            let isCompleted = false;
            let isActive = false;

            if (isFinished) {
              isCompleted = true;
            } else if (progress.phase === 'ENCRYPTING') {
              const activeLayer = Math.min(4, Math.floor(percent / 25) + 1);
              isCompleted = layerNum < activeLayer;
              isActive = layerNum === activeLayer;
            } else {
              // DECRYPTING: peeling from Layer 4 down to Layer 1
              const activeLayer = Math.max(1, 4 - Math.floor(percent / 25));
              isCompleted = layerNum > activeLayer;
              isActive = layerNum === activeLayer;
            }

            return (
              <span
                key={layerNum}
                title={`Layer ${layerNum}: ${LAYER_NAMES[layerNum - 1]}${isActive ? ' (Active)' : isCompleted ? ' (Completed)' : ' (Pending)'}`}
                className={`h-2 w-6 rounded-xs transition-all duration-200 ${
                  isCompleted
                    ? 'bg-indigo-500 shadow-xs shadow-indigo-500/50'
                    : isActive
                    ? 'bg-indigo-400 ring-1 ring-indigo-300 animate-pulse'
                    : 'bg-slate-800'
                }`}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
};
