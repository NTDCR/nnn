/**
 * decoyGenerator.ts
 *
 * Industrial-Grade Decoy File & Honeypot Generator Engine.
 * Provides plausible deniability and forensic evasion across 6 authentic profiles:
 * 1. Audio Polyglot (.wav) - Compliant RIFF WAVE with acoustic PCM room tone and dithering.
 * 2. Video Polyglot (.mp4) - ISO Base Media File Format container with ftyp, moov, mdat structure.
 * 3. Virtual Optical Disc (.iso) - ISO-9660 filesystem header with Sector 16 Primary Volume Descriptor.
 * 4. Forensic Binary Dump (.bin) - Configurable Shannon entropy (~6.90 b/B shaped or ~7.999 b/B CSPRNG).
 * 5. System Audit Log (.log) - Authentic enterprise Linux/systemd/postgres syslog lines.
 * 6. Financial Ledger (.csv) - Authentic tabular corporate ledger and settlement transactions.
 *
 * Anti-Forensics:
 * - Sub-2MB zero-RAM chunked streaming pipeline (no heap exhaustion on 100+ GB decoys).
 * - Strict in-place scratchpad buffer zeroization (.fill(0)) on every chunk emission and error boundary.
 * - Hardware timer byte-accurate telemetry (speed, ETA, elapsed time).
 */

import {
  createWavCarrierHeader,
  createIsoCarrierHeader,
  createMp4CarrierHeader,
} from './format.ts';
import { fillCalibratedShapedBytes } from './distributionMatcher.ts';

export type DecoyProfile = 'wav' | 'mp4' | 'iso' | 'bin' | 'log' | 'csv';

export interface DecoyOptions {
  profile: DecoyProfile;
  targetBytes: number;
  entropyShaped?: boolean; // For 'bin' profile: ~6.90 b/B shaped noise vs uniform ~7.999 b/B
  customFilename?: string;
}

export interface DecoyProgress {
  processedBytes: number;
  totalBytes: number;
  speedMBs: number;
  etaSeconds: number;
  elapsedSeconds: number;
}

export interface StreamDecoyParams {
  options: DecoyOptions;
  onChunk: (chunk: Uint8Array) => Promise<void> | void;
  onProgress?: (progress: DecoyProgress) => void;
  signal?: AbortSignal;
}

export const DECOY_CHUNK_SIZE = 1048576; // 1 MB streaming chunks

/**
 * Returns a realistic, authentic filename matching the chosen decoy profile.
 */
export function getDecoyDefaultFilename(profile: DecoyProfile): string {
  const d = new Date();
  const dateStr = d.toISOString().slice(0, 10).replace(/-/g, '');
  const timeStr = d.toTimeString().slice(0, 8).replace(/:/g, '');
  const id = Math.random().toString(36).substring(2, 6);

  switch (profile) {
    case 'wav':
      return `recording_audio_${dateStr}_${timeStr}.wav`;
    case 'mp4':
      return `security_cam_${dateStr}_${timeStr}.mp4`;
    case 'iso':
      return `system_backup_${dateStr}_v${id}.iso`;
    case 'bin':
      return `memdump_${dateStr}_${timeStr}.bin`;
    case 'log':
      return `syslog_audit_${dateStr}.log`;
    case 'csv':
      return `settlement_ledger_${dateStr}.csv`;
  }
}

/**
 * Generates the authentic header bytes for the selected decoy profile.
 */
export function generateDecoyHeader(profile: DecoyProfile, targetBytes: number): Uint8Array {
  switch (profile) {
    case 'wav': {
      // Standard FortKnox audio carrier header (88,252 bytes)
      const payloadLen = Math.max(0, targetBytes - 88252);
      return createWavCarrierHeader(payloadLen, { audibleTone: true });
    }
    case 'iso': {
      // ISO-9660 filesystem header (43,008 bytes = 21 sectors)
      const payloadLen = Math.max(0, targetBytes - 43008);
      return createIsoCarrierHeader(payloadLen);
    }
    case 'mp4': {
      // ISO-BMFF header with moov box and duration
      const duration = Math.max(1, Math.min(7200, Math.floor(targetBytes / (500 * 1024))));
      const payloadLen = Math.max(0, targetBytes - 2048);
      return createMp4CarrierHeader(payloadLen, { durationSec: duration });
    }
    case 'log': {
      const banner =
        `# ====================================================================\n` +
        `# SYSTEM DIAGNOSTIC & AUDIT LOG - HOST: srv-node-${Math.floor(100 + Math.random() * 900)}\n` +
        `# Session Start: ${new Date().toISOString()} | Kernel: Linux 6.8.0-31-generic\n` +
        `# ====================================================================\n\n`;
      return new TextEncoder().encode(banner);
    }
    case 'csv': {
      const csvHeader =
        `TransactionId,TimestampUtc,AccountId,TransactionType,MerchantDescription,Amount,Currency,SettlementStatus,AuditHash\n`;
      return new TextEncoder().encode(csvHeader);
    }
    case 'bin':
    default:
      return new Uint8Array(0);
  }
}

const LOG_SERVICES = ['systemd', 'sshd', 'kernel', 'dockerd', 'postgres', 'nginx', 'crond', 'auditd'];
const LOG_MESSAGES = [
  'Accepted publickey for sysadmin from 192.168.1.105 port 54822 ssh2: RSA SHA256:vN8k',
  'checkpoint complete: wrote 412 buffers (2.5%); 0 WAL file(s) added, 0 removed, 1 recycled',
  'CPU0: Package temperature above threshold, cpu clock throttled (status: 0x86200000)',
  'Started Session 3912 of user monitoring-agent.',
  'GET /api/v2/metrics HTTP/1.1 200 4892 12.4ms - Go-http-client/1.1',
  'pam_unix(sshd:session): session opened for user admin by (uid=0)',
  'Memory cgroup out of memory: Killed process 8192 (worker_node) total-vm:419200kB',
  'eth0: link up, 10000Mbps, full-duplex, lpa 0x01E1, rx-pause, tx-pause',
  'TLS handshake succeeded from client ip=10.0.4.22 cipher=TLS_AES_256_GCM_SHA384',
  'Periodic background database vacuum completed in 1.48s (cleaned 128 rows)',
];

const CSV_ACCOUNTS = ['ACC-489102', 'ACC-190482', 'ACC-772910', 'ACC-330192', 'ACC-882019', 'ACC-661029'];
const CSV_TYPES = ['PAYMENT', 'SETTLEMENT', 'WIRE_TRANSFER', 'REFUND', 'DIVIDEND', 'CLEARING_FEE'];
const CSV_MERCHANTS = [
  'Cloud Infrastructure Services Inc',
  'Global Fiber Transit Ltd',
  'Data Center Colocation Partner',
  'Enterprise Hardware Leasing LLC',
  'Automated Clearinghouse Direct',
  'Secured Escrow Account Holdings',
];
const CSV_STATUSES = ['SETTLED', 'CLEARED', 'COMPLETED', 'CONFIRMED'];

/**
 * Safely fills arbitrary-sized buffers with CSPRNG noise without exceeding Web Crypto 65,536-byte quota limit.
 */
function fillCsprng(buffer: Uint8Array): void {
  const MAX_CSPRNG = 65536;
  for (let offset = 0; offset < buffer.length; offset += MAX_CSPRNG) {
    const end = Math.min(offset + MAX_CSPRNG, buffer.length);
    crypto.getRandomValues(buffer.subarray(offset, end));
  }
}

/**
 * Generates an authentic payload chunk for the given decoy profile.
 */
export function generateDecoyChunk(
  profile: DecoyProfile,
  chunkSize: number,
  entropyShaped?: boolean,
  chunkIndex: number = 0
): Uint8Array {
  const buf = new Uint8Array(chunkSize);

  switch (profile) {
    case 'bin': {
      if (entropyShaped) {
        fillCalibratedShapedBytes(buf);
      } else {
        // High-entropy uniform CSPRNG noise
        fillCsprng(buf);
      }
      return buf;
    }

    case 'wav': {
      // Generate synthetic 16-bit mono acoustic noise with soft sine harmonic dithering
      const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      const sampleCount = Math.floor(chunkSize / 2);
      const baseFreq = 220; // 220 Hz low acoustic hum
      const sampleRate = 44100;
      const startSample = chunkIndex * sampleCount;

      for (let i = 0; i < sampleCount; i++) {
        const sampleIdx = startSample + i;
        const t = sampleIdx / sampleRate;
        // Low amplitude harmonic tone (-32 dBFS) + TPDF dither
        const tone = Math.sin(2 * Math.PI * baseFreq * t) * 800;
        const dither = (Math.random() - Math.random()) * 200;
        const val = Math.max(-32768, Math.min(32767, Math.round(tone + dither)));
        view.setInt16(i * 2, val, true);
      }
      return buf;
    }

    case 'mp4':
    case 'iso': {
      // Polyglot media / disc payload bytes (shaped calibrated noise or uniform)
      if (entropyShaped) {
        fillCalibratedShapedBytes(buf);
      } else {
        fillCsprng(buf);
      }
      return buf;
    }

    case 'log': {
      let offset = 0;
      const now = Date.now();
      const baseTime = now - 86400000 + chunkIndex * 3600000;
      const encoder = new TextEncoder();

      while (offset < chunkSize) {
        const lineTime = new Date(baseTime + Math.floor(Math.random() * 3600000)).toISOString();
        const svc = LOG_SERVICES[Math.floor(Math.random() * LOG_SERVICES.length)];
        const pid = Math.floor(1000 + Math.random() * 64000);
        const msg = LOG_MESSAGES[Math.floor(Math.random() * LOG_MESSAGES.length)];
        const line = `[${lineTime}] [${svc}:${pid}] [INFO] ${msg}\n`;
        const encoded = encoder.encode(line);

        const copyLen = Math.min(encoded.length, chunkSize - offset);
        buf.set(encoded.subarray(0, copyLen), offset);
        offset += copyLen;
      }
      return buf;
    }

    case 'csv': {
      let offset = 0;
      const now = Date.now();
      const encoder = new TextEncoder();

      while (offset < chunkSize) {
        const txId = `TX_${Date.now().toString(36).toUpperCase()}_${Math.floor(1000 + Math.random() * 9000)}`;
        const ts = new Date(now - Math.floor(Math.random() * 864000000)).toISOString();
        const acc = CSV_ACCOUNTS[Math.floor(Math.random() * CSV_ACCOUNTS.length)];
        const type = CSV_TYPES[Math.floor(Math.random() * CSV_TYPES.length)];
        const merchant = CSV_MERCHANTS[Math.floor(Math.random() * CSV_MERCHANTS.length)];
        const amount = (Math.random() * 50000 + 10).toFixed(2);
        const status = CSV_STATUSES[Math.floor(Math.random() * CSV_STATUSES.length)];
        const hash = Array.from(crypto.getRandomValues(new Uint8Array(8)))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

        const line = `${txId},${ts},${acc},${type},"${merchant}",${amount},USD,${status},0x${hash}\n`;
        const encoded = encoder.encode(line);

        const copyLen = Math.min(encoded.length, chunkSize - offset);
        buf.set(encoded.subarray(0, copyLen), offset);
        offset += copyLen;
      }
      return buf;
    }
  }
}

/**
 * Streams the complete decoy file in zero-RAM chunks to the consumer.
 */
export async function streamDecoyPayload(params: StreamDecoyParams): Promise<{ totalBytesWritten: number }> {
  const { options, onChunk, onProgress, signal } = params;
  const targetBytes = Math.max(1024, options.targetBytes);
  const profile = options.profile;
  const entropyShaped = Boolean(options.entropyShaped);

  const startTime = performance.now();
  let writtenBytes = 0;
  let chunkIndex = 0;

  // 1. Generate & emit header
  const header = generateDecoyHeader(profile, targetBytes);
  if (header.length > 0) {
    if (signal?.aborted) throw new Error('Aborted');
    const emitHeaderLen = Math.min(header.length, targetBytes);
    const headerSlice = header.subarray(0, emitHeaderLen);
    await onChunk(headerSlice);
    writtenBytes += emitHeaderLen;
  }

  // 2. Stream remaining bytes in chunks
  while (writtenBytes < targetBytes) {
    if (signal?.aborted) throw new Error('Aborted');

    const remaining = targetBytes - writtenBytes;
    const currentChunkSize = Math.min(DECOY_CHUNK_SIZE, remaining);

    const chunk = generateDecoyChunk(profile, currentChunkSize, entropyShaped, chunkIndex);
    try {
      await onChunk(chunk);
      if (signal?.aborted) throw new Error('Aborted');
      writtenBytes += currentChunkSize;
      chunkIndex++;

      // Telemetry update
      if (onProgress) {
        const elapsedSec = Math.max(0.001, (performance.now() - startTime) / 1000);
        const speedMBs = (writtenBytes / (1024 * 1024)) / elapsedSec;
        const remainingBytes = Math.max(0, targetBytes - writtenBytes);
        const etaSec = speedMBs > 0 ? (remainingBytes / (1024 * 1024)) / speedMBs : 0;

        onProgress({
          processedBytes: writtenBytes,
          totalBytes: targetBytes,
          speedMBs: Number(speedMBs.toFixed(2)),
          etaSeconds: Math.ceil(etaSec),
          elapsedSeconds: Number(elapsedSec.toFixed(1)),
        });
      }
    } finally {
      // Memory hygiene: wipe chunk buffer immediately
      chunk.fill(0);
    }
  }

  return { totalBytesWritten: writtenBytes };
}
