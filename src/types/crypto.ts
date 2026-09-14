export interface CascadeKeys {
  layer1ThreefishHex: string; // Strictly 1024 bits (256 hex chars / 128 bytes)
  layer2SerpentHex: string;   // 256 bits (64 hex characters)
  layer3ChaChaHex: string;    // 256 bits (64 hex characters)
  layer4AesHex: string;       // 256 bits (64 hex characters)
}

export interface ContainerMetadata {
  magic: number;             // 0x464B4E31 ("FKN1")
  version: number;           // 1
  originalSize: number;      // Original unpadded size in bytes
  chunkCount: number;        // Total 1 MB chunks
  chunkSize: number;         // 1048576
  nonceThreefish: Uint8Array;// 16 bytes
  nonceSerpent: Uint8Array;  // 16 bytes
  nonceChaCha20: Uint8Array; // 12 bytes
  nonceAes256: Uint8Array;   // 12 bytes
  hmacIntegrity: Uint8Array; // 32 bytes HMAC-SHA256
  orderConfirm: Uint8Array;  // 32 bytes cascade order verification
  lastModified?: number;     // Original file modification timestamp in milliseconds
}

export interface WorkerProgressMessage {
  type: 'PROGRESS';
  phase: 'ENCRYPTING' | 'DECRYPTING' | 'PREPARING' | 'FINALIZING';
  currentChunk: number;
  totalChunks: number;
  currentLayer: number; // 1..4
  processedBytes: number;
  totalBytes: number;
  speedMBs: number;
  etaSeconds: number;
}

export interface WorkerSuccessMessage {
  type: 'SUCCESS';
  mode: 'ENCRYPT' | 'DECRYPT';
  fileName: string;
  originalSize: number;
  finalSize: number;
  totalTimeMs: number;
  averageSpeedMBs: number;
  blobUrl?: string; // If streaming directly to memory or fallback
  lastModified?: number; // Preserved original modification timestamp
}

export interface LayerMetadata {
  order: number;
  name: string;
  algorithm: string;
  mode: string;
  auth: string;
  keySizeBits: number;
  description: string;
  library: string;
  auditStatus: string;
}
