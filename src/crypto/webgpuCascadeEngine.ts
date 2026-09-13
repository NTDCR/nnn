/**
 * WebGPU Hardware Acceleration Engine for Fort-Knox Cascade
 * Executes high-performance GPGPU compute shaders over GPU compute cores.
 * Delivers multi-gigabyte throughput with automatic fallback to CPU SIMD WASM pool.
 */

import { CHACHA20_WGSL } from './webgpuShaders.ts';

export interface WebGpuEngineInstance {
  isGpuAccelerated: boolean;
  encryptChunkChaCha(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    startCounter: number
  ): Promise<void>;
  destroy(): void;
}

let gpuDevicePromise: Promise<GPUDevice | null> | null = null;

export async function getWebGpuDevice(): Promise<GPUDevice | null> {
  if (typeof navigator === 'undefined' || !('gpu' in navigator) || !navigator.gpu) {
    return null;
  }
  if (gpuDevicePromise) return gpuDevicePromise;

  gpuDevicePromise = (async () => {
    try {
      const adapter = await navigator.gpu.requestAdapter({
        powerPreference: 'high-performance',
      });
      if (!adapter) return null;
      const device = await adapter.requestDevice();
      return device;
    } catch (e) {
      console.warn('WebGPU device request failed, falling back to CPU SIMD:', e);
      return null;
    }
  })();

  return gpuDevicePromise;
}

export class WebGpuCascadeEngine implements WebGpuEngineInstance {
  public isGpuAccelerated: boolean = true;
  private device: GPUDevice;
  private chachaPipeline: GPUComputePipeline | null = null;

  private constructor(device: GPUDevice) {
    this.device = device;
  }

  public static async create(): Promise<WebGpuCascadeEngine | null> {
    try {
      const device = await getWebGpuDevice();
      if (!device) return null;

      const engine = new WebGpuCascadeEngine(device);
      await engine.initPipelines();
      return engine;
    } catch {
      return null;
    }
  }

  private async initPipelines(): Promise<void> {
    const chachaShaderModule = this.device.createShaderModule({
      label: 'ChaCha20 Compute Shader',
      code: CHACHA20_WGSL,
    });

    this.chachaPipeline = await this.device.createComputePipelineAsync({
      label: 'ChaCha20 Pipeline',
      layout: 'auto',
      compute: {
        module: chachaShaderModule,
        entryPoint: 'main',
      },
    });
  }

  public async encryptChunkChaCha(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    startCounter: number
  ): Promise<void> {
    if (!this.chachaPipeline) throw new Error('Pipeline not initialized');

    const byteLength = data.byteLength;
    const alignedSize = Math.ceil(byteLength / 4) * 4;
    const chunkBlocks = Math.ceil(byteLength / 64);

    // 1. Create GPU Storage Buffer and Uniform Buffer
    const storageBuffer = this.device.createBuffer({
      size: alignedSize,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
      mappedAtCreation: true,
    });
    new Uint8Array(storageBuffer.getMappedRange()).set(data);
    storageBuffer.unmap();

    // Uniform buffer (key: 32B, nonce: 16B, counter: 4B, blocks: 4B, len: 4B, pad: 4B = 64 bytes)
    const uniformArray = new ArrayBuffer(64);
    const uniformU32 = new Uint32Array(uniformArray);
    const keyView = new DataView(key.buffer, key.byteOffset, Math.min(32, key.byteLength));
    const nonceView = new DataView(nonce.buffer, nonce.byteOffset, Math.min(12, nonce.byteLength));

    for (let i = 0; i < 8; i++) {
      uniformU32[i] = i * 4 + 4 <= key.byteLength ? keyView.getUint32(i * 4, true) : 0;
    }
    uniformU32[8] = nonce.byteLength >= 4 ? nonceView.getUint32(0, true) : 0;
    uniformU32[9] = nonce.byteLength >= 8 ? nonceView.getUint32(4, true) : 0;
    uniformU32[10] = nonce.byteLength >= 12 ? nonceView.getUint32(8, true) : 0;
    uniformU32[11] = 0; // pad
    uniformU32[12] = startCounter >>> 0;
    uniformU32[13] = chunkBlocks >>> 0;
    uniformU32[14] = byteLength >>> 0;
    uniformU32[15] = 0; // pad

    const uniformBuffer = this.device.createBuffer({
      size: 64,
      usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
      mappedAtCreation: true,
    });
    new Uint8Array(uniformBuffer.getMappedRange()).set(new Uint8Array(uniformArray));
    uniformBuffer.unmap();

    // 2. Readback staging buffer
    const readbackBuffer = this.device.createBuffer({
      size: alignedSize,
      usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
    });

    const bindGroup = this.device.createBindGroup({
      layout: this.chachaPipeline.getBindGroupLayout(0),
      entries: [
        { binding: 0, resource: { buffer: storageBuffer } },
        { binding: 1, resource: { buffer: uniformBuffer } },
      ],
    });

    // 3. Dispatch GPU Compute Passes
    const commandEncoder = this.device.createCommandEncoder();
    const passEncoder = commandEncoder.beginComputePass();
    passEncoder.setPipeline(this.chachaPipeline);
    passEncoder.setBindGroup(0, bindGroup);
    const workgroups = Math.ceil(chunkBlocks / 64);
    passEncoder.dispatchWorkgroups(workgroups);
    passEncoder.end();

    commandEncoder.copyBufferToBuffer(storageBuffer, 0, readbackBuffer, 0, alignedSize);
    this.device.queue.submit([commandEncoder.finish()]);

    // 4. Map back results to input array
    await readbackBuffer.mapAsync(GPUMapMode.READ);
    const mapped = new Uint8Array(readbackBuffer.getMappedRange(0, byteLength));
    data.set(mapped);
    readbackBuffer.unmap();

    storageBuffer.destroy();
    uniformBuffer.destroy();
    readbackBuffer.destroy();
  }

  public destroy(): void {
    this.chachaPipeline = null;
  }
}
