/**
 * CompositeFileReader
 * Enables seamless, zero-RAM sequential sliced reading across multi-part split files.
 * Provides natural sequence sorting, continuity validation, and transparent slice bridging.
 */

export interface SliceableDataSource {
  readonly size: number;
  readonly name: string;
  slice(start: number, end?: number): { arrayBuffer(): Promise<ArrayBuffer> };
}

export class CompositeFileReader implements SliceableDataSource {
  public readonly size: number;
  public readonly name: string;
  public readonly files: File[];
  private readonly offsets: number[];

  constructor(files: File[]) {
    if (!files || files.length === 0) {
      throw new Error('At least one file part must be provided.');
    }
    const sorted = CompositeFileReader.sortParts([...files]);
    this.files = sorted;
    this.offsets = [0];
    let total = 0;
    for (const f of sorted) {
      total += f.size;
      this.offsets.push(total);
    }
    this.size = total;
    // Strip trailing .partXXX or .part-XXX if present
    this.name = sorted[0].name.replace(/\.part[-_]?\d+$/i, '');
  }

  public static isMultiPart(files: File[]): boolean {
    return files.length > 1;
  }

  public static getPartNumber(name: string): number | null {
    const match = name.match(/\.part[-_]?(\d+)$/i) || name.match(/\.(\d{3,})$/i);
    if (match && match[1]) {
      const num = parseInt(match[1], 10);
      return Number.isSafeInteger(num) ? num : null;
    }
    return null;
  }

  public static sortParts(files: File[]): File[] {
    return files.sort((a, b) => {
      const numA = CompositeFileReader.getPartNumber(a.name);
      const numB = CompositeFileReader.getPartNumber(b.name);
      if (numA !== null && numB !== null) {
        return numA - numB;
      }
      return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
    });
  }

  public static validatePartSequence(files: File[]): { valid: boolean; error?: string } {
    if (files.length <= 1) return { valid: true };
    const sorted = CompositeFileReader.sortParts([...files]);
    const numbers = sorted.map((f) => CompositeFileReader.getPartNumber(f.name));

    // If part numbers were found on all files, ensure sequence starts at 1 and has no gaps
    if (numbers.every((n) => n !== null)) {
      const nums = numbers as number[];
      const first = nums[0];
      if (first !== 1 && first !== 0) {
        return {
          valid: false,
          error: `Part sequence starts at part ${first} instead of 1. Ensure all parts are selected.`,
        };
      }
      for (let i = 1; i < nums.length; i++) {
        if (nums[i] === nums[i - 1]) {
          return {
            valid: false,
            error: `Duplicate part ${nums[i]} detected. Ensure each part is selected only once.`,
          };
        }
        if (nums[i] !== nums[i - 1] + 1) {
          return {
            valid: false,
            error: `Missing part between part ${nums[i - 1]} and part ${nums[i]}.`,
          };
        }
      }
    }
    return { valid: true };
  }

  public slice(start: number, end: number = this.size): { arrayBuffer(): Promise<ArrayBuffer> } {
    const clampedStart = Math.max(0, Math.min(start, this.size));
    const clampedEnd = Math.max(clampedStart, Math.min(end, this.size));
    const reqLen = clampedEnd - clampedStart;

    return {
      arrayBuffer: async (): Promise<ArrayBuffer> => {
        if (reqLen === 0) return new ArrayBuffer(0);

        const chunks: Uint8Array[] = [];
        for (let i = 0; i < this.files.length; i++) {
          const fileStart = this.offsets[i];
          const fileEnd = this.offsets[i + 1];

          if (clampedEnd <= fileStart || clampedStart >= fileEnd) {
            continue;
          }

          const sliceStart = Math.max(0, clampedStart - fileStart);
          const sliceEnd = Math.min(this.files[i].size, clampedEnd - fileStart);
          const partBuf = await this.files[i].slice(sliceStart, sliceEnd).arrayBuffer();
          chunks.push(new Uint8Array(partBuf));
        }

        if (chunks.length === 1) {
          const single = chunks[0];
          if (single.byteOffset === 0 && single.byteLength === single.buffer.byteLength) {
            return single.buffer as ArrayBuffer;
          }
          return single.slice().buffer as ArrayBuffer;
        }

        const merged = new Uint8Array(reqLen);
        let pos = 0;
        for (const c of chunks) {
          merged.set(c, pos);
          pos += c.length;
        }
        return merged.buffer as ArrayBuffer;
      },
    };
  }
}
