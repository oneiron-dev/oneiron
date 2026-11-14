/**
 * Test-only ZIP writer for crafted workbook packages: the bridge never writes
 * packages. Each part is stored, or deflated with the size it really inflates
 * to, and may be written the way a streaming writer writes it.
 */
import { deflateRawSync } from "node:zlib";

export const MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
export const REL = "http://schemas.openxmlformats.org/package/2006/relationships";
export const DOC_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

export interface Part {
  readonly name: string;
  /** Stored bytes, or a raw deflate stream with the size it really inflates to. */
  readonly body: Uint8Array | { readonly stream: Uint8Array; readonly size: number; readonly crc: number };
  /** Written as a streaming writer does: zero local sizes, a data descriptor after the data. */
  readonly streamed?: boolean;
  /** Extra-field bytes of the central directory entry. */
  readonly centralExtra?: readonly number[];
}

function le(bytes: number[], value: number, width: 2 | 4): void {
  for (let i = 0; i < width; i += 1) bytes.push((value >>> (8 * i)) & 0xff);
}

/** The package holding `parts`, in order, with its central directory. */
export function zip(parts: readonly Part[]): Uint8Array {
  const out: number[] = [];
  const central: number[] = [];
  for (const part of parts) {
    const name = new TextEncoder().encode(part.name);
    const stored = part.body instanceof Uint8Array;
    const data = part.body instanceof Uint8Array ? part.body : part.body.stream;
    const size = part.body instanceof Uint8Array ? data.length : part.body.size;
    const crc = part.body instanceof Uint8Array ? Bun.hash.crc32(data) : part.body.crc;
    const flags = part.streamed ? 8 : 0;
    const extra = part.centralExtra ?? [];
    const offset = out.length;
    le(out, 0x04034b50, 4);
    le(out, 20, 2);
    le(out, flags, 2);
    le(out, stored ? 0 : 8, 2);
    le(out, 0, 2);
    le(out, 0x21, 2);
    le(out, part.streamed ? 0 : crc, 4);
    le(out, part.streamed ? 0 : data.length, 4);
    le(out, part.streamed ? 0 : size, 4);
    le(out, name.length, 2);
    le(out, 0, 2);
    out.push(...name);
    for (const byte of data) out.push(byte);
    if (part.streamed) {
      le(out, 0x08074b50, 4);
      le(out, crc, 4);
      le(out, data.length, 4);
      le(out, size, 4);
    }
    le(central, 0x02014b50, 4);
    le(central, 20, 2);
    le(central, 20, 2);
    le(central, flags, 2);
    le(central, stored ? 0 : 8, 2);
    le(central, 0, 2);
    le(central, 0x21, 2);
    le(central, crc, 4);
    le(central, data.length, 4);
    le(central, size, 4);
    le(central, name.length, 2);
    le(central, extra.length, 2);
    le(central, 0, 2);
    le(central, 0, 2);
    le(central, 0, 2);
    le(central, 0, 4);
    le(central, offset, 4);
    central.push(...name, ...extra);
  }
  const directory = out.length;
  out.push(...central);
  le(out, 0x06054b50, 4);
  le(out, 0, 2);
  le(out, 0, 2);
  le(out, parts.length, 2);
  le(out, parts.length, 2);
  le(out, central.length, 4);
  le(out, directory, 4);
  le(out, 0, 2);
  return Uint8Array.from(out);
}

/** UTF-8 bytes of a part's XML text. */
export const text = (xml: string) => new TextEncoder().encode(xml);

/** `bytes` as a raw deflate stream, with the size and CRC it really inflates to. */
export function deflated(bytes: Uint8Array): Part["body"] {
  return { stream: deflateRawSync(bytes), size: bytes.length, crc: Bun.hash.crc32(bytes) };
}
