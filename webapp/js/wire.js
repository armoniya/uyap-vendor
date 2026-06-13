// p2p_wire.py'nin tarayıcı (JS) karşılığı — ofis ajanıyla BİREBİR aynı tel protokolü.
//
// Her çerçeve = [4 bayt başlık uzunluğu (big-endian)] + [JSON başlık (utf-8)] + [ham parça].
// Başlık: {id, kind, seq, total, meta?(yalnızca seq==0)}; meta._comp sıkıştırma bayrağı.
//
// Tarayıcı -> ofis isteklerini SIKIŞTIRMAYIZ (genelde küçük/gövdesiz); meta._comp=false
// gönderir, ofis Reassembler'ı bunu olduğu gibi açar. Ofis -> tarayıcı cevapları zlib ile
// sıkıştırılmış gelir; onları DecompressionStream('deflate') ile açarız (RFC 1950 = zlib).

export const CHUNK = 48 * 1024;

const _enc = new TextEncoder();
const _dec = new TextDecoder();

export function* encodeFrames(msgId, kind, meta, body) {
  body = body || new Uint8Array(0);
  const total = Math.max(1, Math.ceil(body.length / CHUNK));
  for (let seq = 0; seq < total; seq++) {
    const chunk = body.subarray(seq * CHUNK, (seq + 1) * CHUNK);
    const header = { id: msgId, kind, seq, total };
    if (seq === 0) {
      const m = meta ? Object.assign({}, meta) : {};
      m._comp = false;               // tarayıcı tarafı sıkıştırma yapmaz
      header.meta = m;
    }
    const headerBytes = _enc.encode(JSON.stringify(header));
    const frame = new Uint8Array(4 + headerBytes.length + chunk.length);
    new DataView(frame.buffer).setUint32(0, headerBytes.length, false); // big-endian
    frame.set(headerBytes, 4);
    frame.set(chunk, 4 + headerBytes.length);
    yield frame.buffer;
  }
}

export class Reassembler {
  constructor() {
    this._buf = new Map(); // id -> {chunks: Map<seq,Uint8Array>, total, meta, kind}
  }

  // data: ArrayBuffer (channel.binaryType = 'arraybuffer'). Mesaj tamamlandıysa kayıt,
  // değilse null döndürür. Kayıt: {id, kind, meta, body(Uint8Array), comp}.
  feed(data) {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const hlen = dv.getUint32(0, false);
    const header = JSON.parse(_dec.decode(bytes.subarray(4, 4 + hlen)));
    // Geçici tampon yeniden kullanılabileceği için parçayı kopyalayarak sakla.
    const chunk = Uint8Array.from(bytes.subarray(4 + hlen));
    const mid = header.id;
    let entry = this._buf.get(mid);
    if (!entry) {
      entry = { chunks: new Map(), total: header.total, meta: null, kind: header.kind };
      this._buf.set(mid, entry);
    }
    entry.chunks.set(header.seq, chunk);
    if (header.seq === 0) entry.meta = header.meta || null;
    if (entry.chunks.size >= entry.total) {
      this._buf.delete(mid);
      let totalLen = 0;
      for (let i = 0; i < entry.total; i++) totalLen += entry.chunks.get(i).length;
      const body = new Uint8Array(totalLen);
      let off = 0;
      for (let i = 0; i < entry.total; i++) {
        const c = entry.chunks.get(i);
        body.set(c, off);
        off += c.length;
      }
      return {
        id: mid, kind: entry.kind, meta: entry.meta, body,
        comp: !!(entry.meta && entry.meta._comp),
      };
    }
    return null;
  }
}

export async function inflate(bytes) {
  if (typeof DecompressionStream === "undefined") {
    throw new Error("Tarayıcı DecompressionStream desteklemiyor (zlib açılamıyor).");
  }
  const ds = new DecompressionStream("deflate"); // zlib (RFC 1950) = Python zlib.compress
  const stream = new Blob([bytes]).stream().pipeThrough(ds);
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

// Tamamlanmış kaydı, gerekiyorsa açarak gövdesini hazır hale getirir.
export async function finalize(rec) {
  if (rec.comp) rec.body = await inflate(rec.body);
  return rec;
}
