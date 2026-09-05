import opentype from "opentype.js";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

const FONT_PATH = path.join(
  ROOT,
  "public",
  "assets",
  "fonts",
  "montserrat-alternates",
  "montserrat-alternates-medium.ttf"
);
const OUT_SVG = path.join(ROOT, "public", "favicon.svg");
const OUT_ICO = path.join(ROOT, "public", "favicon.ico");

const VIEW = 64;
const BOX = 44;
const GRADIENT_FROM = [59, 130, 246]; // #3b82f6
const GRADIENT_TO = [56, 189, 248]; // #38bdf8
const BG = [15, 23, 42]; // #0f172a

const fmt = (n) => Math.round(n * 100) / 100;
const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, n));

function pathBBox(commands) {
  let minX = Infinity,
    minY = Infinity,
    maxX = -Infinity,
    maxY = -Infinity;
  const inc = (x, y) => {
    minX = Math.min(minX, x);
    minY = Math.min(minY, y);
    maxX = Math.max(maxX, x);
    maxY = Math.max(maxY, y);
  };
  for (const c of commands) {
    if (c.type === "M" || c.type === "L") inc(c.x, c.y);
    else if (c.type === "Q") {
      inc(c.x, c.y);
      inc(c.x1, c.y1);
    } else if (c.type === "C") {
      inc(c.x, c.y);
      inc(c.x1, c.y1);
      inc(c.x2, c.y2);
    }
  }
  return { minX, minY, maxX, maxY };
}

function pathData(commands, s, dx, dy) {
  const parts = [];
  for (const c of commands) {
    const tx = (x) => fmt(x * s + dx);
    const ty = (y) => fmt(y * s + dy);
    switch (c.type) {
      case "M":
        parts.push(`M${tx(c.x)} ${ty(c.y)}`);
        break;
      case "L":
        parts.push(`L${tx(c.x)} ${ty(c.y)}`);
        break;
      case "Q":
        parts.push(`Q${tx(c.x1)} ${ty(c.y1)} ${tx(c.x)} ${ty(c.y)}`);
        break;
      case "C":
        parts.push(
          `C${tx(c.x1)} ${ty(c.y1)} ${tx(c.x2)} ${ty(c.y2)} ${tx(c.x)} ${ty(c.y)}`
        );
        break;
      case "Z":
        parts.push("Z");
        break;
    }
  }
  return parts.join("");
}

function flattenPolys(commands, s, dx, dy) {
  const polys = [];
  let cur = null;
  let px = 0,
    py = 0;
  const N = 12;
  for (const c of commands) {
    const x = c.x * s + dx;
    const y = c.y * s + dy;
    if (c.type === "M") {
      if (cur) polys.push(cur);
      cur = [[x, y]];
      px = x;
      py = y;
    } else if (c.type === "L") {
      cur.push([x, y]);
      px = x;
      py = y;
    } else if (c.type === "Q") {
      const x1 = c.x1 * s + dx;
      const y1 = c.y1 * s + dy;
      for (let i = 1; i <= N; i++) {
        const t = i / N;
        const mt = 1 - t;
        cur.push([
          mt * mt * px + 2 * mt * t * x1 + t * t * x,
          mt * mt * py + 2 * mt * t * y1 + t * t * y,
        ]);
      }
      px = x;
      py = y;
    } else if (c.type === "C") {
      const x1 = c.x1 * s + dx;
      const y1 = c.y1 * s + dy;
      const x2 = c.x2 * s + dx;
      const y2 = c.y2 * s + dy;
      for (let i = 1; i <= N; i++) {
        const t = i / N;
        const mt = 1 - t;
        cur.push([
          mt * mt * mt * px + 3 * mt * mt * t * x1 + 3 * mt * t * t * x2 + t * t * t * x,
          mt * mt * mt * py + 3 * mt * mt * t * y1 + 3 * mt * t * t * y2 + t * t * t * y,
        ]);
      }
      px = x;
      py = y;
    } else if (c.type === "Z") {
      polys.push(cur);
      cur = null;
    }
  }
  if (cur) polys.push(cur);
  return polys.filter((p) => p.length > 2);
}

function pointInPoly(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const xi = poly[i][0];
    const yi = poly[i][1];
    const xj = poly[j][0];
    const yj = poly[j][1];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) {
      inside = !inside;
    }
  }
  return inside;
}

function inRoundRect(x, y, x0, y0, x1, y1, r) {
  const cx = (x0 + x1) / 2;
  const cy = (y0 + y1) / 2;
  const hw = (x1 - x0) / 2 - r;
  const hh = (y1 - y0) / 2 - r;
  const dx = Math.max(Math.abs(x - cx) - hw, 0);
  const dy = Math.max(Math.abs(y - cy) - hh, 0);
  return dx * dx + dy * dy <= r * r;
}

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const t = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([t, data])));
  return Buffer.concat([len, t, data, crc]);
}

function encodePNG(width, height, rgba) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  const stride = width * 4 + 1;
  const raw = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    raw[y * stride] = 0;
    rgba.copy(raw, y * stride + 1, y * width * 4, (y + 1) * width * 4);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([
    sig,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", idat),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function encodeICO(pngs) {
  const count = pngs.length;
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(count, 4);
  const dirs = [];
  const data = [];
  let offset = 6 + 16 * count;
  for (const p of pngs) {
    const b = Buffer.alloc(16);
    b[0] = p.size >= 256 ? 0 : p.size;
    b[1] = p.size >= 256 ? 0 : p.size;
    b[2] = 0;
    b[3] = 0;
    b.writeUInt16LE(1, 4);
    b.writeUInt16LE(32, 6);
    b.writeUInt32LE(p.buffer.length, 8);
    b.writeUInt32LE(offset, 12);
    dirs.push(b);
    data.push(p.buffer);
    offset += p.buffer.length;
  }
  return Buffer.concat([header, ...dirs, ...data]);
}

function rasterize(size, polys, glyphBox) {
  const SS = 3;
  const out = Buffer.alloc(size * size * 4);
  const offsets = [];
  for (let a = 0; a < SS; a++)
    for (let b = 0; b < SS; b++) offsets.push([(a + 0.5) / SS, (b + 0.5) / SS]);
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let cov = 0;
      let bgIn = 0;
      for (const [ox, oy] of offsets) {
        const x = ((px + ox) * VIEW) / size;
        const y = ((py + oy) * VIEW) / size;
        if (inRoundRect(x, y, 2, 2, 62, 62, 14)) bgIn++;
        let hit = false;
        for (const poly of polys) {
          if (pointInPoly(x, y, poly)) {
            hit = true;
            break;
          }
        }
        if (hit) cov++;
      }
      cov /= offsets.length;
      bgIn /= offsets.length;
      const t = clamp(
        (((py + 0.5) * VIEW) / size - glyphBox.minY) /
          (glyphBox.maxY - glyphBox.minY),
        0,
        1
      );
      const gc = GRADIENT_FROM.map((v, i) => v * (1 - t) + GRADIENT_TO[i] * t);
      const r = Math.round(BG[0] * (1 - cov) + gc[0] * cov);
      const g = Math.round(BG[1] * (1 - cov) + gc[1] * cov);
      const b = Math.round(BG[2] * (1 - cov) + gc[2] * cov);
      const o = (py * size + px) * 4;
      out[o] = r;
      out[o + 1] = g;
      out[o + 2] = b;
      out[o + 3] = Math.round(bgIn * 255);
    }
  }
  return encodePNG(size, size, out);
}

function main() {
  const font = opentype.parse(fs.readFileSync(FONT_PATH));
  const pathObj = font.getPath("T", 0, 0, 1000);
  const commands = pathObj.commands;
  const bbox = pathBBox(commands);
  const glyphW = bbox.maxX - bbox.minX;
  const glyphH = bbox.maxY - bbox.minY;
  const s = BOX / Math.max(glyphW, glyphH);
  const w = glyphW * s;
  const h = glyphH * s;
  const dx = (VIEW - w) / 2 - bbox.minX * s;
  const dy = (VIEW - h) / 2 - bbox.minY * s;

  const d = pathData(commands, s, dx, dy);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${VIEW} ${VIEW}" width="${VIEW}" height="${VIEW}">
  <defs>
    <linearGradient id="tesloT" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#3b82f6"/>
      <stop offset="100%" stop-color="#38bdf8"/>
    </linearGradient>
  </defs>
  <rect x="2" y="2" width="60" height="60" rx="14" fill="#0f172a"/>
  <rect x="3.5" y="3.5" width="57" height="57" rx="12.5" fill="none" stroke="#ffffff" stroke-opacity="0.08" stroke-width="1.5"/>
  <path d="${d}" fill="url(#tesloT)"/>
</svg>
`;
  fs.writeFileSync(OUT_SVG, svg);

  const polys = flattenPolys(commands, s, dx, dy);
  const glyphBox = { minX: dx + bbox.minX * s, maxX: dx + bbox.maxX * s, minY: dy + bbox.minY * s, maxY: dy + bbox.maxY * s };
  const sizes = [16, 32, 48];
  const ico = encodeICO(sizes.map((size) => ({ size, buffer: rasterize(size, polys, glyphBox) })));
  fs.writeFileSync(OUT_ICO, ico);

  console.log(`favicon.svg written (${Buffer.byteLength(svg)} bytes)`);
  console.log(`favicon.ico written (${ico.length} bytes)`);
}

main();