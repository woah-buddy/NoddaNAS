// FrontDir download worker: turns a stream of decrypted chunks into an
// ordinary browser download, so files of any size are saved without being
// held in memory. The page decrypts (and verifies) the chunks; this worker
// only hands them to the browser's download manager.
//
// Least privilege: it is registered with scope /dl/, so it sees no request
// but /dl/<id>; it fetches nothing itself; each download id is random,
// single use and expires after a minute. Its responses are attachments,
// typed as opaque bytes, never sniffed, and sandboxed by CSP, so even a
// browser that tried to display one could not run it as a page.
'use strict';

const pending = new Map(); // id -> { stream, name, size, port, at }
const TTL = 60 * 1000;
const ID = /^[0-9a-f]{32}$/;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

function sweep() {
  const now = Date.now();
  for (const [id, p] of pending) {
    if (now - p.at > TTL) { pending.delete(id); p.port.postMessage({ expired: true }); }
  }
}

self.addEventListener('message', (e) => {
  const m = e.data, port = e.ports && e.ports[0];
  if (!port || !m || m.type !== 'download' || typeof m.id !== 'string' || !ID.test(m.id) ||
      typeof m.name !== 'string' || m.name.length === 0 || m.name.length > 1024 ||
      !Number.isSafeInteger(m.size) || m.size < 0) return;
  sweep();
  let waiting = null;
  const stream = new ReadableStream({
    // One chunk is requested at a time, and only as the download consumes
    // them: the page never decrypts far ahead of the disk.
    pull(c) {
      return new Promise((resolve) => {
        waiting = { c, resolve };
        port.postMessage({ pull: true });
      });
    },
    cancel() { port.postMessage({ cancel: true }); },
  }, { highWaterMark: 2 });
  port.onmessage = ({ data }) => {
    const w = waiting;
    waiting = null;
    if (!w) return;
    if (data && data.chunk instanceof Uint8Array) w.c.enqueue(data.chunk);
    else if (data && data.done) w.c.close();
    else w.c.error(new Error((data && data.error) || 'download failed'));
    w.resolve();
  };
  pending.set(m.id, { stream, name: m.name, size: m.size, port, at: Date.now() });
  port.postMessage({ ready: true });
});

// RFC 6266 / 5987: an ASCII fallback plus the exact UTF-8 name.
function disposition(name) {
  const ascii = name.replace(/[^A-Za-z0-9._ ()-]/g, '_');
  const enc = encodeURIComponent(name).replace(/['()*]/g, (ch) => '%' + ch.charCodeAt(0).toString(16).toUpperCase());
  return `attachment; filename="${ascii}"; filename*=UTF-8''${enc}`;
}

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  const m = url.origin === self.location.origin && url.pathname.match(/^\/dl\/([0-9a-f]{32})$/);
  if (!m) return; // not a download: the network handles it
  sweep();
  const p = pending.get(m[1]);
  pending.delete(m[1]); // single use
  if (!p) {
    e.respondWith(new Response(null, { status: 204 }));
    return;
  }
  p.port.postMessage({ started: true });
  e.respondWith(new Response(p.stream, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': disposition(p.name),
      'Content-Length': String(p.size),
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'; sandbox",
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
    },
  }));
});
