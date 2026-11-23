/* DVLPR+ BLD private preview — decrypts the encrypted site files on request. Holds no data of its own. */
const DB = "bld-sw", ST = "k";
let CK = null, MAN = null, VER = null;
const idb = () => new Promise((res, rej) => { const r = indexedDB.open(DB, 1); r.onupgradeneeded = () => r.result.createObjectStore(ST); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
const kget = async (k) => { const db = await idb(); return new Promise((res) => { const t = db.transaction(ST).objectStore(ST).get(k); t.onsuccess = () => res(t.result); t.onerror = () => res(null); }); };
const kput = async (k, v) => { const db = await idb(); return new Promise((res) => { const t = db.transaction(ST, "readwrite"); t.objectStore(ST).put(v, k); t.oncomplete = () => res(); t.onerror = () => res(); }); };
const kdel = async () => { const db = await idb(); return new Promise((res) => { const t = db.transaction(ST, "readwrite"); t.objectStore(ST).clear(); t.oncomplete = () => res(); t.onerror = () => res(); }); };
const u8 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const base = () => self.registration.scope;
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
async function ready() {
  if (!CK) { const raw = await kget("ck"); if (raw) { CK = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]); VER = await kget("v"); } }
  if (!CK) return false;
  if (!MAN) { const r = await fetch(base() + "m.bin", { cache: "no-store" }); const b = new Uint8Array(await r.arrayBuffer());
    try { MAN = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12) }, CK, b.slice(12)))); } catch (e) { CK = null; await kdel(); return false; } }
  return true;
}
self.addEventListener("message", (e) => { const d = e.data || {};
  if (d.type === "key") e.waitUntil((async () => { await kput("ck", d.ck); await kput("v", d.v); CK = null; MAN = null; const ok = await ready(); e.source && e.source.postMessage({ type: "key-ok", ok }); })());
  if (d.type === "has") e.waitUntil((async () => { const ok = await ready(); e.source && e.source.postMessage({ type: "has", ok }); })());
  if (d.type === "forget") e.waitUntil((async () => { CK = null; MAN = null; await kdel(); e.source && e.source.postMessage({ type: "forgot" }); })());
});
const CH = new Map();
async function chunkSlice(n, off, len) {
  const url = base() + "c" + String(n).padStart(2, "0") + ".bin?v=" + (VER || "");
  try { const r = await fetch(url, { headers: { Range: "bytes=" + off + "-" + (off + len - 1) } }); if (r.status === 206) return new Uint8Array(await r.arrayBuffer()); if (r.ok) { const all = new Uint8Array(await r.arrayBuffer()); return all.slice(off, off + len); } } catch (e) {}
  if (!CH.has(url)) CH.set(url, fetch(url).then((r) => r.arrayBuffer()).then((b) => new Uint8Array(b)));
  return (await CH.get(url)).slice(off, off + len);
}
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url); if (url.origin !== self.location.origin || e.request.method !== "GET") return;
  let p = decodeURIComponent(url.pathname.slice(new URL(base()).pathname.length));
  if (p === "" || p === "index.html" || p === "sw.js" || p === "k.json" || p === "m.bin" || p === "robots.txt" || /^c\d\d\.bin$/.test(p)) return;
  e.respondWith((async () => {
    if (!(await ready())) return Response.redirect(base(), 302);
    const m = p === "__ch" ? null : MAN[p]; if (!m) return new Response("Not found", { status: 404 });
    const SZ = MAN.__ch || 0; let n = m[0], off = m[1], left = m[2]; const segs = [];
    while (left > 0) { const take = SZ ? Math.min(left, SZ - off) : left; segs.push(chunkSlice(n, off, take)); left -= take; n++; off = 0; }
    const got = await Promise.all(segs); let ct; if (got.length === 1) ct = got[0]; else { ct = new Uint8Array(m[2]); let o = 0; for (const g of got) { ct.set(g, o); o += g.length; } }
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: u8(m[3]) }, CK, ct);
    return new Response(pt, { status: 200, headers: { "Content-Type": m[4] + (/^text\/|json|javascript/.test(m[4]) ? "; charset=utf-8" : ""), "Cache-Control": "no-store" } });
  })());
});
