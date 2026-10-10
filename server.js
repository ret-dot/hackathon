// Offline-first PoS fallback: ATTEMPT -> FAIL_REASON -> FALLBACK_AUTH -> PROVISIONAL_ISSUE -> RECONCILED
// Zero dependencies. Run: node server.js  (Node 16+)
const http = require('http'), fs = require('fs'), P = require('path'), C = require('crypto');
const KP = () => C.generateKeyPairSync('ed25519');
const sign = (k, o) => C.sign(null, Buffer.from(JSON.stringify(o)), k.privateKey).toString('hex');
const ok = (k, o, s) => { try { return C.verify(null, Buffer.from(JSON.stringify(o)), k.publicKey, Buffer.from(s, 'hex')); } catch (e) { return false; } };
const fp = k => k.publicKey.export({ type: 'spki', format: 'der' }).toString('hex').slice(-12);
const rnd = () => C.randomBytes(6).toString('hex');
let S;

function init() {
  const A = KP(); // state authority key: signs lot-level caps
  S = { A, ev: [], tx: [], ledger: [], nonces: new Set(), last: {}, lotUsed: {}, cards: {}, shops: {}, seq: 0, t0: Date.now() };
  [['C1', 'Ramesh Kushwaha', 3], ['C2', 'Sunita Bai', 4], ['C3', 'Gopal Yadav', 2]]
    .forEach(([id, head, n]) => S.cards[id] = { id, head, members: n, quota: 5 * n, used: 0 }); // 5 kg per member
  [['FPS-101', 'Maihar'], ['FPS-102', 'Satna'], ['FPS-103', 'Jabalpur']].forEach(([id, name]) => {
    const cap = { lotId: 'LOT-' + id.slice(-3), shopId: id, capKg: 60 };
    S.shops[id] = { id, name, key: KP(), counter: 0, online: true, queue: [], cap, capSig: sign(A, cap), issued: 0, local: {}, snap: {} };
    S.last[id] = 0; S.lotUsed[cap.lotId] = 0;
  });
}
init();

const log = (shopId, txId, state, reason, detail) =>
  S.ev.push({ t: Math.round((Date.now() - S.t0) / 1000), shopId, txId, state, reason: reason || null, detail: detail || '' });
const snapshot = () => Object.fromEntries(Object.values(S.cards).map(c => [c.id, c.used]));

// Central reconcile: verify signature, nonce, monotonic counter, then per-card quota and lot cap
function sync(sh) {
  let n = 0;
  for (const tok of sh.queue) {
    if (tok.status !== 'PROVISIONAL') continue;
    const p = tok.p, cd = S.cards[p.cardId];
    let st = 'RECONCILED', why = null;
    if (!ok(sh.key, p, tok.sig)) { st = 'REJECTED'; why = 'BAD_SIGNATURE'; }
    else if (S.nonces.has(p.nonce)) { st = 'REJECTED'; why = 'REPLAY_NONCE'; }
    else if (p.counter <= S.last[sh.id]) { st = 'REJECTED'; why = 'COUNTER_ROLLBACK'; }
    else {
      S.nonces.add(p.nonce); S.last[sh.id] = p.counter;
      if (cd.used + p.kg > cd.quota) { st = 'FLAGGED'; why = 'QUOTA_EXCEEDED'; }
      else if (S.lotUsed[p.lotId] + p.kg > sh.cap.capKg) { st = 'FLAGGED'; why = 'LOT_CAP_EXCEEDED'; }
    }
    if (st !== 'REJECTED') {
      if (st === 'RECONCILED') { cd.used += p.kg; S.lotUsed[p.lotId] += p.kg; }
      S.ledger.push({ p, sig: tok.sig, status: st, why });
    }
    tok.status = st; tok.why = why; n++;
    const t = S.tx.find(x => x.id === p.txId);
    if (t && !tok.attack) t.final = st;
    log(sh.id, p.txId, st, why, 'counter ' + p.counter);
  }
  sh.local = {}; sh.snap = snapshot();
  return n;
}

function doTx(b) {
  const sh = S.shops[b.shopId], cd = S.cards[b.cardId];
  if (!sh || !cd) return { error: 'Unknown shop or card' };
  const kg = +b.kg;
  if (!(kg > 0)) return { error: 'Quantity must be above 0 kg' };
  if (sh.online) sh.snap = snapshot(); // online devices see fresh central quota
  const id = 'TX-' + (++S.seq), path = [], att = [];
  let authed = null, secs = 0;
  (b.attempts || []).forEach((a, i, arr) => {
    if (authed) return;
    const r = sh.online ? a.result : 'SERVER_DOWN'; // offline: every Aadhaar auth fails, reason is recorded
    path.push('ATTEMPT'); att.push({ method: a.method, result: r });
    if (r === 'OK') { authed = a.method; secs += 8; log(sh.id, id, 'ATTEMPT', null, a.method + ' verified'); }
    else {
      secs += 20; path.push('FAIL_REASON'); log(sh.id, id, 'FAIL_REASON', r, a.method);
      if (i < arr.length - 1) path.push('FALLBACK_AUTH');
    }
  });
  const t = { id, shopId: sh.id, cardId: cd.id, member: b.member, kg, attempts: att, path, secs, auth: authed || 'NONE' };
  S.tx.push(t);
  const why = (sh.snap[cd.id] || 0) + (sh.local[cd.id] || 0) + kg > cd.quota ? 'CARD_QUOTA_LOCAL'
    : sh.issued + kg > sh.cap.capKg ? 'LOT_CAP_LOCAL' : null;
  if (why) { t.final = 'REFUSED'; t.why = why; path.push('REFUSED'); log(sh.id, id, 'REFUSED', why); return { tx: t, error: 'Refused on the device: ' + why }; }
  const p = { txId: id, shopId: sh.id, cardId: cd.id, member: b.member, kg, lotId: sh.cap.lotId, auth: t.auth,
    reasons: att.filter(a => a.result !== 'OK').map(a => a.result), nonce: rnd(), counter: ++sh.counter, ts: Date.now() };
  sh.queue.push({ p, sig: sign(sh.key, p), status: 'PROVISIONAL' });
  sh.issued += kg; sh.local[cd.id] = (sh.local[cd.id] || 0) + kg; t.secs = secs + 10;
  if (authed && sh.online) { sync(sh); path.push('RECONCILED'); }
  else { path.push('PROVISIONAL_ISSUE'); t.final = 'PROVISIONAL'; log(sh.id, id, 'PROVISIONAL_ISSUE', null, kg + ' kg on a signed token'); }
  return { tx: t };
}

function attack(type, shopId) {
  const sh = S.shops[shopId];
  if (!sh) return { error: 'Unknown shop' };
  if (type === 'doubledip') {
    ['FPS-101', 'FPS-102'].forEach(id => {
      S.shops[id].online = false;
      doTx({ shopId: id, cardId: 'C2', member: 'Member 1', kg: S.cards.C2.quota, attempts: [{ method: 'FINGERPRINT', result: 'FP_MISMATCH' }] });
    });
    return { msg: 'FPS-101 and FPS-102 went offline and each issued the full 20 kg quota of card C2. Bring both online and sync them: the second one is flagged.' };
  }
  const base = [...S.ledger].reverse().find(l => l.p.shopId === sh.id && l.status === 'RECONCILED');
  if (!base) return { error: 'Reconcile at least one token at ' + sh.id + ' first (issue a successful transaction while online).' };
  let p = { ...base.p, txId: 'ATK-' + type }, sig = base.sig;
  if (type === 'replay') p = { ...base.p };
  if (type === 'forge') p = { ...p, kg: p.kg + 40, nonce: rnd(), counter: sh.counter + 1 };
  if (type === 'rollback') { p = { ...p, nonce: rnd(), counter: 1 }; sig = sign(sh.key, p); }
  sh.queue.push({ p, sig, status: 'PROVISIONAL', attack: type });
  if (sh.online) sync(sh);
  return { msg: 'Injected a ' + type + ' token at ' + sh.id + (sh.online ? ' and synced.' : '. Bring the shop online and sync.') };
}

function view() {
  const att = S.tx.flatMap(t => t.attempts), f = att.filter(a => a.result !== 'OK'), byReason = {}, byFinal = {}, byMethod = {};
  f.forEach(a => byReason[a.result] = (byReason[a.result] || 0) + 1);
  S.tx.forEach(t => { if (t.final) byFinal[t.final] = (byFinal[t.final] || 0) + 1; });
  att.forEach(a => { const m = byMethod[a.method] = byMethod[a.method] || { n: 0, f: 0 }; m.n++; if (a.result !== 'OK') m.f++; });
  return {
    cards: S.cards,
    shops: Object.values(S.shops).map(s => ({
      id: s.id, name: s.name, online: s.online, counter: s.counter, pub: fp(s.key), capKg: s.cap.capKg, lotId: s.cap.lotId,
      capOk: ok(S.A, s.cap, s.capSig), issued: s.issued, lotCentral: S.lotUsed[s.cap.lotId],
      queue: s.queue.slice(-8).map(q => ({ ...q.p, sig: q.sig.slice(0, 32) + '…', status: q.status, why: q.why, attack: q.attack }))
    })),
    events: S.ev.slice(-40).reverse(), last: S.tx[S.tx.length - 1] || null,
    metrics: { attempts: att.length, fails: f.length, byReason, byFinal, byMethod, ledger: S.ledger.length,
      avgSecs: S.tx.length ? Math.round(S.tx.reduce((s, t) => s + t.secs, 0) / S.tx.length) : 0 }
  };
}

const port = process.env.PORT || 3000;
http.createServer((req, res) => {
  const send = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (req.method === 'GET' && req.url === '/api/state') return send(200, view());
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    const f = [P.join(__dirname, 'public', 'index.html'), P.join(__dirname, 'index.html')].find(fs.existsSync);
    if (!f) { res.writeHead(500, { 'Content-Type': 'text/plain' }); return res.end('index.html not found. Put it in a "public" folder next to server.js, or directly beside server.js.'); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(fs.readFileSync(f));
  }
  if (req.method !== 'POST') return send(404, { error: 'Not found' });
  let d = '';
  req.on('data', c => d += c).on('end', () => {
    let b = {}; try { b = JSON.parse(d || '{}'); } catch (e) { }
    const sh = S.shops[b.shopId]; let r = {};
    switch (req.url) {
      case '/api/tx': r = doTx(b); break;
      case '/api/online': if (sh) sh.online = !!b.online; break;
      case '/api/sync': r = !sh ? { error: 'Unknown shop' } : !sh.online ? { error: sh.id + ' is offline, so it cannot sync. Bring it online first.' } : { synced: sync(sh) }; break;
      case '/api/attack': r = attack(b.type, b.shopId); break;
      case '/api/reset': init(); break;
      default: return send(404, { error: 'Not found' });
    }
    send(200, { ...r, state: view() });
  });
}).listen(port, () => console.log('PoS fallback demo: http://localhost:' + port));