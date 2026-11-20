// FrontDir web client (end-to-end encrypted).
//
// Everything is encrypted and decrypted here, in the browser (see e2ee.js
// and docs/E2EE.md). The server only ever receives ciphertext: file
// contents, file and folder names, team names and every key are encrypted
// before they leave this page. Keys live in memory only, for this tab.
//
// The page is written against DOM APIs only (createElement/textContent);
// its CSP enforces Trusted Types with no policies, so the browser refuses
// any string-to-HTML injection.
import * as E from './e2ee.js';

const main = document.getElementById('main');
const S = { me: null, acct: null, bundle: null, contacts: null, keys: new Map(), spaces: new Map(), users: new Map(), pubs: new Map() };

// ---- DOM helpers --------------------------------------------------------------------------
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (['hidden', 'disabled', 'required', 'checked', 'multiple'].includes(k)) el[k] = Boolean(v);
    else el.setAttribute(k, String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 5000);
}
function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  const u = ['KiB', 'MiB', 'GiB', 'TiB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${u[i]}`;
}
const fmtDate = (s) => (s ? new Date(s).toLocaleString() : '');
function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: name, hidden: true });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}
function pickFiles(accept, multiple = true) {
  return new Promise((resolve) => {
    const input = h('input', { type: 'file', accept, multiple, hidden: true, onchange: () => { resolve(Array.from(input.files)); input.remove(); } });
    document.body.append(input);
    input.click();
  });
}

// ---- API ---------------------------------------------------------------------------------
class ApiError extends Error {
  constructor(status, body) {
    super(body?.error?.message || `Request failed (${status})`);
    this.status = status;
    this.code = body?.error?.code;
    this.detail = body?.error?.detail || {};
  }
}
async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: 'same-origin' };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(path, opts);
  const isJSON = (r.headers.get('Content-Type') || '').includes('application/json');
  const data = isJSON ? await r.json() : null;
  if (!r.ok) throw new ApiError(r.status, data);
  return data;
}
async function apiBlob(path, init) {
  const r = await fetch(path, { credentials: 'same-origin', ...init });
  if (!r.ok) throw new ApiError(r.status, await r.json().catch(() => null));
  return r.blob();
}
// XMLHttpRequest (not fetch) because it reports upload progress.
function send(method, path, blob, headers, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, path);
    for (const [k, v] of Object.entries(headers)) xhr.setRequestHeader(k, v);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress && onProgress(e.loaded / e.total);
    xhr.onload = () => {
      let body = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body);
      else reject(new ApiError(xhr.status, body));
    };
    xhr.onerror = () => reject(new ApiError(0, null));
    xhr.send(blob);
  });
}

// ---- dialogs -------------------------------------------------------------------------------
function dialog(title, ...content) {
  const d = h('dialog', {}, h('h2', {}, title), ...content);
  d.addEventListener('close', () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}
function prompt(title, label, value = '', type = 'text') {
  return new Promise((resolve) => {
    const input = h('input', { value, type, required: true });
    const d = dialog(title, h('form', { class: 'stack', method: 'dialog', onsubmit: () => resolve(input.value) },
      h('label', {}, label, input),
      h('div', { class: 'row' }, h('button', { type: 'button', onclick: () => { resolve(null); d.close(); } }, 'Cancel'), h('button', { class: 'primary' }, 'OK'))));
    d.addEventListener('cancel', () => resolve(null));
    input.select();
  });
}
function confirmBox(title, text, ok = 'OK') {
  return new Promise((resolve) => {
    const d = dialog(title, h('p', {}, text), h('form', { method: 'dialog', class: 'row' },
      h('button', { onclick: () => resolve(false) }, 'Cancel'), h('button', { class: 'primary', onclick: () => resolve(true) }, ok)));
    d.addEventListener('cancel', () => resolve(false));
  });
}
function showSecret(title, explanation, secret) {
  dialog(title, h('p', { class: 'note' }, explanation), h('div', { class: 'secret' }, secret),
    h('form', { method: 'dialog', class: 'row' },
      h('button', { type: 'button', onclick: async () => { try { await navigator.clipboard.writeText(secret); toast('Copied'); } catch { toast('Copy failed: select and copy manually'); } } }, 'Copy'),
      h('button', { class: 'primary' }, 'Done')));
}
function busy(text) {
  const d = dialog(text, h('div', { class: 'progress' }, h('div', { class: 'bar' })));
  return { set: (f) => { d.querySelector('.bar').style.width = `${Math.round(f * 100)}%`; }, close: () => d.close() };
}

// ---- keys and spaces -------------------------------------------------------------------------
async function userKeys(id) {
  if (S.users.has(id)) return S.users.get(id);
  const u = await api('GET', `/api/v1/users/${id}/keys`);
  const pu = await E.verifyUser(u.id, u.keys);
  pu.displayName = u.displayName;
  pu.email = u.email;
  S.users.set(id, pu);
  return pu;
}
async function spacePub(sp) {
  if (S.pubs.has(sp.id)) return S.pubs.get(sp.id);
  const pub = await E.verifySpaceKey(await userKeys(sp.keySigner), sp.id, sp.publicKey, sp.keySig);
  S.pubs.set(sp.id, pub);
  return pub;
}
// openSpace unlocks a space (personal via the account; team via a signed grant).
async function openSpace(sp) {
  const cached = S.spaces.get(sp.id);
  if (cached) return cached.space;
  let space;
  if (sp.kind === 'personal') space = await S.acct.personalSpace(sp.id);
  else if (sp.myGrant) space = await E.Space.openGrant(S.acct, await userKeys(sp.myGrant.grantedBy), sp.id, sp.myGrant.grant, sp.myGrant.grantSig);
  else throw new Error('You have not been given this team folder’s key yet. Ask a manager to approve you on its Members page.');
  if (E.b64u(space.publicKey) !== sp.publicKey) throw new Error('Space key mismatch');
  S.keys.set(sp.rootId, await space.unwrapRoot(sp.rootId, sp.rootKey));
  const name = sp.kind === 'team' ? await space.decryptName(sp.nameEnc) : 'Home';
  S.spaces.set(sp.id, { space, info: sp, name });
  S.pubs.set(sp.id, space.publicKey);
  return space;
}
const spaceName = (sp) => S.spaces.get(sp.id)?.name || (sp.kind === 'personal' ? 'Home' : 'Locked team folder');

// pathTo derives keys from an entry point the user holds down to a node and
// returns breadcrumb entries with decrypted names.
async function pathTo(id) {
  const p = await api('GET', `/api/v1/nodes/${id}/path`);
  let key, label;
  if (p.share) {
    const sh = await E.openShare(S.acct, await userKeys(p.share.createdBy), p.share);
    key = sh.nk;
    label = sh.name;
  } else {
    await openSpace(p.space);
    key = S.keys.get(p.space.rootId);
    label = spaceName(p.space);
  }
  const trail = [{ id: p.nodes[0].id, name: label, node: p.nodes[0] }];
  S.keys.set(p.nodes[0].id, key);
  for (let i = 1; i < p.nodes.length; i++) {
    const n = p.nodes[i];
    const name = await key.decryptName(n.id, n.nameEnc);
    key = await key.unwrapChild(n.id, n.wrappedKey);
    S.keys.set(n.id, key);
    trail.push({ id: n.id, name, node: n });
  }
  return { space: p.space, share: p.share, trail, node: p.node, key };
}
async function nodeKey(id) {
  if (!S.keys.has(id)) await pathTo(id);
  return S.keys.get(id);
}
const signerFor = (id) => userKeys(id);

// ---- verified people (E2EE.md §8) ----------------------------------------------------------------
// Names and emails come from the server, which could fake them. What cannot
// be faked is a key fingerprint compared in person. The list of people this
// user has verified is sealed under their own key and stored on the server,
// which can withhold it but cannot read or forge it.
async function loadContacts() {
  let list = E.emptyContacts(), rev = 0, problem = '';
  try {
    const r = await api('GET', '/api/v1/contacts');
    rev = r.revision;
    if (r.contacts) {
      try { list = await E.openContacts(S.acct, r.contacts); } catch {
        problem = 'Your list of verified people failed its integrity check and is being ignored. Verify people again, and tell your administrator.';
      }
    }
  } catch { problem = 'Your list of verified people could not be loaded.'; }
  S.contacts = { rev, list, problem };
  if (problem) toast(problem);
}
// saveContacts applies change() and saves. If another device saved first,
// the change is re-applied on top of that version instead of overwriting it.
async function saveContacts(change) {
  for (let attempt = 0; ; attempt++) {
    const next = structuredClone(S.contacts.list);
    change(next.contacts);
    try {
      const { revision } = await api('PUT', '/api/v1/contacts', { contacts: await E.sealContacts(S.acct, next), revision: S.contacts.rev });
      S.contacts = { rev: revision, list: next, problem: '' };
      return;
    } catch (e) {
      if (e.status !== 412 || attempt > 0) throw e;
      await loadContacts();
    }
  }
}
const nameOf = (pu) => pu.displayName || pu.email || 'this person';
function trust(pu) {
  return E.classifyContact(S.contacts?.list, { id: pu.id, fp: pu.fp, name: pu.displayName, email: pu.email });
}
function trustText(pu, t = trust(pu)) {
  switch (t.level) {
    case 'verified': return `You verified ${t.contact.name || nameOf(pu)} on ${new Date(t.contact.verifiedAt).toLocaleDateString()}.`;
    case 'changed': return 'This account’s keys are not the ones you verified. Keys never change, so someone is tampering with what the server shows you. Do not trust this account.';
    case 'lookalike': return `This is NOT ${t.contact.name || t.contact.email}, whom you verified: it is a different account with a similar name or email. It may be impersonating them.`;
    default: return 'You have not verified this person. Their name and email come from the server and could be faked; comparing fingerprints proves who they are.';
  }
}
const TRUST_LABEL = { verified: '✔ Verified', unverified: 'Not verified', changed: '⚠ Key changed', lookalike: '⚠ Possible impersonation' };
// trustBadge shows a person's status, with a Verify button when useful and,
// for warnings, the explanation in full (not only as a tooltip).
function trustBadge(pu, onChange) {
  if (!pu || pu.id === S.me.user.id) return null;
  const t = trust(pu);
  const badge = h('span', { class: `trust trust-${t.level}`, title: trustText(pu, t) }, TRUST_LABEL[t.level]);
  const btn = h('button', { class: 'link', onclick: async () => { if (await verifyDialog(pu)) (onChange || route)(); } }, t.level === 'verified' ? 'Details' : 'Verify…');
  const warn = t.level === 'changed' || t.level === 'lookalike';
  return h('span', { class: 'trust-wrap' }, badge, btn, warn ? h('div', { class: 'error' }, trustText(pu, t)) : null);
}
async function verifyDialog(pu) {
  const mine = await S.acct.fingerprint();
  const t = trust(pu);
  return new Promise((resolve) => {
    const finish = (v) => { resolve(v); d.close(); };
    const save = async (change, msg) => {
      try { await saveContacts(change); toast(msg); finish(true); } catch (e) { toast(e.message); }
    };
    const d = dialog(`Verify ${nameOf(pu)}`,
      h('p', {}, 'Compare fingerprints in person, or on a phone or video call where you recognise them. Not by chat or email: whoever controls the server could fake those too.'),
      h('p', { class: 'note' }, `${nameOf(pu)}${pu.email ? ` (${pu.email})` : ''} should see this under Settings → Encryption:`),
      h('div', { class: 'secret', 'data-fp': 'theirs' }, E.formatFingerprint(pu.fp)),
      h('p', { class: 'note' }, 'Yours, for them to check:'),
      h('div', { class: 'secret' }, E.formatFingerprint(mine)),
      h('p', { class: t.level === 'changed' || t.level === 'lookalike' ? 'error' : 'note' }, trustText(pu, t)),
      h('div', { class: 'row' },
        h('button', { type: 'button', onclick: () => finish(false) }, 'Cancel'),
        t.level === 'verified' && h('button', { type: 'button', class: 'danger', onclick: () => save((c) => { delete c[pu.id]; }, 'Verification removed') }, 'Remove verification'),
        t.level !== 'verified' && h('button', { type: 'button', class: 'primary', onclick: () => save((c) => {
          c[pu.id] = { fp: pu.fp, name: (pu.displayName || '').slice(0, 200), ...(pu.email ? { email: pu.email.slice(0, 320) } : {}), verifiedAt: Date.now() };
        }, `${nameOf(pu)} verified`) }, 'The fingerprints match')));
    d.addEventListener('cancel', () => resolve(false));
  });
}
// confirmList is confirmBox with a list of items (e.g. people) shown in full.
function confirmList(title, intro, items, ok) {
  return new Promise((resolve) => {
    const d = dialog(title, h('p', {}, intro), h('ul', { class: 'confirm-list' }, items.map((x) => h('li', {}, x))),
      h('form', { method: 'dialog', class: 'row' },
        h('button', { onclick: () => resolve(false) }, 'Cancel'), h('button', { class: 'primary', onclick: () => resolve(true) }, ok)));
    d.addEventListener('cancel', () => resolve(false));
  });
}

// ---- branding and appearance ------------------------------------------------------------------------------
// Colors come from /theme.css, which the server generates from validated
// tokens. This code never builds CSS or markup from data: it shows the brand
// name as text, points an <img> at the same-origin, re-encoded logo, and picks
// a mode and accent by setting two allowlisted attributes on <html>.
const APPEARANCE_KEY = 'frontdir.appearance';
const MODES = { system: 'Match system', light: 'Light', dark: 'Dark', contrast: 'High contrast' };
const ACCENT_RE = /^[a-z][a-z0-9-]{0,23}$/;
let branding = { name: 'FrontDir', logo: false, defaultAccent: '', accents: [] };

function loadAppearance() {
  try {
    const v = JSON.parse(localStorage.getItem(APPEARANCE_KEY) || 'null') || {};
    return {
      mode: Object.hasOwn(MODES, v.mode) ? v.mode : 'system',
      accent: typeof v.accent === 'string' && ACCENT_RE.test(v.accent) ? v.accent : '',
    };
  } catch { return { mode: 'system', accent: '' }; }
}
function applyAppearance(a) {
  const root = document.documentElement;
  if (a.mode === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', a.mode);
  // An accent the operator has since removed falls back to the default.
  if (a.accent && branding.accents.some((x) => x.id === a.accent)) root.setAttribute('data-accent', a.accent);
  else root.removeAttribute('data-accent');
}
function saveAppearance(a) {
  applyAppearance(a);
  try {
    if (a.mode === 'system' && !a.accent) localStorage.removeItem(APPEARANCE_KEY);
    else localStorage.setItem(APPEARANCE_KEY, JSON.stringify({ mode: a.mode, accent: a.accent }));
  } catch { toast('Applied for now, but this browser does not allow saving it.'); }
}
async function loadBranding() {
  try {
    const b = await api('GET', '/api/v1/branding');
    branding = {
      name: typeof b.name === 'string' && b.name ? b.name : 'FrontDir',
      logo: b.logo === true,
      defaultAccent: typeof b.defaultAccent === 'string' ? b.defaultAccent : '',
      accents: (Array.isArray(b.accents) ? b.accents : [])
        .filter((x) => x && typeof x.id === 'string' && ACCENT_RE.test(x.id))
        .map((x) => ({ id: x.id, label: String(x.label || x.id) })),
    };
  } catch { return; } // keep the built-in name and whatever theme-init.js applied
  document.getElementById('brand-name').textContent = branding.name;
  document.title = branding.name;
  if (branding.logo) {
    const img = document.getElementById('brand-logo');
    img.src = '/branding/logo';
    img.hidden = false;
  }
  applyAppearance(loadAppearance());
}

function appearanceSection() {
  const cur = loadAppearance();
  const note = h('p', { class: 'note' }, 'High contrast uses its own fixed colors, so the accent cannot be changed.');
  const accents = h('fieldset', {}, h('legend', {}, 'Accent color'), h('div', { class: 'choices' },
    branding.accents.map((a) => h('label', {},
      h('input', { type: 'radio', name: 'appearance-accent', value: a.id, checked: (cur.accent || branding.defaultAccent) === a.id }),
      h('span', { class: 'swatch', 'data-accent': a.id, 'aria-hidden': 'true' }), a.label))), note);
  const modes = h('fieldset', {}, h('legend', {}, 'Mode'), h('div', { class: 'choices' },
    Object.entries(MODES).map(([id, label]) => h('label', {},
      h('input', { type: 'radio', name: 'appearance-mode', value: id, checked: cur.mode === id }), label))));
  const sync = () => {
    const mode = modes.querySelector('input:checked')?.value || 'system';
    accents.disabled = mode === 'contrast';
    note.hidden = mode !== 'contrast';
  };
  const onChange = () => {
    const mode = modes.querySelector('input:checked')?.value || 'system';
    const picked = accents.querySelector('input:checked')?.value || '';
    saveAppearance({ mode, accent: picked === branding.defaultAccent ? '' : picked });
    sync();
  };
  modes.addEventListener('change', onChange);
  accents.addEventListener('change', onChange);
  sync();
  return [h('h2', {}, 'Appearance'),
    h('p', { class: 'note' }, 'Saved in this browser only.'),
    modes, branding.accents.length ? accents : null,
    h('div', { class: 'toolbar' }, h('button', { onclick: () => { saveAppearance({ mode: 'system', accent: '' }); settingsView(); } }, 'Reset to default'))];
}

// ---- routing ------------------------------------------------------------------------------------
function navigate(path) { history.pushState(null, '', path); route(); }
document.addEventListener('click', (e) => {
  const a = e.target.closest('a[data-nav]');
  if (a && !e.metaKey && !e.ctrlKey && !e.shiftKey) { e.preventDefault(); navigate(a.getAttribute('href')); }
});
window.addEventListener('popstate', route);

async function route() {
  const path = location.pathname;
  if (path === '/s') return publicLink();
  if (path === '/setup') return setupView();
  try {
    if (!S.me) {
      try { S.me = await api('GET', '/api/v1/me'); } catch (e) { if (e.status === 401) return signIn(); throw e; }
    }
    document.getElementById('nav-admin').hidden = !S.me.user.admin;
    // The admin area needs no encryption keys: an administrator can
    // configure the server before (or without) setting up their own files.
    if (path === '/admin' || path.startsWith('/admin/')) {
      if (!S.me.user.admin) return navigate('/');
      document.getElementById('nav').hidden = false;
      markNav(path);
      return await adminView(path.split('/')[2] || 'people');
    }
    if (!S.me.user.keys) return setupKeys();
    if (!S.acct) return unlockScreen();
    if (!S.contacts) await loadContacts();
    document.getElementById('nav').hidden = false;
    renderQuota();
    markNav(path);
    if (path === '/shared') return await sharedWithMeView();
    if (path === '/shared/by-me') return await sharedByMeView();
    if (path === '/teams') return await teamsView();
    if (path.startsWith('/teams/')) return await teamView(path.split('/')[2]);
    if (path === '/trash' || path.startsWith('/trash/')) return await trashView(path.split('/')[2] || S.me.personalSpace.id);
    if (path === '/settings') return await settingsView();
    const m = path.match(/^\/f\/([0-9a-f]{32})$/);
    return await folderView(m ? m[1] : S.me.personalSpace.rootId);
  } catch (e) {
    if (e.status === 401) { S.me = null; return signIn(); }
    main.replaceChildren(h('div', { class: 'panel center' }, h('p', { class: 'error' }, e.message)));
  }
}
function markNav(path) {
  for (const a of document.querySelectorAll('#nav a')) a.classList.toggle('active', path === a.getAttribute('href') || (a.getAttribute('href') !== '/' && path.startsWith(a.getAttribute('href'))));
}
async function refreshMe() {
  S.me = await api('GET', '/api/v1/me');
  renderQuota();
}
function renderQuota() {
  const q = document.getElementById('quota');
  const u = S.me.user, sp = S.me.personalSpace;
  q.hidden = false;
  q.textContent = `${u.displayName || u.email || ''} · ${fmtSize(sp.usedBytes)} of ${fmtSize(sp.quotaBytes)}` + (u.admin ? ' · admin' : '');
}

// ---- sign in, key setup, unlock ---------------------------------------------------------------------
async function signIn() {
  const err = new URLSearchParams(location.search).get('error');
  const methods = await api('GET', '/api/v1/auth/methods').catch(() => ({ oidc: true }));
  const rt = encodeURIComponent(location.pathname === '/' ? '/' : location.pathname);
  if (methods.setup) {
    return main.replaceChildren(h('div', { class: 'panel center narrow' },
      h('h1', {}, branding.name), h('p', {}, 'This server is not set up yet: no sign-in method is configured.'),
      h('p', { class: 'note' }, 'The person who runs the server can create a one-time setup link by running ',
        h('code', {}, 'frontdir setup-link'), ' on the server (for Docker Compose: ',
        h('code', {}, 'docker compose exec frontdir frontdir setup-link'), ').')));
  }
  main.replaceChildren(h('div', { class: 'panel center' },
    h('h1', {}, branding.name), h('p', {}, 'Private, end-to-end encrypted file storage.'),
    err && h('p', { class: 'error' }, err === 'not_allowed' ? `Your account is not permitted to use ${branding.name}.` : 'Sign-in failed. Please try again.'),
    h('div', { class: 'toolbar centered' },
      methods.oidc && h('a', { class: 'button primary', href: `/auth/login?return_to=${rt}` }, 'Sign in'),
      methods.saml && h('a', { class: 'button' + (methods.oidc ? '' : ' primary'), href: `/auth/saml/login?return_to=${rt}` }, 'Sign in with SAML'))));
}

function setupKeys() {
  const p1 = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: E.MIN_PASSPHRASE });
  const p2 = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  const msg = h('p', { class: 'error' });
  main.replaceChildren(h('div', { class: 'panel narrow' },
    h('h1', {}, 'Set up encryption'),
    h('p', {}, 'Your files are encrypted on this device before upload. Choose an encryption passphrase: it unlocks your keys and is never sent to the server.'),
    h('p', { class: 'note' }, 'It is separate from your sign-in password. Use at least 12 characters; a few random words work well.'),
    h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      if (p1.value !== p2.value) { msg.textContent = 'The passphrases do not match.'; return; }
      msg.textContent = '';
      const b = busy('Generating keys…');
      try {
        const { account, bundle, recoveryCode } = await E.newAccount(S.me.user.id, p1.value);
        const sp = S.me.personalSpace;
        const space = await account.personalSpace(sp.id);
        const root = await E.NodeKey.fresh();
        await api('POST', '/api/v1/keys', { bundle: JSON.stringify(bundle), personalSpace: {
          publicKey: E.b64u(space.publicKey), keySig: await E.signSpaceKey(account, sp.id, space.publicKey), rootKey: await space.wrapRoot(sp.rootId, root) } });
        b.close();
        await showRecoveryCode(recoveryCode);
        S.acct = account;
        S.bundle = bundle;
        await refreshMe();
        route();
      } catch (err) { b.close(); msg.textContent = err.message; }
    } }, h('label', {}, 'Passphrase', p1), h('label', {}, 'Repeat passphrase', p2), msg, h('button', { class: 'primary' }, 'Create my keys'))));
}

function showRecoveryCode(code) {
  return new Promise((resolve) => {
    const check = h('input', { placeholder: 'last 4 characters', required: true, autocomplete: 'off' });
    const err = h('p', { class: 'error' });
    const d = dialog('Save your recovery code',
      h('p', {}, 'If you forget your passphrase, this code is the only way back into your files. Nobody, including the administrator, can recover them for you.'),
      h('div', { class: 'secret' }, code),
      h('p', { class: 'note' }, 'Write it down or store it in a password manager, away from this device.'),
      h('div', { class: 'row' },
        h('button', { type: 'button', onclick: () => saveBlob(new Blob([`FrontDir recovery code for ${S.me.user.email || S.me.user.id}\n${code}\n`], { type: 'text/plain' }), 'frontdir-recovery-code.txt') }, 'Download as file')),
      h('form', { class: 'stack', onsubmit: (e) => {
        e.preventDefault();
        if (check.value.trim().toUpperCase() !== code.slice(-4)) { err.textContent = 'That does not match. Check the code you saved.'; return; }
        d.close();
        resolve();
      } }, h('label', {}, 'To confirm, type the last 4 characters of the code', check), err, h('button', { class: 'primary' }, 'I have saved it')));
    d.addEventListener('cancel', (e) => e.preventDefault());
  });
}

function unlockScreen() {
  let recovery = false;
  const input = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const label = h('span', {}, 'Encryption passphrase');
  const msg = h('p', { class: 'error' });
  const toggle = h('button', { type: 'button', class: 'link', onclick: () => {
    recovery = !recovery;
    label.textContent = recovery ? 'Recovery code' : 'Encryption passphrase';
    input.type = recovery ? 'text' : 'password';
    toggle.textContent = recovery ? 'Use my passphrase' : 'Forgot passphrase? Use recovery code';
  } }, 'Forgot passphrase? Use recovery code');
  main.replaceChildren(h('div', { class: 'panel narrow' },
    h('h1', {}, 'Unlock your files'),
    h('p', { class: 'note' }, 'Your keys are decrypted here, in this browser tab, and are forgotten when you close it.'),
    h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      msg.textContent = '';
      const b = busy('Unlocking…');
      try {
        const { bundle } = await api('GET', '/api/v1/keys');
        S.bundle = JSON.parse(bundle);
        if (S.bundle.userId !== S.me.user.id) throw new Error('Key bundle belongs to another user');
        S.acct = recovery ? await E.unlockWithRecoveryCode(S.bundle, input.value) : await E.unlock(S.bundle, input.value);
        b.close();
        if (recovery) {
          const np = await prompt('Choose a new passphrase', 'New encryption passphrase (12+ characters)', '', 'password');
          if (np) await changePassphrase(np);
        }
        route();
      } catch (err) { b.close(); msg.textContent = err.message; }
    } }, h('label', {}, label, input), msg, h('div', { class: 'row' }, toggle, h('button', { class: 'primary' }, 'Unlock')))));
  input.focus();
}

async function changePassphrase(np) {
  const nb = await E.changePassphrase(S.acct, S.bundle, np);
  await api('PUT', '/api/v1/keys', { bundle: JSON.stringify(nb) });
  S.bundle = nb;
  toast('Passphrase changed');
}

// ---- folders -----------------------------------------------------------------------------------------
async function listChildren(id) {
  const key = await nodeKey(id);
  let cursor = '', node = null;
  const out = [];
  do {
    const page = await api('GET', `/api/v1/nodes/${id}/children?limit=1000${cursor ? `&cursor=${cursor}` : ''}`);
    node = page.node;
    for (const c of page.children) {
      try { c.name = await key.decryptName(c.id, c.nameEnc); } catch { c.name = '⚠ undecryptable item'; c.bad = true; }
      out.push(c);
    }
    cursor = page.nextCursor;
  } while (cursor);
  out.sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'folder' ? -1 : 1));
  return { node, children: out };
}

async function folderView(id) {
  const where = await pathTo(id);
  const { node, children } = await listChildren(id);
  const canWrite = ['owner', 'write'].includes(node.permission);
  const crumbs = [];
  where.trail.forEach((t, i) => {
    if (i) crumbs.push(h('span', { class: 'sep' }, '/'));
    crumbs.push(i === where.trail.length - 1 ? h('strong', {}, t.name) : h('a', { href: `/f/${t.id}`, 'data-nav': '' }, t.name));
  });
  const ctx = { folderId: id, space: where.space, node };
  const rows = children.map((c) => fileRow(c, ctx));
  const panel = h('div', { class: 'panel dropzone' },
    h('div', { class: 'toolbar' }, h('div', { class: 'crumbs' }, ...crumbs),
      canWrite && children.some((c) => c.kind === 'file' && !c.hasThumbnail && thumbable(c.name)) &&
        h('button', { title: 'Make previews for the images and videos here. Others see previews you make only on files you uploaded.',
          onclick: () => makeThumbnails(ctx, children) }, 'Make thumbnails'),
      canWrite && h('button', { onclick: () => newFolder(ctx) }, 'New folder'),
      canWrite && h('button', { onclick: async () => restoreBackups(ctx, await pickFiles('.fdenc,.ndne')) }, 'Restore backup…'),
      canWrite && h('button', { class: 'primary', onclick: async () => uploadMany(ctx, await pickFiles('')) }, 'Upload')),
    h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Size'), h('th', {}, 'Modified'), h('th', {}))),
      h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 4, class: 'empty' }, 'This folder is empty.')))));
  if (canWrite) {
    panel.addEventListener('dragover', (e) => { e.preventDefault(); panel.classList.add('over'); });
    panel.addEventListener('dragleave', () => panel.classList.remove('over'));
    panel.addEventListener('drop', (e) => { e.preventDefault(); panel.classList.remove('over'); uploadMany(ctx, Array.from(e.dataTransfer.files)); });
  }
  main.replaceChildren(panel);
}

function fileRow(c, ctx) {
  const canModify = ['owner', 'write'].includes(ctx.node.permission);
  const isOwner = ctx.node.permission === 'owner';
  const name = c.kind === 'folder'
    ? h('a', { href: `/f/${c.id}`, 'data-nav': '' }, c.name)
    : h('a', { href: '#', onclick: (e) => { e.preventDefault(); downloadFile(c); } }, c.name);
  return h('tr', {},
    h('td', {}, h('div', { class: 'name' }, c.kind === 'folder' ? h('span', { class: 'icon', 'aria-hidden': 'true' }, '📁') : thumbSlot(c), name)),
    h('td', { class: 'num' }, c.kind === 'file' ? fmtSize(c.plainSize) : ''),
    h('td', { class: 'num' }, fmtDate(c.modifiedAt)),
    h('td', { class: 'actions' },
      !c.bad && isOwner && h('button', { class: 'link', onclick: () => shareDialog(c) }, 'Share'),
      !c.bad && c.kind === 'file' && h('button', { class: 'link', title: 'Download the encrypted file; restore it later with “Restore backup”', onclick: () => backupFile(c) }, 'Backup'),
      !c.bad && c.kind === 'file' && h('button', { class: 'link', onclick: () => versionsDialog(c) }, 'Versions'),
      !c.bad && canModify && h('button', { class: 'link', onclick: () => renameNode(c, ctx) }, 'Rename'),
      !c.bad && canModify && h('button', { class: 'link danger', onclick: () => trashNode(c, ctx) }, 'Delete')));
}

async function act(fn, ok) {
  try { await fn(); if (ok) toast(ok); } catch (e) { toast(e.message); }
  await refreshMe().catch(() => {});
  route();
}

async function newFolder(ctx) {
  const name = await prompt('New folder', 'Name');
  if (!name) return;
  const bad = E.validateName(name);
  if (bad) return toast(bad);
  await act(async () => {
    const id = E.newId(), nk = await E.NodeKey.fresh();
    const entry = await (await nodeKey(ctx.folderId)).entry(id, name, nk);
    await api('POST', `/api/v1/nodes/${ctx.folderId}/folders`, { id, ...entry });
    S.keys.set(id, nk);
  }, 'Folder created');
}

// ---- signed version history (E2EE.md §5c) ------------------------------------------------------------
// Every version carries a record signed by whoever stored it, chained to
// the one before. This browser remembers, per file, the newest record it
// verified, and notices if the server later shows a history that ends
// earlier (gone back in time) or differs (a fork). The memory stays on
// this device on purpose: kept on the server, it could be rolled back too.
const SEEN_MAX = 20000;
const seenKey = () => `frontdir.seen.${S.me.user.id}`;
function seenAll() {
  try { return JSON.parse(localStorage.getItem(seenKey()) || '{}') || {}; } catch { return {}; }
}
const seenGet = (nodeId) => seenAll()[nodeId] || null;
function seenSet(nodeId, value) {
  try {
    const all = seenAll();
    delete all[nodeId]; // re-insert: insertion order is recency
    if (value) all[nodeId] = value;
    const ids = Object.keys(all);
    for (const old of ids.slice(0, Math.max(0, ids.length - SEEN_MAX))) delete all[old];
    localStorage.setItem(seenKey(), JSON.stringify(all));
  } catch { /* storage unavailable: nothing remembered on this device */ }
}
function remember(nodeId, head, force = false) {
  const cur = seenGet(nodeId);
  if (force || !cur || head.rec.seq > cur.seq) seenSet(nodeId, E.seenOf(head));
}

// loadHistory fetches a file's versions and checks their signed history
// and its freshness. With accept, an internally sound history is
// remembered as it is (after a rollback or fork warning).
async function loadHistory(nodeId, accept = false) {
  const data = await api('GET', `/api/v1/nodes/${nodeId}/versions`);
  const entries = [];
  let err = null;
  for (const v of data.versions) {
    const e = { v, prefix: v.prefix ? E.unb64u(v.prefix) : null, record: null };
    if (v.record) { try { e.record = await E.parseVersionRecord(v.record, v.recordSig); } catch (x) { err = err || x; } }
    entries.push(e);
  }
  let head = null;
  if (!err) { try { head = await E.verifyHistory(nodeId, entries, userKeys); } catch (x) { err = x; } }
  if (!err && !accept) {
    try { E.checkFresh(seenGet(nodeId), entries.filter((e) => e.record).map((e) => e.record)); } catch (x) { err = x; }
  }
  if (!err && head) remember(nodeId, head, accept);
  if (!err && !head && accept) seenSet(nodeId, null);
  return { data, entries, head, err };
}

// newRecord signs the record for a new version of nodeId (the first, for
// a new file). It refuses to build on a history that does not check out.
async function newRecord(nodeId, container, kind, isNew) {
  const { prefix } = await E.parseContainer(container);
  let seq = 1, prev = '';
  if (!isNew) {
    const hs = await loadHistory(nodeId);
    if (hs.err) throw new Error(`Not saved: ${hs.err.message} Open Versions to review it.`);
    if (hs.head) { seq = hs.head.rec.seq + 1; prev = E.b64u(hs.head.hash); }
  }
  return E.signVersionRecord(S.acct, { node: nodeId, seq, prev, container: await E.containerId(prefix), kind });
}
const recordHeaders = (r) => ({ 'X-FrontDir-Record': E.b64u(r.raw), 'X-FrontDir-Record-Sig': E.b64u(r.sig) });

// checkServed checks the record served with a file's current content.
async function checkServed(nodeId, headers, prefix) {
  const seen = seenGet(nodeId);
  const raw = headers.get('X-FrontDir-Record');
  if (!raw) { if (seen) throw E.rolledBackError(); return; }
  const r = await E.parseVersionRecord(raw, headers.get('X-FrontDir-Record-Sig') || '');
  await E.verifyHistory(nodeId, [{ prefix, record: r }], userKeys);
  if (!E.checkFreshHead(seen, r)) { // more than one version on: check the chain in between
    const hs = await loadHistory(nodeId);
    if (hs.err) throw hs.err;
    return;
  }
  remember(nodeId, r);
}
const historyMsg = (e) => (['rolledback', 'forked', 'history'].includes(e.code) ? `${e.message} Open Versions to review it.` : e.message);

async function encryptFor(ctx, blob, nk, name, onProgress) {
  return E.encryptFile(blob, { nk, spaceId: ctx.space.id, spacePub: await spacePub(ctx.space),
    meta: { name, type: blob.type || 'application/octet-stream', mtime: blob.lastModified || Date.now() }, signer: S.acct }, onProgress);
}

async function uploadMany(ctx, files) {
  for (const file of files) {
    const bad = E.validateName(file.name);
    if (bad) { toast(`${file.name}: ${bad}`); continue; }
    const b = busy(`Encrypting and uploading ${file.name}…`);
    try {
      const id = E.newId(), nk = await E.NodeKey.fresh();
      const entry = await (await nodeKey(ctx.folderId)).entry(id, file.name, nk);
      const container = await encryptFor(ctx, file, nk, file.name, (f) => b.set(f / 2));
      const rec = await newRecord(id, container, 'save', true);
      try {
        const node = await send('POST', `/api/v1/nodes/${ctx.folderId}/files`, container,
          { 'Content-Type': 'application/octet-stream', 'X-FrontDir-Entry': JSON.stringify({ id, ...entry }), ...recordHeaders(rec) }, (f) => b.set(0.5 + f / 2));
        S.keys.set(id, nk);
        remember(id, rec);
        await attachThumb(id, node?.versionId, container, nk, file, file.name);
      } catch (e) {
        if (e.status !== 409 || e.detail.existingKind !== 'file') throw e;
        b.close();
        if (!(await confirmBox('File exists', `“${file.name}” already exists. Upload as a new version?`, 'Upload new version'))) continue;
        const existing = e.detail.existingId;
        const ek = await nodeKey(existing);
        const v = await encryptFor(ctx, file, ek, file.name);
        const vrec = await newRecord(existing, v, 'save', false);
        const node = await send('PUT', `/api/v1/nodes/${existing}/content`, v, { 'Content-Type': 'application/octet-stream', ...recordHeaders(vrec) });
        remember(existing, vrec);
        await attachThumb(existing, node?.versionId, v, ek, file, file.name);
      }
    } catch (e) { toast(`${file.name}: ${e.message}`); } finally { b.close(); }
  }
  await refreshMe().catch(() => {});
  route();
}

// downloadFile saves a file (or an older version). The current version is
// checked against the history this browser has seen before.
async function downloadFile(c, versionId) {
  const path = `/api/v1/nodes/${c.id}/content${versionId ? `?version=${versionId}` : ''}`;
  await decryptAndSave(c.name, c.plainSize, () => fetch(path, { credentials: 'same-origin' }), await nodeKey(c.id), signerFor,
    versionId ? null : c.id);
}

// ---- thumbnails (E2EE.md §5a) --------------------------------------------------------------------------------
// Made on this device from the plaintext when a file is uploaded (or with
// "Make thumbnails"), re-encoded so no photo metadata survives, encrypted
// for that one version and signed. Shown only if made by the version's
// author or by you, and only ever as an <img> of a WebP or JPEG.
const THUMB_SIDE = 256;
const THUMB_MAX_SOURCE = 256 * 1024 * 1024;
const IMAGE_EXT = /\.(jpe?g|png|gif|webp|avif|bmp)$/i;
const VIDEO_EXT = /\.(mp4|m4v|mov|webm|ogv)$/i;
const thumbable = (name) => IMAGE_EXT.test(name) || VIDEO_EXT.test(name);

// videoFrame grabs a frame about a second in (or 10% into a short clip).
function videoFrame(blob) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(blob);
    const v = document.createElement('video');
    v.muted = true;
    v.preload = 'auto';
    v.playsInline = true;
    let finished = false;
    const done = (err, val) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      URL.revokeObjectURL(url);
      v.removeAttribute('src');
      v.load();
      if (err) reject(err); else resolve(val);
    };
    const timer = setTimeout(() => done(new Error('video did not load in time')), 8000);
    v.addEventListener('error', () => done(new Error('this browser cannot play the video')));
    v.addEventListener('loadedmetadata', () => { v.currentTime = Math.min(1, (v.duration || 0) * 0.1); });
    v.addEventListener('seeked', () => createImageBitmap(v).then((bmp) => done(null, bmp), done));
    v.src = url;
  });
}

// renderThumb returns { type, w, h, bytes } or null if no preview can be made.
async function renderThumb(blob, name) {
  let bmp;
  try {
    if (IMAGE_EXT.test(name)) bmp = await createImageBitmap(blob, { imageOrientation: 'from-image' });
    else if (VIDEO_EXT.test(name)) bmp = await videoFrame(blob);
    else return null;
    const scale = Math.min(1, THUMB_SIDE / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale)), ht = Math.max(1, Math.round(bmp.height * scale));
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = ht;
    canvas.getContext('2d').drawImage(bmp, 0, 0, w, ht);
    for (const [type, q] of [['image/webp', 0.75], ['image/jpeg', 0.8], ['image/jpeg', 0.5]]) {
      const out = await new Promise((r) => canvas.toBlob(r, type, q));
      if (out && out.type === type && out.size <= E.MAX_THUMB_BYTES) return { type, w, h: ht, bytes: new Uint8Array(await out.arrayBuffer()) };
    }
  } catch { /* no preview for this file */ } finally { bmp?.close?.(); }
  return null;
}

// attachThumb makes and uploads a thumbnail for a version just written (or
// downloaded). Failures are silent: a missing preview is not an error.
async function attachThumb(nodeId, versionId, container, nk, source, name) {
  if (!versionId || !thumbable(name) || source.size > THUMB_MAX_SOURCE) return false;
  try {
    const t = await renderThumb(source, name);
    if (!t) return false;
    const header = E.parsePrefix(new Uint8Array(await container.slice(0, 12 + 65536).arrayBuffer()));
    await api('PUT', `/api/v1/nodes/${nodeId}/thumbnail`, { versionId, ...(await E.sealThumb(S.acct, nodeId, header, nk, t)) });
    return true;
  } catch { return false; }
}

async function makeThumbnails(ctx, children) {
  const todo = children.filter((c) => c.kind === 'file' && !c.hasThumbnail && thumbable(c.name) && c.plainSize <= THUMB_MAX_SOURCE);
  const b = busy(`Making thumbnails (0 of ${todo.length})…`);
  let made = 0;
  for (const [i, c] of todo.entries()) {
    b.set(i / todo.length);
    try {
      const container = await apiBlob(`/api/v1/nodes/${c.id}/content?version=${c.versionId}`);
      const nk = await nodeKey(c.id);
      const res = await E.decryptFile(container, nk, signerFor); // verified before anything is rendered
      if (await attachThumb(c.id, c.versionId, container, nk, res.blob, c.name)) made++;
    } catch { /* skip this one */ }
  }
  b.close();
  toast(`Made ${made} thumbnail${made === 1 ? '' : 's'}${made < todo.length ? `; ${todo.length - made} could not be previewed` : ''}`);
  route();
}

// Display: only rows on screen load, at most four at a time; previews are
// cached per version and released when evicted or when you lock.
const thumbCache = new Map(); // versionId -> object URL ('' if none)
const thumbWaiting = [];
let thumbBusy = 0;
function clearThumbs() {
  for (const url of thumbCache.values()) if (url) URL.revokeObjectURL(url);
  thumbCache.clear();
}
const thumbObserver = 'IntersectionObserver' in window ? new IntersectionObserver((entries) => {
  for (const e of entries) {
    if (!e.isIntersecting) continue;
    thumbObserver.unobserve(e.target);
    thumbWaiting.push(e.target);
  }
  pumpThumbs();
}, { rootMargin: '200px' }) : null;

function thumbSlot(c) {
  const icon = h('span', { class: 'icon', 'aria-hidden': 'true' }, '📄');
  if (!c.hasThumbnail || !c.versionId || !thumbObserver) return icon;
  icon.fileNode = c;
  const cached = thumbCache.get(c.versionId);
  if (cached) return thumbImg(cached);
  if (cached === undefined) thumbObserver.observe(icon);
  return icon;
}
const thumbImg = (url) => h('img', { class: 'thumb', src: url, alt: '', loading: 'lazy', decoding: 'async' });

async function pumpThumbs() {
  while (thumbBusy < 4 && thumbWaiting.length) {
    const slot = thumbWaiting.shift();
    thumbBusy++;
    loadThumb(slot.fileNode).then((url) => {
      if (url && slot.isConnected) slot.replaceWith(thumbImg(url));
    }).finally(() => { thumbBusy--; pumpThumbs(); });
  }
}

async function loadThumb(c) {
  if (thumbCache.has(c.versionId)) return thumbCache.get(c.versionId);
  let url = '';
  try {
    const r = await api('GET', `/api/v1/nodes/${c.id}/thumbnail`);
    const prefix = E.unb64u(r.prefix);
    const header = E.parsePrefix(prefix);
    const nk = await nodeKey(c.id);
    const me = S.me.user.id;
    // The author counts only once their signature over this version
    // verifies (E2EE.md §5b); otherwise only your own thumbnail is shown.
    let author = null;
    if (r.bodyHash && r.trailer) {
      try { author = (await E.versionAuthor(nk, prefix, E.unb64u(r.bodyHash), E.unb64u(r.trailer), userKeys)).signer; } catch { /* unverified */ }
    }
    outer: for (const want of author ? [author.id, me] : [me]) { // the author's first, then your own
      for (const t of r.thumbnails) {
        if (t.maker !== want) continue;
        try {
          const maker = await userKeys(t.maker);
          if (!E.thumbAuthorOK(author, maker, me)) continue;
          const th = await E.openThumb(maker, c.id, header, nk, t);
          url = URL.createObjectURL(new Blob([th.bytes], { type: th.type }));
          break outer;
        } catch { /* not this one */ }
      }
    }
  } catch { /* no preview */ }
  thumbCache.set(c.versionId, url);
  if (thumbCache.size > 500) { // evict the oldest
    const [k, old] = thumbCache.entries().next().value;
    thumbCache.delete(k);
    if (old) URL.revokeObjectURL(old);
  }
  return url;
}

// ---- saving decrypted files --------------------------------------------------------------------------------
// Small files are decrypted in memory and verified completely before they
// are offered. Large ones are streamed to disk through the download worker
// (/dl/sw.js): each chunk is released once AES-GCM authenticates it, and
// the last only after the author's signature over every chunk verifies;
// if anything fails the download is aborted and the browser discards the
// partial file. Without the worker (private windows in some browsers),
// large files fall back to memory.
const STREAM_FROM = 64 * 1024 * 1024;
const MEMORY_WARNING = 1536 * 1024 * 1024;

async function decryptAndSave(name, size, fetchContainer, nk, signerFn, historyOf = null) {
  if (size >= STREAM_FROM && await streamToDisk(name, fetchContainer, nk, signerFn, historyOf)) return;
  if (size >= MEMORY_WARNING && !(await confirmBox('Large file', `${name} is ${fmtSize(size)}. This browser cannot save it as a stream, ` +
    'so it has to fit in memory and may fail. frontdir-cli (get, or mount) handles files of any size.', 'Try anyway'))) return;
  const b = busy(`Downloading and decrypting ${name}…`);
  try {
    const r = await fetchContainer();
    if (!r.ok) throw new ApiError(r.status, await r.json().catch(() => null));
    const blob = await r.blob();
    if (historyOf) await checkServed(historyOf, r.headers, (await E.parseContainer(blob)).prefix);
    const res = await E.decryptFile(blob, nk, signerFn, (f) => b.set(f));
    saveBlob(res.blob, name);
  } catch (e) { toast(`${name}: ${historyMsg(e)}`); } finally { b.close(); }
}

// The one Trusted Types policy the page's CSP allows ("frontdir-sw"):
// registering a service worker needs a TrustedScriptURL, and this policy
// can only ever produce the download worker's constant URL. It makes no
// HTML, no script and no other URL, and it can be created only once.
const SW_URL = '/dl/sw.js';
let swPolicy;
function workerScriptURL() {
  if (!window.trustedTypes) return SW_URL;
  swPolicy = swPolicy || window.trustedTypes.createPolicy('frontdir-sw', {
    createScriptURL: (u) => { if (u !== SW_URL) throw new TypeError('only the download worker may be loaded'); return u; },
  });
  return swPolicy.createScriptURL(SW_URL);
}

let dlWorker = null;
function downloadWorker() {
  if (!dlWorker) {
    dlWorker = (async () => {
      if (!('serviceWorker' in navigator) || !window.isSecureContext) return null;
      const reg = await navigator.serviceWorker.register(workerScriptURL(), { scope: '/dl/', updateViaCache: 'none' });
      const w = reg.active || reg.waiting || reg.installing;
      if (w && w.state !== 'activated') {
        await new Promise((resolve, reject) => {
          const t = setTimeout(() => reject(new Error('download worker did not start')), 10000);
          w.addEventListener('statechange', () => {
            if (w.state === 'activated') { clearTimeout(t); resolve(); }
            if (w.state === 'redundant') { clearTimeout(t); reject(new Error('download worker failed')); }
          });
        });
      }
      return reg.active;
    })().catch(() => null);
  }
  return dlWorker;
}

// streamToDisk returns false if streaming is unavailable (nothing was
// saved), and true once it has handled the download, successfully or not.
async function streamToDisk(name, fetchContainer, nk, signerFn, historyOf) {
  const sw = await downloadWorker();
  if (!sw) return false;
  const b = busy(`Decrypting ${name} to your downloads… keep this tab open until it finishes.`);
  let dec;
  try {
    const r = await fetchContainer();
    if (!r.ok) throw new ApiError(r.status, await r.json().catch(() => null));
    const total = Number(r.headers.get('Content-Length')) || undefined;
    dec = await E.openContainerStream(r.body, nk, signerFn, total);
    if (historyOf) {
      try { await checkServed(historyOf, r.headers, dec.prefix); } catch (e) { dec.cancel(); throw e; }
    }
  } catch (e) {
    b.close();
    toast(`${name}: ${historyMsg(e)}`);
    return true;
  }
  const id = E.newId();
  const { port1, port2 } = new MessageChannel();
  let sent = 0, started = false;
  const outcome = new Promise((resolve) => {
    const startTimer = setTimeout(() => { if (!started) { dec.cancel(); resolve('not-started'); } }, 15000);
    port1.onmessage = async ({ data }) => {
      if (data.ready) { // the worker holds the stream: let the browser fetch it as a download
        const a = h('a', { href: `/dl/${id}`, hidden: true });
        document.body.append(a);
        a.click();
        a.remove();
      } else if (data.started) {
        started = true;
        clearTimeout(startTimer);
      } else if (data.pull) {
        try {
          const r = await dec.next();
          if (r.done) { port1.postMessage({ done: true }); resolve('done'); return; }
          sent += r.value.length;
          b.set(dec.size ? sent / dec.size : 1);
          port1.postMessage({ chunk: r.value }, [r.value.buffer]);
        } catch (e) {
          port1.postMessage({ error: e.message });
          resolve(e);
        }
      } else if (data.cancel || data.expired) {
        dec.cancel();
        resolve('cancelled');
      }
    };
  });
  sw.postMessage({ type: 'download', id, name, size: dec.size }, [port2]);
  const result = await outcome;
  b.close();
  port1.close();
  if (result === 'not-started') return false;
  if (result instanceof Error) toast(`${name}: download stopped, ${result.message}. The browser discards the partial file.`);
  else if (result === 'cancelled') toast(`${name}: download cancelled`);
  return true;
}

async function backupFile(c) {
  try {
    saveBlob(await apiBlob(`/api/v1/nodes/${c.id}/content`), `${c.name}.fdenc`);
    toast('Encrypted backup saved. It can be restored, or decrypted offline, with your keys.');
  } catch (e) { toast(e.message); }
}

// restoreBackups re-links backed-up containers, unchanged, into this folder.
async function restoreBackups(ctx, files) {
  for (const file of files) {
    try {
      const c = await E.parseContainer(file);
      if (c.header.owner.space !== ctx.space.id) throw new Error('This backup belongs to a different space; restore it there.');
      const nk = await E.ownerNodeKey(c, await openSpace(ctx.space));
      const res = await E.decryptFile(file, nk, signerFor); // verify everything before restoring
      let name = res.meta.name;
      for (;;) {
        const id = E.newId();
        const entry = await (await nodeKey(ctx.folderId)).entry(id, name, nk);
        const rec = await newRecord(id, file, 'restore', true); // stored again, from a backup
        try {
          await send('POST', `/api/v1/nodes/${ctx.folderId}/files`, file,
            { 'Content-Type': 'application/octet-stream', 'X-FrontDir-Entry': JSON.stringify({ id, ...entry }), ...recordHeaders(rec) });
          S.keys.set(id, nk);
          remember(id, rec);
          toast(`Restored ${name} (signed by ${res.signer.displayName || res.signer.id.slice(0, 8)})`);
          break;
        } catch (e) {
          if (e.status !== 409) throw e;
          name = await prompt('Name in use', 'Restore under a new name', `${name} (restored)`);
          if (!name) break;
        }
      }
    } catch (e) { toast(`${file.name}: ${e.message}`); }
  }
  await refreshMe().catch(() => {});
  route();
}

async function renameNode(c, ctx) {
  const name = await prompt('Rename', 'New name', c.name);
  if (!name || name === c.name) return;
  const bad = E.validateName(name);
  if (bad) return toast(bad);
  await act(async () => {
    const pk = await nodeKey(ctx.folderId);
    await api('PATCH', `/api/v1/nodes/${c.id}`, { nameEnc: await pk.encryptName(c.id, name), nameHash: await pk.nameHash(name), revision: c.revision });
  }, 'Renamed');
}

async function trashNode(c, ctx) {
  if (!(await confirmBox('Move to trash', `Move “${c.name}” to the trash?`, 'Move to trash'))) return;
  await act(async () => {
    const tk = await E.trashKey(S.acct, await spacePub(ctx.space), c.id, c.name, c.kind, await nodeKey(c.id));
    await api('POST', `/api/v1/nodes/${c.id}/trash`, { ...tk, revision: c.revision });
  }, 'Moved to trash');
}

async function versionsDialog(c) {
  let hs, nk;
  try {
    hs = await loadHistory(c.id);
    nk = await nodeKey(c.id);
  } catch (e) { return toast(e.message); }
  // Who wrote each version, checked from its signature without downloading
  // it (E2EE.md §5b), and who stored it and when, from its signed record
  // (§5c). A server cannot make these name the wrong person; at worst it
  // makes a check fail, which we show as a warning.
  const author = async (e) => {
    const v = e.v;
    if (!v.prefix || !v.bodyHash) return { pending: true };
    try {
      const { signer } = await E.versionAuthor(nk, e.prefix, E.unb64u(v.bodyHash), E.unb64u(v.trailer), userKeys);
      return { signer };
    } catch { return { failed: true }; }
  };
  const who = (pu) => (pu.id === S.me.user.id ? 'You' : nameOf(pu));
  const authors = await Promise.all(hs.entries.map(author));
  const reopen = () => { d.close(); versionsDialog(c); };
  const restore = async (e) => {
    d.close();
    await act(async () => {
      const cur = await loadHistory(c.id);
      if (cur.err) throw new Error(historyMsg(cur.err));
      const rec = await E.signVersionRecord(S.acct, { node: c.id, seq: cur.head ? cur.head.rec.seq + 1 : 1,
        prev: cur.head ? E.b64u(cur.head.hash) : '', container: await E.containerId(e.prefix), kind: 'restore' });
      await api('POST', `/api/v1/nodes/${c.id}/versions/${e.v.id}/restore`, { record: E.b64u(rec.raw), recordSig: E.b64u(rec.sig) });
      remember(c.id, rec);
    }, 'Version restored');
  };
  const rows = hs.entries.map((e, i) => {
    const a = authors[i], signed = e.record && e.storedBy;
    const when = h('td', {}, fmtDate(signed ? e.record.rec.at : e.v.createdAt), i === 0 ? ' (current)' : '',
      signed ? h('span', { class: 'note', title: 'Position in the file’s signed history' }, ` #${e.record.rec.seq}`)
        : h('span', { class: 'note', title: 'Saved before FrontDir signed each version’s history: this time comes from the server.' }, ' · server time'));
    let by;
    if (a.signer) {
      const restored = signed && e.record.rec.kind === 'restore' ? h('span', { class: 'note' }, ` · restored by ${who(e.storedBy)}`) : null;
      by = h('span', { class: 'version-author' }, who(a.signer), ' ', trustBadge(a.signer, reopen), restored);
    } else if (a.pending) {
      by = h('span', { class: 'note', title: 'This version was saved before FrontDir recorded what is needed to check its author. The server fills this in for older versions in the background.' }, 'Not checked yet');
    } else {
      by = h('span', { class: 'error', title: 'Its signature does not check out: it may have been altered on the server. Do not rely on its contents.' }, '⚠ Cannot verify who saved this');
    }
    return h('tr', {}, when, h('td', { 'data-label': 'By' }, by), h('td', { class: 'num' }, fmtSize(e.v.size)),
      h('td', { class: 'actions' },
        h('button', { class: 'link', onclick: () => downloadFile(c, e.v.id) }, 'Download'),
        i > 0 && !a.failed && !hs.err && e.prefix && h('button', { class: 'link', onclick: () => restore(e) }, 'Restore')));
  });
  let warning = null;
  if (hs.err) {
    const freshness = hs.err.code === 'rolledback' || hs.err.code === 'forked';
    const accept = async () => {
      if (!(await confirmBox('Accept this history?', 'Accept the history as the server shows it now? Do this only if you know why it changed, ' +
        'for example because your administrator restored the server from a backup. Until you do, this browser will not save over this file.', 'Accept'))) return;
      const res = await loadHistory(c.id, true);
      if (res.err) toast(res.err.message); else reopen();
    };
    warning = h('div', { class: 'banner history-warning', role: 'alert' },
      h('span', { class: 'error' }, `⚠ ${hs.err.message}`, freshness ? '' : ' Saving and restoring are disabled for this file.'),
      freshness && h('button', { onclick: accept }, 'Accept this history…'));
  }
  const head = h('thead', {}, h('tr', {}, h('th', {}, 'Saved'), h('th', {}, 'By'), h('th', { class: 'num' }, 'Size'), h('th', {})));
  const d = dialog(`Versions of ${c.name}`, warning, h('table', { class: 'versions' }, head, h('tbody', {}, rows)),
    h('form', { method: 'dialog', class: 'row' }, h('button', {}, 'Close')));
}

// ---- sharing ---------------------------------------------------------------------------------------------
async function shareDialog(c) {
  const list = h('tbody');
  const refresh = async () => {
    const { shares } = await api('GET', `/api/v1/nodes/${c.id}/shares`);
    const rows = [];
    for (const s of shares) {
      const who = s.type === 'link' ? 'Public link' : (await userKeys(s.recipientId).catch(() => ({})))?.displayName || s.recipientId.slice(0, 8);
      rows.push(h('tr', {}, h('td', {}, who),
        h('td', {}, s.permission, s.hasPassword ? ' · password' : '', s.expiresAt ? ` · expires ${fmtDate(s.expiresAt)}` : '', s.maxDownloads ? ` · ${s.downloads}/${s.maxDownloads}` : ''),
        h('td', { class: 'actions' }, h('button', { class: 'link danger', onclick: async () => { try { await api('DELETE', `/api/v1/shares/${s.id}`); await refresh(); } catch (e) { toast(e.message); } } }, 'Revoke'))));
    }
    list.replaceChildren(...(rows.length ? rows : [h('tr', {}, h('td', { class: 'note' }, 'Not shared yet.'))]));
  };
  const email = h('input', { type: 'email', placeholder: 'person@example.com', required: true });
  const perm = h('select', {}, h('option', { value: 'read' }, 'Can view'), h('option', { value: 'write' }, 'Can edit'));
  const pw = h('input', { type: 'password', placeholder: 'optional, 10+ characters', autocomplete: 'new-password' });
  const days = h('input', { type: 'number', min: 1, max: 365, value: 30 });
  const maxDl = h('input', { type: 'number', min: 0, value: 0 });
  const d = dialog(`Share “${c.name}”`, h('table', {}, list),
    h('h3', {}, 'Share with a person'),
    h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      try {
        const u = await api('GET', `/api/v1/users/lookup?email=${encodeURIComponent(email.value)}`);
        const recipient = await E.verifyUser(u.id, u.keys);
        recipient.displayName = u.displayName; recipient.email = u.email;
        const t = trust(recipient);
        if (t.level === 'changed') { toast(`Not shared. ${trustText(recipient, t)}`); return; }
        if (!(await confirmBox('Confirm recipient', `Share with ${nameOf(recipient)}${u.email ? ` (${u.email})` : ''}? Key fingerprint: ${E.formatFingerprint(recipient.fp)}. ${trustText(recipient, t)}`, t.level === 'lookalike' ? 'Share anyway' : 'Share'))) return;
        const shareId = E.newId();
        const sealed = await E.shareNode(S.acct, recipient, shareId, c.id, perm.value, c.name, await nodeKey(c.id));
        await api('POST', `/api/v1/nodes/${c.id}/shares`, { type: 'user', shareId, recipientId: recipient.id, permission: perm.value, ...sealed });
        email.value = '';
        await refresh();
        toast('Shared');
      } catch (err) { toast(err.message); }
    } }, h('label', {}, 'Email', email), h('label', {}, 'Permission', perm), h('div', { class: 'row' }, h('button', { class: 'primary' }, 'Share'))),
    h('h3', {}, 'Public link (read-only)'),
    h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      try {
        const secret = E.random(32), shareId = E.newId();
        const res = await api('POST', `/api/v1/nodes/${c.id}/shares`, { type: 'link', shareId, password: pw.value,
          linkKey: await E.linkKey(secret, shareId, c.id, c.name, await nodeKey(c.id)),
          expiresAt: new Date(Date.now() + Number(days.value) * 86400000).toISOString(), maxDownloads: Number(maxDl.value) });
        pw.value = '';
        await refresh();
        showSecret('Public link created', 'Copy it now: the decryption key is inside the link (after the #) and is never stored anywhere, so it cannot be shown again.', `${res.urlPrefix}.${E.b64u(secret)}`);
      } catch (err) { toast(err.message); }
    } }, h('label', {}, 'Password', pw), h('label', {}, 'Expires after (days)', days), h('label', {}, 'Download limit (0 = unlimited)', maxDl),
    h('div', { class: 'row' }, h('button', { class: 'primary' }, 'Create link'))),
    h('form', { method: 'dialog', class: 'row' }, h('button', {}, 'Close')));
  try { await refresh(); } catch (e) { toast(e.message); d.close(); }
}

// ---- shared ---------------------------------------------------------------------------------------------------
// One page, two tabs: what others shared with you, and what you shared.
function sharedTabs(active) {
  const tab = (href, label, id) => h('a', { href, 'data-nav': '', class: active === id ? 'active' : '', 'aria-current': active === id ? 'page' : null }, label);
  return h('nav', { class: 'tabs', 'aria-label': 'Shared' }, tab('/shared', 'Shared with me', 'with'), tab('/shared/by-me', 'Shared by me', 'by'));
}

async function sharedWithMeView() {
  const { items } = await api('GET', '/api/v1/shared-with-me');
  const rows = [];
  for (const it of items) {
    let name, err = '';
    try {
      const sh = await E.openShare(S.acct, await userKeys(it.share.createdBy), it.share);
      S.keys.set(it.share.nodeId, sh.nk);
      name = sh.name;
    } catch (e) { name = '⚠ unverifiable share'; err = e.message; }
    const sharerKeys = await userKeys(it.share.createdBy).catch(() => null);
    const sharer = sharerKeys ? nameOf(sharerKeys) : 'unknown';
    rows.push(h('tr', { title: err },
      h('td', {}, h('div', { class: 'name' }, h('span', { class: 'icon' }, it.node.kind === 'folder' ? '📁' : '📄'),
        err ? name : it.node.kind === 'folder' ? h('a', { href: `/f/${it.node.id}`, 'data-nav': '' }, name)
          : h('a', { href: '#', onclick: (e) => { e.preventDefault(); downloadFile({ ...it.node, name }); } }, name))),
      h('td', {}, `from ${sharer} `, trustBadge(sharerKeys)),
      h('td', {}, it.share.permission === 'write' ? 'Can edit' : 'Can view'),
      h('td', { class: 'actions' }, h('button', { class: 'link danger', onclick: async () => {
        if (await confirmBox('Leave share', `Remove “${name}” from your shared items?`, 'Leave')) await act(() => api('DELETE', `/api/v1/shares/${it.share.id}`), 'Removed');
      } }, 'Leave'))));
  }
  main.replaceChildren(h('div', { class: 'panel' }, h('h1', {}, 'Shared'), sharedTabs('with'),
    h('table', {}, h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { class: 'empty' }, 'Nothing has been shared with you yet.'))))));
}

const LINK_STATUS = { active: 'Active', expired: 'Expired', exhausted: 'Download limit reached', locked: 'Locked after wrong passwords' };

// mapLimit runs fn over items with at most n in flight.
async function mapLimit(items, n, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (next < items.length) { const k = next++; out[k] = await fn(items[k]); }
  }));
  return out;
}

// describeShared decrypts an item's name and location through the normal
// key path. The server cannot help: it only has the encrypted names.
async function describeShared(it) {
  if (!it.node) return { name: 'In the trash, or no longer available to you', where: '', ok: false };
  try {
    const names = (await pathTo(it.node.id)).trail.map((t) => t.name);
    return { name: names.at(-1), where: names.slice(0, -1).join(' / '), ok: true };
  } catch { return { name: 'Could not decrypt this item', where: '', ok: false }; }
}

async function sharedByMeView() {
  const { items, truncated } = await api('GET', '/api/v1/shared-by-me');
  const info = await mapLimit(items, 6, describeShared);
  const links = [], people = [];
  items.forEach((it, i) => (it.share.type === 'link' ? links : people).push({ ...it, ...info[i] }));

  const label = (x) => h('div', { class: 'name' },
    h('span', { class: 'icon' }, !x.node ? '•' : x.node.kind === 'folder' ? '📁' : '📄'),
    h('div', {}, x.ok && x.node.kind === 'folder' ? h('a', { href: `/f/${x.node.id}`, 'data-nav': '' }, x.name) : h('span', { class: x.ok ? '' : 'note' }, x.name),
      x.where ? h('div', { class: 'note' }, x.where) : null));
  const revoke = (x, title, text) => h('button', { class: 'link danger', onclick: async () => {
    if (await confirmBox(title, text, 'Revoke')) await act(() => api('DELETE', `/api/v1/shares/${x.share.id}`), 'Revoked');
  } }, 'Revoke');

  const linkRows = links.map((x) => {
    const st = Object.hasOwn(LINK_STATUS, x.share.status) ? x.share.status : 'active';
    return h('tr', {}, h('td', {}, label(x)),
      h('td', {}, h('span', { class: st === 'active' ? '' : 'note' }, LINK_STATUS[st])),
      h('td', { class: 'num', 'data-label': 'Created' }, fmtDate(x.share.createdAt)),
      h('td', { class: 'num', 'data-label': 'Expires' }, x.share.expiresAt ? fmtDate(x.share.expiresAt) : 'Never'),
      h('td', { class: 'num', 'data-label': 'Downloads' }, x.share.maxDownloads ? `${x.share.downloads || 0} of ${x.share.maxDownloads}` : String(x.share.downloads || 0)),
      h('td', { 'data-label': 'Protection' }, x.share.hasPassword ? 'Password' : 'None'),
      h('td', { class: 'actions' }, revoke(x, 'Revoke link', `The public link to “${x.name}” stops working immediately for everyone who has it.`)));
  });
  const peopleRows = await Promise.all(people.map(async (x) => {
    const pu = await userKeys(x.share.recipientId).catch(() => null);
    const who = pu ? nameOf(pu) : 'Unknown user';
    return h('tr', {}, h('td', {}, label(x)), h('td', {}, who, ' ', trustBadge(pu)),
      h('td', {}, x.share.permission === 'write' ? 'Can edit' : 'Can view'),
      h('td', { class: 'num', 'data-label': 'Shared' }, fmtDate(x.share.createdAt)),
      h('td', { class: 'actions' }, revoke(x, 'Stop sharing', `${who} loses access to “${x.name}”.`)));
  }));

  const killMine = h('button', { class: 'danger', disabled: links.length === 0, onclick: async () => {
    const what = links.length === 1 && !truncated ? 'Your public link stops' : `All ${links.length}${truncated ? '+' : ''} of your public links stop`;
    const ok = await confirmBox('Revoke all your public links?',
      `${what} working immediately, including any you have already sent. ` +
      'This cannot be undone; you can create new links later. Sharing with specific people is not affected.', 'Revoke all my links');
    if (!ok) return;
    try {
      const { revoked } = await api('POST', '/api/v1/links/revoke-all');
      toast(`Revoked ${revoked} public link${revoked === 1 ? '' : 's'}`);
    } catch (e) { toast(e.message); }
    route();
  } }, 'Revoke all my public links');

  // Columns marked with a leading '#' are numeric/date columns, right-aligned like their cells.
  const head = (...cols) => h('thead', {}, h('tr', {}, cols.map((c) => (c.startsWith('#') ? h('th', { class: 'num' }, c.slice(1)) : h('th', {}, c)))));
  main.replaceChildren(h('div', { class: 'panel' }, h('h1', {}, 'Shared'), sharedTabs('by'),
    truncated ? h('p', { class: 'note' }, `Showing your ${items.length} most recent shares.`) : null,
    h('div', { class: 'toolbar' }, h('h2', {}, 'Public links'), killMine),
    h('p', { class: 'note' }, 'A link’s address cannot be shown again: its decryption key exists only in the link itself and was never stored. To share again, create a new link.'),
    h('table', {}, linkRows.length ? head('Item', 'Status', '#Created', '#Expires', '#Downloads', 'Protection', '') : null,
      h('tbody', {}, linkRows.length ? linkRows : h('tr', {}, h('td', { class: 'empty' }, 'You have no public links.')))),
    h('h2', {}, 'Shared with people'),
    h('table', {}, peopleRows.length ? head('Item', 'With', 'Permission', '#Shared', '') : null,
      h('tbody', {}, peopleRows.length ? peopleRows : h('tr', {}, h('td', { class: 'empty' }, 'You have not shared anything with specific people.'))))));
}

// ---- team folders ------------------------------------------------------------------------------------------
async function teamsView() {
  const { spaces } = await api('GET', '/api/v1/spaces');
  const teams = spaces.filter((s) => s.kind === 'team');
  const cards = [];
  for (const sp of teams) {
    let locked = '';
    try { await openSpace(sp); } catch (e) { locked = e.message; }
    cards.push(h('tr', {},
      h('td', {}, h('div', { class: 'name' }, h('span', { class: 'icon' }, '👥'), locked ? h('span', { title: locked }, '🔒 Waiting for key') : h('a', { href: `/f/${sp.rootId}`, 'data-nav': '' }, spaceName(sp)))),
      h('td', {}, sp.role),
      h('td', { class: 'num' }, `${fmtSize(sp.usedBytes)} / ${fmtSize(sp.quotaBytes)}`),
      h('td', { class: 'actions' }, h('a', { href: `/teams/${sp.id}`, 'data-nav': '' }, 'Members'), ' ', ['write', 'manage'].includes(sp.role) && h('a', { href: `/trash/${sp.id}`, 'data-nav': '' }, 'Trash'))));
  }
  main.replaceChildren(h('div', { class: 'panel' },
    h('div', { class: 'toolbar' }, h('h1', { class: 'crumbs' }, 'Team folders'),
      h('button', { class: 'primary', onclick: async () => {
        const name = await prompt('New team folder', 'Name');
        if (!name) return;
        await act(async () => {
          const id = E.newId(), rootId = E.newId(), team = await E.Space.newTeam(id), root = await E.NodeKey.fresh();
          await api('POST', '/api/v1/spaces', { id, rootId, nameEnc: await team.encryptName(name),
            keys: { publicKey: E.b64u(team.publicKey), keySig: await E.signSpaceKey(S.acct, id, team.publicKey), rootKey: await team.wrapRoot(rootId, root) },
            ...(await team.grant(S.acct, await S.acct.publicUser())) });
        }, 'Team folder created');
      } }, 'New team folder')),
    h('p', { class: 'note' }, 'Team folders belong to the team, not to one person, and have their own quota. Members are added by managers, or by administrators through identity-provider groups.'),
    h('table', {}, h('tbody', {}, cards.length ? cards : h('tr', {}, h('td', { class: 'empty' }, 'You are not in any team folders yet.'))))));
}

async function teamView(spaceId) {
  const sp = await api('GET', `/api/v1/spaces/${spaceId}`);
  let opened = true;
  try { await openSpace(sp); } catch { opened = false; }
  const manager = sp.role === 'manage';
  const { members } = await api('GET', `/api/v1/spaces/${spaceId}/members`);
  const groups = (await api('GET', `/api/v1/spaces/${spaceId}/groups`).catch(() => ({ groups: [] }))).groups;
  // Member keys come from the server's directory: check every self-signature.
  const people = await Promise.all(members.map(async (m) => {
    let pu = null;
    if (m.keys) {
      try { pu = await E.verifyUser(m.userId, m.keys); pu.displayName = m.displayName; pu.email = m.email; } catch { pu = null; }
    }
    return { m, pu };
  }));
  // Nobody gets the team key automatically. The member list is the
  // server's claim, and whoever controls the server could add to it, so a
  // manager gives each key deliberately (E2EE.md §3, "Granting the key").
  const pending = manager && opened ? people.filter(({ m, pu }) => !m.hasGrant && pu && m.userId !== S.me.user.id) : [];
  const how = (m) => [m.directRole ? `added directly (${m.directRole})` : '', m.groupRoles?.length ? `via an identity-provider group (${m.groupRoles.join(', ')})` : '']
    .filter(Boolean).join('; ');
  const roleSel = (value, onchange) => {
    const s = h('select', { onchange: () => onchange(s.value) }, ...['read', 'write', 'manage'].map((r) => h('option', { value: r }, r)));
    s.value = value;
    return s;
  };
  const removeBtn = (m) => (manager || m.userId === S.me.user.id) && m.directRole && h('button', { class: 'link danger', onclick: async () => {
    if (await confirmBox(m.userId === S.me.user.id ? 'Leave team folder' : 'Remove member', 'Their direct membership and key grant will be removed.', 'Remove')) {
      await act(() => api('DELETE', `/api/v1/spaces/${spaceId}/members/${m.userId}`), 'Removed');
      if (m.userId === S.me.user.id) navigate('/teams');
    }
  } }, m.userId === S.me.user.id ? 'Leave' : 'Remove');
  const giveKey = async ({ m, pu }) => {
    const t = trust(pu);
    if (t.level === 'changed') return toast(`Key not given. ${trustText(pu, t)}`);
    const can = m.role === 'read' ? 'read' : 'read and change';
    const ok = await confirmBox(`Give ${nameOf(pu)} the key to “${spaceName(sp)}”?`,
      `${nameOf(pu)}${pu.email ? ` (${pu.email})` : ''} will be able to ${can} everything in this team folder, including everything already in it. ` +
      `Key fingerprint: ${E.formatFingerprint(pu.fp)}. ${trustText(pu, t)} If you do not expect this person here, choose Cancel and remove them, or ask an administrator.`,
      t.level === 'lookalike' ? 'Give key anyway' : 'Give key');
    if (!ok) return;
    await act(async () => api('PUT', `/api/v1/spaces/${spaceId}/members/${m.userId}`, await S.spaces.get(spaceId).space.grant(S.acct, pu)), `${nameOf(pu)} can now open the folder`);
  };
  const giveAll = async () => {
    const eligible = pending.filter(({ pu }) => !['changed', 'lookalike'].includes(trust(pu).level));
    const skipped = pending.length - eligible.length;
    const ok = await confirmList(`Give the key to ${eligible.length} people?`,
      `Each will be able to open everything in “${spaceName(sp)}”. Check that you expect every one of them.` +
      (skipped ? ` ${skipped} flagged ${skipped === 1 ? 'person is' : 'people are'} left out; review them one by one.` : ''),
      eligible.map(({ m, pu }) => `${nameOf(pu)}${pu.email ? ` (${pu.email})` : ''}, ${how(m) || m.role}, key ${E.formatFingerprint(pu.fp).slice(0, 19)}…, ${TRUST_LABEL[trust(pu).level]}`),
      'Give keys');
    if (!ok) return;
    await act(async () => {
      for (const { m, pu } of eligible) await api('PUT', `/api/v1/spaces/${spaceId}/members/${m.userId}`, await S.spaces.get(spaceId).space.grant(S.acct, pu));
    }, `Gave the key to ${eligible.length} people`);
  };

  const rows = people.map(({ m, pu }) => h('tr', {},
    h('td', {}, m.displayName || m.email || m.userId.slice(0, 8), m.userId === S.me.user.id ? ' (you)' : '', m.email && m.displayName ? h('div', { class: 'note' }, m.email) : null),
    h('td', {}, manager && m.directRole ? roleSel(m.directRole, (r) => act(() => api('PUT', `/api/v1/spaces/${spaceId}/members/${m.userId}`, { role: r }), 'Role changed')) : m.role,
      m.groupRoles?.length ? h('span', { class: 'note' }, ` via group (${m.groupRoles.join(', ')})`) : ''),
    h('td', {}, m.hasGrant ? '🔑 has key' : pu ? '⏳ waiting for a manager' : '⚠ no encryption keys yet'),
    h('td', {}, trustBadge(pu)),
    h('td', { class: 'actions' }, removeBtn(m))));
  const email = h('input', { type: 'email', placeholder: 'person@example.com', required: true });
  const role = roleSel('write', () => {});
  const group = h('input', { placeholder: 'IdP group name', required: true });
  const grole = roleSel('read', () => {});
  main.replaceChildren(h('div', { class: 'panel' },
    h('div', { class: 'toolbar' }, h('h1', { class: 'crumbs' }, opened ? spaceName(sp) : '🔒 Team folder'),
      opened && h('a', { class: 'button', href: `/f/${sp.rootId}`, 'data-nav': '' }, 'Open'),
      manager && opened && h('button', { onclick: async () => {
        const name = await prompt('Rename team folder', 'Name', spaceName(sp));
        if (name) await act(async () => { await api('PATCH', `/api/v1/spaces/${spaceId}`, { nameEnc: await S.spaces.get(spaceId).space.encryptName(name) }); S.spaces.delete(spaceId); }, 'Renamed');
      } }, 'Rename'),
      manager && h('button', { class: 'danger', onclick: async () => {
        if (await confirmBox('Delete team folder', 'Permanently delete this team folder and everything in it, for everyone? This cannot be undone.', 'Delete forever')) {
          await act(() => api('DELETE', `/api/v1/spaces/${spaceId}`), 'Team folder deleted');
          navigate('/teams');
        }
      } }, 'Delete')),
    !opened && h('p', { class: 'note' }, 'You have access, but no manager has given you the team key yet. Ask a manager to approve you on this page.'),
    pending.length ? [
      h('div', { class: 'toolbar' }, h('h2', {}, `Waiting for the team key (${pending.length})`),
        pending.length > 1 && h('button', { onclick: giveAll }, 'Give key to everyone listed…')),
      h('p', { class: 'note' }, 'The server says these people belong here, but they cannot open anything until a manager gives them the key. ' +
        'Anyone who controls the server could add a name to this list, so give the key only to people you expect.'),
      h('table', { class: 'pending' }, h('tbody', {}, pending.map((p) => h('tr', {},
        h('td', {}, nameOf(p.pu), p.pu.email && p.pu.displayName ? h('div', { class: 'note' }, p.pu.email) : null),
        h('td', { class: 'note' }, how(p.m) || p.m.role),
        h('td', {}, h('code', { title: E.formatFingerprint(p.pu.fp) }, E.formatFingerprint(p.pu.fp).slice(0, 19) + '…'), ' ', trustBadge(p.pu)),
        h('td', { class: 'actions' }, h('button', { class: 'primary', onclick: () => giveKey(p) }, 'Give key'), ' ', removeBtn(p.m)))))),
    ] : null,
    h('h2', {}, 'Members'),
    h('table', {}, h('tbody', {}, rows)),
    manager && opened && h('form', { class: 'toolbar', onsubmit: async (e) => {
      e.preventDefault();
      try {
        const u = await api('GET', `/api/v1/users/lookup?email=${encodeURIComponent(email.value)}`);
        const pu = await E.verifyUser(u.id, u.keys);
        pu.displayName = u.displayName; pu.email = u.email;
        const t = trust(pu);
        if (t.level === 'changed') return toast(`Not added. ${trustText(pu, t)}`);
        if (!(await confirmBox(`Add ${nameOf(pu)} as ${role.value}?`,
          `${nameOf(pu)}${u.email ? ` (${u.email})` : ''} will get the key and be able to open everything in this team folder. Key fingerprint: ${E.formatFingerprint(pu.fp)}. ${trustText(pu, t)}`,
          t.level === 'lookalike' ? 'Add anyway' : 'Add and give key'))) return;
        await act(async () => {
          await api('PUT', `/api/v1/spaces/${spaceId}/members/${u.id}`, { role: role.value });
          await api('PUT', `/api/v1/spaces/${spaceId}/members/${u.id}`, await S.spaces.get(spaceId).space.grant(S.acct, pu));
        }, 'Member added');
      } catch (err) { toast(err.message); }
    } }, email, role, h('button', { class: 'primary' }, 'Add member')),
    h('h2', {}, 'Identity-provider groups'),
    h('p', { class: 'note' }, 'Everyone in a mapped group gets the role below. Only administrators can change mappings. New group members still need a manager to give them the key.'),
    h('table', {}, h('tbody', {}, groups.length ? groups.map((g) => h('tr', {}, h('td', {}, g.group), h('td', {}, g.role),
      h('td', { class: 'actions' }, S.me.user.admin && h('button', { class: 'link danger', onclick: () => act(() => api('DELETE', `/api/v1/spaces/${spaceId}/groups/${encodeURIComponent(g.group)}`), 'Mapping removed') }, 'Remove'))))
      : h('tr', {}, h('td', { class: 'note' }, 'No groups mapped.')))),
    S.me.user.admin && h('form', { class: 'toolbar', onsubmit: async (e) => {
      e.preventDefault();
      await act(() => api('PUT', `/api/v1/spaces/${spaceId}/groups/${encodeURIComponent(group.value)}`, { role: grole.value }), 'Group mapped');
    } }, group, grole, h('button', { class: 'primary' }, 'Map group'))));
}

// ---- trash -----------------------------------------------------------------------------------------------------
async function trashView(spaceId) {
  const sp = await api('GET', `/api/v1/spaces/${spaceId}`);
  const space = await openSpace(sp);
  const { items } = await api('GET', `/api/v1/spaces/${spaceId}/trash`);
  const rows = [];
  for (const it of items) {
    let entry;
    try { entry = await E.openTrashKey(space, await userKeys(it.trashedBy), it); } catch { entry = null; }
    rows.push(h('tr', {},
      h('td', {}, h('div', { class: 'name' }, h('span', { class: 'icon' }, it.kind === 'folder' ? '📁' : '📄'), entry ? entry.name : '⚠ unverifiable item')),
      h('td', { class: 'num' }, `deleted ${fmtDate(it.trashedAt)}`),
      h('td', { class: 'num' }, `purged ${fmtDate(it.expiresAt)}`),
      h('td', { class: 'actions' },
        entry && h('button', { class: 'link', onclick: () => restoreItem(sp, it, entry) }, 'Restore'),
        sp.role === 'manage' && h('button', { class: 'link danger', onclick: async () => {
          if (await confirmBox('Delete permanently', 'This cannot be undone.', 'Delete forever')) await act(() => api('DELETE', `/api/v1/trash/${it.id}`), 'Deleting…');
        } }, 'Delete forever'))));
  }
  main.replaceChildren(h('div', { class: 'panel' },
    h('div', { class: 'toolbar' }, h('h1', { class: 'crumbs' }, `Trash · ${spaceName(sp)}`),
      sp.role === 'manage' && items.length > 0 && h('button', { class: 'danger', onclick: async () => {
        if (await confirmBox('Empty trash', 'Permanently delete everything in this trash?', 'Empty trash')) await act(() => api('DELETE', `/api/v1/spaces/${spaceId}/trash`), 'Emptying…');
      } }, 'Empty trash')),
    h('table', {}, h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { class: 'empty' }, 'The trash is empty.'))))));
}

async function restoreItem(sp, it, entry) {
  await act(async () => {
    let parent = it.parentId;
    try { await nodeKey(parent); } catch { parent = sp.rootId; } // original folder gone: restore to the root
    let name = entry.name;
    for (;;) {
      const fields = await (await nodeKey(parent)).entry(it.id, name, entry.nk);
      try { await api('POST', `/api/v1/trash/${it.id}/restore`, { parentId: parent, ...fields }); break; } catch (e) {
        if (e.status !== 409) throw e;
        name = await prompt('Name in use', 'Restore under a new name', `${name} (restored)`);
        if (!name) return;
      }
    }
    S.keys.set(it.id, entry.nk);
  }, 'Restored');
}

// ---- settings ---------------------------------------------------------------------------------------------------
async function settingsView() {
  const fp = await S.acct.fingerprint();
  let aps = [], note = null;
  try { ({ appPasswords: aps } = await api('GET', '/api/v1/app-passwords')); } catch (e) { note = e.message; }
  const apName = h('input', { placeholder: 'e.g. Laptop CLI', required: true });
  const ro = h('input', { type: 'checkbox' });
  main.replaceChildren(h('div', { class: 'panel' },
    h('h1', {}, 'Settings'),
    appearanceSection(),
    h('h2', {}, 'Encryption'),
    h('p', {}, 'Your key fingerprint: ', h('code', {}, E.formatFingerprint(fp))),
    h('p', { class: 'note' }, 'When sharing something sensitive, compare fingerprints with the other person over another channel.'),
    h('div', { class: 'toolbar' },
      h('button', { onclick: async () => {
        const np = await prompt('Change passphrase', 'New encryption passphrase (12+ characters)', '', 'password');
        if (np) { try { await changePassphrase(np); } catch (e) { toast(e.message); } }
      } }, 'Change passphrase'),
      h('button', { onclick: exportKeys }, 'Download key backup'),
      h('button', { onclick: () => { S.acct = null; S.contacts = null; S.keys.clear(); S.spaces.clear(); clearThumbs(); route(); } }, 'Lock now')),
    h('p', { class: 'note' }, 'The key backup is encrypted: it opens only with your passphrase or recovery code. With it, any backed-up file (.fdenc) or WebDAV mirror can be decrypted offline using the frontdir-cli tool.'),
    h('h2', {}, 'Verified people'),
    h('p', { class: 'note' }, 'People whose key fingerprints you compared with them directly. FrontDir marks them ✔ wherever they appear and warns you about other accounts that imitate them. This list is encrypted with your own key: the server cannot read or change it.'),
    S.contacts?.problem ? h('p', { class: 'error' }, S.contacts.problem) : null,
    h('table', {}, h('tbody', {}, Object.keys(S.contacts?.list.contacts || {}).length
      ? Object.entries(S.contacts.list.contacts).sort((a, b) => a[1].name.localeCompare(b[1].name)).map(([id, c]) => h('tr', {},
        h('td', {}, c.name || c.email || id.slice(0, 8), c.email && c.name ? h('div', { class: 'note' }, c.email) : null),
        h('td', {}, h('code', {}, E.formatFingerprint(c.fp))),
        h('td', { class: 'num' }, `verified ${new Date(c.verifiedAt).toLocaleDateString()}`),
        h('td', { class: 'actions' }, h('button', { class: 'link danger', onclick: async () => {
          if (!(await confirmBox('Remove verification', `Stop treating ${c.name || c.email || 'this person'} as verified?`, 'Remove'))) return;
          try { await saveContacts((list) => { delete list[id]; }); toast('Verification removed'); settingsView(); } catch (e) { toast(e.message); }
        } }, 'Remove'))))
      : h('tr', {}, h('td', { class: 'note' }, 'You have not verified anyone yet. Use “Verify…” next to a person’s name.')))),
    h('h2', {}, 'App passwords'),
    h('p', { class: 'note' }, 'For the frontdir-cli tool and for backing up encrypted files over WebDAV (', `${location.origin}/dav/`, '). WebDAV is read-only and serves ciphertext only.'),
    note && h('p', { class: 'error' }, note),
    h('table', {}, h('tbody', {}, aps.length ? aps.map((a) => h('tr', {}, h('td', {}, a.name, a.readOnly ? ' (read-only)' : ''),
      h('td', { class: 'num' }, a.lastUsedAt ? `last used ${fmtDate(a.lastUsedAt)}` : 'never used'),
      h('td', { class: 'actions' }, h('button', { class: 'link danger', onclick: () => act(() => api('DELETE', `/api/v1/app-passwords/${a.id}`), 'Revoked') }, 'Revoke'))))
      : h('tr', {}, h('td', { class: 'note' }, 'No app passwords.')))),
    h('form', { class: 'toolbar', onsubmit: async (e) => {
      e.preventDefault();
      try {
        const res = await api('POST', '/api/v1/app-passwords', { name: apName.value, readOnly: ro.checked });
        showSecret('App password created', 'Copy it now: it cannot be shown again. Use any username with this password.', res.token);
        settingsView();
      } catch (err) { toast(err.message); }
    } }, apName, h('label', {}, ro, ' read-only'), h('button', { class: 'primary' }, 'Create')),
    adminSection(),
    h('h2', {}, 'Session'),
    h('div', { class: 'toolbar' },
      h('button', { onclick: signOut }, 'Sign out'),
      h('button', { class: 'danger', onclick: async () => {
        if (await confirmBox('Sign out everywhere', 'End all browser sessions, including this one?', 'Sign out everywhere')) {
          try { await api('POST', '/api/v1/sessions/revoke-all'); } catch (e) { toast(e.message); }
          location.assign('/');
        }
      } }, 'Sign out everywhere'))));
}

function adminSection() {
  if (!S.me.user.admin) return null;
  return [h('h2', {}, 'Administration'),
    h('p', {}, 'Server settings, people, quotas and emergency switches are in the ', h('a', { href: '/admin', 'data-nav': '' }, 'Admin area'), '.')];
}

async function exportKeys() {
  try {
    const { spaces } = await api('GET', '/api/v1/spaces');
    const teams = [];
    for (const sp of spaces) {
      if (sp.kind !== 'team' || !sp.myGrant) continue;
      const u = await api('GET', `/api/v1/users/${sp.myGrant.grantedBy}/keys`);
      teams.push({ spaceId: sp.id, ...sp.myGrant, granterKeys: { enc: u.keys.enc, sig: u.keys.sig }, granterSelfSig: u.keys.selfSig });
    }
    const backup = { format: 'frontdir-keys/v1', bundle: S.bundle, teams };
    saveBlob(new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' }), 'frontdir-keys.json');
  } catch (e) { toast(e.message); }
}

async function signOut() {
  try {
    const { logoutUrl } = await api('POST', '/auth/logout');
    if (logoutUrl && /^https:\/\//.test(logoutUrl)) return location.assign(logoutUrl);
  } catch { /* fall through */ }
  location.assign('/');
}

// ---- admin area --------------------------------------------------------------------------------------------------
// Every rule here is enforced by the server: administrators only, and every
// change needs a recent sign-in ("confirm it's you", like sudo asking for
// your password again). The page shows the rules so nobody is surprised.
const ADMIN_TABS = [['people', 'People'], ['settings', 'Storage & sharing'], ['sign-in', 'Sign-in'], ['branding', 'Branding'], ['emergency', 'Emergency']];
const TAB_GROUPS = { settings: ['storage', 'sharing', 'sessions'], 'sign-in': ['oidc', 'saml', 'access'], branding: ['branding'] };
const reauthURL = () => `/auth/reauth?return_to=${encodeURIComponent(location.pathname)}`;

async function adminView(tab) {
  if (!ADMIN_TABS.some(([id]) => id === tab)) tab = 'people';
  renderQuota();
  const session = await api('GET', '/api/v1/admin/session');
  const body = h('div');
  main.replaceChildren(h('div', { class: 'panel' }, h('h1', {}, 'Admin'),
    !S.me.user.keys && h('p', { class: 'note' }, 'You have not set up encryption for your own files yet. Open ', h('a', { href: '/', 'data-nav': '' }, 'Files'), ' when you are ready.'),
    reauthBanner(session),
    h('nav', { class: 'tabs', 'aria-label': 'Admin' }, ADMIN_TABS.map(([id, label]) => h('a',
      { href: `/admin/${id}`, 'data-nav': '', class: tab === id ? 'active' : '', 'aria-current': tab === id ? 'page' : null }, label))),
    body));
  if (tab === 'people') return peopleTab(body);
  if (tab === 'emergency') return emergencyTab(body);
  const v = await api('GET', '/api/v1/admin/settings');
  // A branding change restyles the whole page: reload it to fetch the new theme.
  body.replaceChildren(settingsForm(v, TAB_GROUPS[tab],
    (set, confirm) => api('PUT', '/api/v1/admin/settings', { revision: v.revision, set, confirm }),
    tab === 'branding' ? () => location.reload() : () => adminView(tab)));
}

function reauthBanner(s) {
  if (s.recent) return h('p', { class: 'banner ok' }, `Identity confirmed: you can make changes until ${new Date(s.recentUntil).toLocaleTimeString()}.`);
  return h('div', { class: 'banner' },
    h('span', {}, `You can look around. To change anything, confirm it’s you: your identity provider asks you to sign in again (even if you are signed in there), then brings you back. It lasts ${s.window.replace(/m0s$/, ' minutes')}.`),
    h('button', { class: 'primary', onclick: () => location.assign(reauthURL()) }, 'Confirm it’s you'));
}

// adminChange runs a change and reports whether it worked. A change refused
// for want of a recent sign-in offers to go and get one.
async function adminChange(fn, ok) {
  try {
    await fn();
    if (ok) toast(ok);
    return true;
  } catch (e) {
    if (e.code === 'reauth_required') {
      if (await confirmBox('Confirm it’s you', 'This change needs a recent sign-in. You will be sent to your identity provider and brought back here.', 'Continue')) location.assign(reauthURL());
    } else toast(e.message);
    return false;
  }
}

function exactSize(n) {
  for (const [u, m] of [['TiB', 2 ** 40], ['GiB', 2 ** 30], ['MiB', 2 ** 20], ['KiB', 2 ** 10]]) if (n >= m && n % m === 0) return `${n / m}${u}`;
  return String(n);
}

async function peopleTab(body) {
  const search = h('input', { type: 'search', placeholder: 'Search by name or email', 'aria-label': 'Search people' });
  const rows = h('tbody');
  const load = async () => {
    const { users } = await api('GET', `/api/v1/admin/users?q=${encodeURIComponent(search.value)}`);
    rows.replaceChildren(...(users.length ? users.map(row) : [h('tr', {}, h('td', { colspan: 5, class: 'note' }, 'Nobody found.'))]));
  };
  const row = (u) => {
    const me = u.id === S.me.user.id;
    const name = u.displayName || u.email || u.id.slice(0, 8);
    const role = u.admin ? (u.adminGranted ? 'Administrator (appointed)' : 'Administrator (through a group)') : 'Member';
    return h('tr', {},
      h('td', {}, name, me ? ' (you)' : '', u.email && u.displayName ? h('div', { class: 'note' }, u.email) : null,
        u.keysSetUp ? null : h('div', { class: 'note' }, 'Has not set up encryption yet')),
      h('td', { 'data-label': 'Sign-in' }, u.signIn.toUpperCase()),
      h('td', {}, role),
      h('td', { class: 'num', 'data-label': 'Storage' }, `${fmtSize(u.usedBytes)} of ${fmtSize(u.quotaBytes)}`),
      h('td', { class: 'actions' },
        h('button', { class: 'link', onclick: async () => {
          const size = await prompt(`Storage for ${name}`, 'Personal storage, e.g. 20GiB', exactSize(u.quotaBytes));
          if (size !== null && await adminChange(() => api('PUT', `/api/v1/admin/users/${u.id}/quota`, { size }), 'Storage changed')) load();
        } }, 'Storage…'),
        !me && (u.adminGranted || !u.admin) && h('button', { class: 'link', onclick: async () => {
          const make = !u.adminGranted;
          const text = make ? `${name} will be able to change server settings, appoint administrators and use the emergency switches. Administrators cannot read anyone’s files: those stay end-to-end encrypted.`
            : `${name} will no longer be an administrator (unless they are in an administrator group).`;
          if (!(await confirmBox(make ? 'Make administrator' : 'Remove administrator', text, make ? 'Make administrator' : 'Remove'))) return;
          if (await adminChange(() => api('PUT', `/api/v1/admin/users/${u.id}/admin`, { admin: make }), 'Done')) load();
        } }, u.adminGranted ? 'Remove administrator' : 'Make administrator'),
        !me && h('button', { class: 'link danger', onclick: async () => {
          if (!(await confirmBox('Revoke access', `Sign ${name} out of every browser and delete their app passwords? Their files and shares stay. ` +
            'They can sign in again unless you also remove them at your identity provider, so do that first.', 'Revoke access'))) return;
          await adminChange(() => api('POST', `/api/v1/admin/users/${u.id}/revoke-access`), `${name} was signed out everywhere`);
        } }, 'Revoke access')));
  };
  body.replaceChildren(
    h('form', { class: 'toolbar', onsubmit: (e) => { e.preventDefault(); load().catch((err) => toast(err.message)); } }, search, h('button', {}, 'Search')),
    h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Person'), h('th', {}, 'Sign-in'), h('th', {}, 'Role'), h('th', { class: 'num' }, 'Storage'), h('th', {}))), rows),
    h('p', { class: 'note' }, 'Administrators come from the administrator groups (Sign-in tab) or are appointed here. Nobody can change their own administrator rights, so the last administrator cannot lock everyone out by accident. ' +
      'New people get the default storage from the Storage & sharing tab.'));
  await load();
}

function emergencyTab(body) {
  body.replaceChildren(
    h('h2', {}, 'Revoke every public link'),
    h('p', { class: 'note' }, 'Links stop working immediately and cannot be restored. Shares with specific people and team folders are not affected. ' +
      'From the server’s shell: frontdir revoke-links --all.'),
    h('div', { class: 'toolbar' }, h('button', { class: 'danger', onclick: async () => {
      const typed = await prompt('Revoke every public link on this server?', 'This affects all users and cannot be undone. Type REVOKE ALL to confirm.');
      if (typed === null) return;
      if (typed.trim() !== 'REVOKE ALL') return toast('Not confirmed. Nothing was revoked.');
      await adminChange(async () => {
        const { revoked } = await api('POST', '/api/v1/admin/links/revoke-all');
        toast(`Revoked ${revoked} public link${revoked === 1 ? '' : 's'} across the server`);
      });
    } }, 'Revoke all public links')),
    h('h2', {}, 'Sign everyone out'),
    h('p', { class: 'note' }, 'Ends every browser session on the server, including yours. People sign in again through the identity provider, which applies its current rules. ' +
      'App passwords keep working; revoke those per person under People. From the server’s shell: frontdir revoke-sessions --all.'),
    h('div', { class: 'toolbar' }, h('button', { class: 'danger', onclick: async () => {
      const typed = await prompt('Sign everyone out?', 'Everyone, including you, must sign in again. Type SIGN OUT EVERYONE to confirm.');
      if (typed === null) return;
      if (typed.trim() !== 'SIGN OUT EVERYONE') return toast('Not confirmed. Nobody was signed out.');
      if (await adminChange(() => api('POST', '/api/v1/admin/sessions/revoke-all'))) location.assign('/');
    } }, 'Sign everyone out')));
}

// settingsForm renders the settings of some groups as one form. Only fields
// the administrator touched are sent; the server validates everything again.
function settingsForm(v, groups, save, done) {
  const editors = new Map();
  const status = h('p', { class: 'error', hidden: true, role: 'alert' });
  // Sections appear in the order the caller lists them.
  const sections = groups.map((id) => v.groups.find((g) => g.id === id)).filter(Boolean).map((g) => h('fieldset', {}, h('legend', {}, g.label),
    g.fromServer && h('p', { class: 'note' }, 'Configured on the server (environment variables). Change it there; it cannot be mixed with web settings.'),
    g.id === 'oidc' && h('p', { class: 'note wrap-anywhere' }, 'At your identity provider, register FrontDir as a confidential client (authorization code flow with PKCE) with this redirect URI: ', h('code', {}, v.signIn.oidcRedirectUri)),
    g.id === 'saml' && h('p', { class: 'note wrap-anywhere' }, 'Give your identity provider our metadata: ', h('code', {}, v.signIn.samlMetadataUrl), ' (assertion consumer service ', h('code', {}, v.signIn.samlAcsUrl), ').'),
    v.fields.filter((f) => f.group === g.id).map((f) => fieldEditor(f, editors, v))));
  return h('form', { class: 'settings', onsubmit: async (e) => {
    e.preventDefault();
    const set = {};
    for (const [k, ed] of editors) { const val = ed.get(); if (val !== undefined) set[k] = val; }
    if (!Object.keys(set).length) return toast('Nothing changed');
    for (const ed of editors.values()) ed.error.hidden = true;
    status.hidden = true;
    const confirm = [];
    for (;;) {
      try {
        await save(set, confirm);
        toast('Saved');
        return done();
      } catch (err) {
        if (err.code === 'confirm_required' && err.detail.confirm && !confirm.includes(err.detail.confirm)) {
          if (!(await confirmBox('Please confirm', err.message, 'Save anyway'))) return;
          confirm.push(err.detail.confirm);
          continue;
        }
        if (err.code === 'reauth_required') {
          if (await confirmBox('Confirm it’s you', 'Saving needs a recent sign-in. Your changes here are not kept: you will be sent to your identity provider and brought back to this page.', 'Continue')) location.assign(reauthURL());
          return;
        }
        if (err.code === 'precondition') { toast(err.message); return done(); }
        const fields = Object.entries(err.detail || {}).filter(([k]) => k !== 'confirm');
        if (err.code === 'invalid' && fields.length) {
          for (const [k, msg] of fields) {
            const ed = editors.get(k);
            if (ed) { ed.error.textContent = msg; ed.error.hidden = false; } else { status.textContent = `${k}: ${msg}`; status.hidden = false; }
          }
          return toast('Some settings need attention');
        }
        status.textContent = err.message;
        status.hidden = false;
        return;
      }
    }
  } }, v.readOnly && h('p', { class: 'note' }, 'Settings are read-only on the web on this server (FRONTDIR_WEB_SETTINGS=false).'),
  sections, status, h('div', { class: 'toolbar' }, h('button', { class: 'primary', disabled: v.readOnly }, 'Save changes')));
}

const truthy = (s) => /^(1|t|true)$/i.test(s || '');

function fieldEditor(f, editors, v) {
  const id = `set-${f.key}`;
  const error = h('p', { class: 'error field-error', hidden: true, id: `${id}-err`, role: 'alert' });
  const meta = h('div', { class: 'meta' });
  let control, get;
  switch (f.kind) {
    case 'bool': {
      control = h('select', { id, disabled: f.locked },
        h('option', { value: '' }, `Default (${truthy(f.default) ? 'on' : 'off'})`), h('option', { value: 'true' }, 'On'), h('option', { value: 'false' }, 'Off'));
      control.value = f.source === 'default' ? '' : (truthy(f.value) ? 'true' : 'false');
      const orig = control.value;
      get = () => (control.value === orig ? undefined : control.value);
      break;
    }
    case 'secret': {
      let clear = false;
      control = h('input', { id, type: 'password', autocomplete: 'new-password', spellcheck: 'false', disabled: f.locked || !v.canStoreSecrets,
        placeholder: f.isSet ? 'Set (hidden). Type a new value to replace it.' : (v.canStoreSecrets || f.locked ? '' : 'Unavailable: the server has no settings key') });
      const remove = h('button', { type: 'button', class: 'link danger', hidden: f.locked || !f.isSet, onclick: () => {
        clear = true; control.value = ''; control.placeholder = 'Will be removed when you save'; remove.hidden = true;
      } }, 'Remove');
      meta.append(remove);
      get = () => (control.value ? control.value : (clear ? '' : undefined));
      break;
    }
    case 'json': case 'xml': {
      control = h('textarea', { id, rows: f.kind === 'xml' ? 8 : 12, spellcheck: 'false', disabled: f.locked });
      control.value = f.value;
      get = () => (control.value.trim() === f.value.trim() ? undefined : control.value.trim());
      break;
    }
    case 'image': {
      let data;
      const preview = h('img', { class: 'logo-preview', alt: 'Logo preview', hidden: !f.isSet, src: f.isSet ? `/branding/logo?v=${Date.now()}` : null });
      const file = h('input', { id, type: 'file', accept: 'image/png,image/jpeg', disabled: f.locked, onchange: async () => {
        const picked = file.files[0];
        if (!picked) return;
        if (picked.size > 512 * 1024) { error.textContent = 'The logo must be at most 512 KiB.'; error.hidden = false; file.value = ''; return; }
        const bytes = new Uint8Array(await picked.arrayBuffer());
        let bin = '';
        for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
        data = btoa(bin);
        preview.src = URL.createObjectURL(picked);
        preview.hidden = false;
        error.hidden = true;
      } });
      const remove = h('button', { type: 'button', class: 'link danger', hidden: f.locked || !f.isSet, onclick: () => {
        data = ''; preview.hidden = true; remove.hidden = true;
      } }, 'Remove logo');
      meta.append(remove);
      control = h('div', {}, preview, file);
      get = () => data;
      break;
    }
    default: {
      control = h('input', { id, type: 'text', spellcheck: 'false', disabled: f.locked, placeholder: f.default || '',
        inputmode: f.kind === 'url' ? 'url' : null, value: f.source === 'default' ? '' : f.value });
      const orig = control.value;
      get = () => (control.value.trim() === orig.trim() ? undefined : control.value.trim());
    }
  }
  if (f.source === 'server') meta.append(h('span', { class: 'note' }, 'Set on the server: ', h('code', {}, f.env)));
  else if (f.source === 'web' && !f.locked && f.kind !== 'secret' && f.kind !== 'image') {
    const reset = h('button', { type: 'button', class: 'link', onclick: () => { control.value = ''; reset.hidden = true; } }, 'Use default');
    meta.append(reset);
  }
  editors.set(f.key, { get: f.locked ? () => undefined : get, error });
  control.setAttribute?.('aria-describedby', `${id}-help ${id}-err`);
  return h('div', { class: 'field' },
    h('label', { for: id }, f.label), control,
    h('p', { class: 'note', id: `${id}-help` }, f.help, f.default && f.kind !== 'bool' ? ` Default: ${f.default}.` : ''),
    meta.childNodes.length ? meta : null, error);
}

// ---- first-time setup --------------------------------------------------------------------------------------------
// The link from `frontdir setup-link` carries its token in the fragment
// (/setup#token), which browsers never send to the server. The page moves
// it out of the address bar at once and keeps it in memory only.
let setupToken = null;

async function setupView() {
  document.getElementById('nav').hidden = true;
  if (location.hash.length > 1) {
    setupToken = location.hash.slice(1);
    history.replaceState(null, '', '/setup');
  }
  const panel = h('div', { class: 'panel narrow' }, h('h1', {}, `Set up ${branding.name}`));
  main.replaceChildren(panel);
  if (!setupToken) {
    return panel.append(h('p', { class: 'error' }, 'Open the setup link exactly as frontdir setup-link printed it, including the part after #. ' +
      'If you reloaded this page, open the link again: it keeps working until someone signs in through it.'));
  }
  let v;
  try {
    v = await api('POST', '/api/v1/setup/view', { token: setupToken });
  } catch (e) {
    return panel.append(h('p', { class: 'error' }, e.message));
  }
  const on = (k) => v.fields.some((f) => f.key === k && f.isSet);
  const oidc = on('OIDC_ISSUER'), saml = on('SAML_IDP_METADATA_URL') || on('SAML_IDP_METADATA');
  const finish = async (method) => {
    try {
      const { redirect } = await api('POST', '/api/v1/setup/login', { token: setupToken, method });
      if (/^https?:\/\//.test(redirect)) location.assign(redirect);
    } catch (e) { toast(e.message); }
  };
  panel.append(...[
    h('p', {}, `${branding.name} never stores passwords: your identity provider (Keycloak, Authentik, Zitadel, Entra ID, Okta, Google and others) signs people in, with its own multi-factor authentication.`),
    h('p', { class: 'note' }, 'Step 1: configure OpenID Connect or SAML below (or both); it is tried against your identity provider before it is saved. ' +
      'Step 2: sign in through this page. You become the first administrator and this link stops working.'),
    (oidc || saml) && h('div', { class: 'banner' }, h('span', {}, 'Sign-in is configured. Finish setup by signing in:'),
      oidc && h('button', { class: 'primary', onclick: () => finish('oidc') }, 'Sign in to finish'),
      saml && h('button', { class: oidc ? '' : 'primary', onclick: () => finish('saml') }, 'Sign in with SAML to finish')),
    settingsForm(v, ['oidc', 'saml', 'access'],
      (set, confirm) => api('POST', '/api/v1/setup/save', { token: setupToken, revision: v.revision, set, confirm }), () => setupView()),
  ].filter(Boolean));
}

// ---- public links ------------------------------------------------------------------------------------------------
// The fragment holds "<token>.<link secret>". Browsers never send fragments
// to servers: the server sees only the token (in POST bodies), never the key.
async function publicLink(nodeId = '', password = '') {
  document.getElementById('nav').hidden = true;
  const [token, secretB64] = location.hash.slice(1).split('.');
  let data;
  try {
    if (!token || !secretB64) throw new Error('This link is incomplete. Make sure you copied all of it.');
    data = await api('POST', '/api/v1/public/node', { token, password, nodeId });
  } catch (e) {
    if (e.status === 401) return passwordPrompt(nodeId, e.detail?.reason === 'password_wrong');
    return main.replaceChildren(h('div', { class: 'panel center' }, h('h1', {}, 'Link unavailable'), h('p', {}, e.message)));
  }
  try {
    const link = await E.openLinkKey(E.unb64u(secretB64), data.link.id, data.link.nodeId, data.link.linkKey);
    let key = link.nk, name = link.name;
    for (const n of data.path.slice(1)) { name = await key.decryptName(n.id, n.nameEnc); key = await key.unwrapChild(n.id, n.wrappedKey); }
    const target = data.path[data.path.length - 1];
    const signerCache = new Map();
    const signerFn = async (uid) => {
      if (!signerCache.has(uid)) {
        const u = await api('POST', '/api/v1/public/signer', { token, password, userId: uid });
        signerCache.set(uid, await E.verifyUser(u.id, u.keys));
      }
      return signerCache.get(uid);
    };
    const download = (id, fileKey, fileName, size) => decryptAndSave(fileName, size, () => fetch('/api/v1/public/download', {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, password, nodeId: id }),
    }), fileKey, signerFn);
    let body;
    if (target.kind === 'file') {
      body = h('div', { class: 'center' }, h('h1', {}, name), h('p', { class: 'note' }, fmtSize(target.plainSize)),
        h('button', { class: 'primary', onclick: () => download(target.id, key, name, target.plainSize) }, 'Download'));
    } else {
      const rows = [];
      for (const c of data.children) {
        const cname = await key.decryptName(c.id, c.nameEnc);
        const ck = await key.unwrapChild(c.id, c.wrappedKey);
        rows.push(h('tr', {}, h('td', {}, h('div', { class: 'name' }, h('span', { class: 'icon' }, c.kind === 'folder' ? '📁' : '📄'),
          c.kind === 'folder' ? h('button', { class: 'link', onclick: () => publicLink(c.id, password) }, cname)
            : h('button', { class: 'link', onclick: () => download(c.id, ck, cname, c.plainSize) }, cname))),
          h('td', { class: 'num' }, c.kind === 'file' ? fmtSize(c.plainSize) : '')));
      }
      body = h('div', {}, h('div', { class: 'toolbar' }, h('h1', { class: 'crumbs' }, name),
        target.id !== data.link.nodeId && h('button', { onclick: () => publicLink('', password) }, 'Back to top')),
        h('table', {}, h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { class: 'empty' }, 'Empty folder.')))));
    }
    main.replaceChildren(h('div', { class: 'panel' }, body,
      h('p', { class: 'note' }, '🔒 End-to-end encrypted: decrypted in your browser with the key in this link.',
        data.link.expiresAt ? ` This link expires ${fmtDate(data.link.expiresAt)}.` : '')));
  } catch (e) {
    main.replaceChildren(h('div', { class: 'panel center' }, h('h1', {}, 'Cannot decrypt'), h('p', {}, 'The link is damaged or incomplete: ', e.message)));
  }
}

function passwordPrompt(nodeId, wrong) {
  const pw = h('input', { type: 'password', required: true, autocomplete: 'off' });
  main.replaceChildren(h('div', { class: 'panel center' }, h('h1', {}, 'Password required'),
    wrong && h('p', { class: 'error' }, 'Wrong password.'),
    h('form', { class: 'toolbar centered', onsubmit: (e) => { e.preventDefault(); publicLink(nodeId, pw.value); } }, pw, h('button', { class: 'primary' }, 'Open'))));
  pw.focus();
}

loadBranding().then(route);
