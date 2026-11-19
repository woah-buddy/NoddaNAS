// NoddaNAS web client (end-to-end encrypted).
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
const APPEARANCE_KEY = 'noddanas.appearance';
const MODES = { system: 'Match system', light: 'Light', dark: 'Dark', contrast: 'High contrast' };
const ACCENT_RE = /^[a-z][a-z0-9-]{0,23}$/;
let branding = { name: 'NoddaNAS', logo: false, defaultAccent: '', accents: [] };

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
      name: typeof b.name === 'string' && b.name ? b.name : 'NoddaNAS',
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
  try {
    if (!S.me) {
      try { S.me = await api('GET', '/api/v1/me'); } catch (e) { if (e.status === 401) return signIn(); throw e; }
    }
    if (!S.me.user.keys) return setupKeys();
    if (!S.acct) return unlockScreen();
    if (!S.contacts) await loadContacts();
    document.getElementById('nav').hidden = false;
    renderQuota();
    for (const a of document.querySelectorAll('#nav a')) a.classList.toggle('active', path === a.getAttribute('href') || (a.getAttribute('href') !== '/' && path.startsWith(a.getAttribute('href'))));
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
        h('button', { type: 'button', onclick: () => saveBlob(new Blob([`NoddaNAS recovery code for ${S.me.user.email || S.me.user.id}\n${code}\n`], { type: 'text/plain' }), 'noddanas-recovery-code.txt') }, 'Download as file')),
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
      canWrite && h('button', { onclick: () => newFolder(ctx) }, 'New folder'),
      canWrite && h('button', { onclick: async () => restoreBackups(ctx, await pickFiles('.ndne')) }, 'Restore backup…'),
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
    h('td', {}, h('div', { class: 'name' }, h('span', { class: 'icon', 'aria-hidden': 'true' }, c.kind === 'folder' ? '📁' : '📄'), name)),
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
      try {
        await send('POST', `/api/v1/nodes/${ctx.folderId}/files`, container,
          { 'Content-Type': 'application/octet-stream', 'X-NoddaNAS-Entry': JSON.stringify({ id, ...entry }) }, (f) => b.set(0.5 + f / 2));
        S.keys.set(id, nk);
      } catch (e) {
        if (e.status !== 409 || e.detail.existingKind !== 'file') throw e;
        b.close();
        if (!(await confirmBox('File exists', `“${file.name}” already exists. Upload as a new version?`, 'Upload new version'))) continue;
        const existing = e.detail.existingId;
        const ek = await nodeKey(existing);
        const v = await encryptFor(ctx, file, ek, file.name);
        await send('PUT', `/api/v1/nodes/${existing}/content`, v, { 'Content-Type': 'application/octet-stream' });
      }
    } catch (e) { toast(`${file.name}: ${e.message}`); } finally { b.close(); }
  }
  await refreshMe().catch(() => {});
  route();
}

async function downloadFile(c, versionId) {
  const b = busy(`Downloading and decrypting ${c.name}…`);
  try {
    const blob = await apiBlob(`/api/v1/nodes/${c.id}/content${versionId ? `?version=${versionId}` : ''}`);
    const res = await E.decryptFile(blob, await nodeKey(c.id), signerFor, (f) => b.set(f));
    saveBlob(res.blob, c.name);
  } catch (e) { toast(`${c.name}: ${e.message}`); } finally { b.close(); }
}

async function backupFile(c) {
  try {
    saveBlob(await apiBlob(`/api/v1/nodes/${c.id}/content`), `${c.name}.ndne`);
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
        try {
          await send('POST', `/api/v1/nodes/${ctx.folderId}/files`, file,
            { 'Content-Type': 'application/octet-stream', 'X-NoddaNAS-Entry': JSON.stringify({ id, ...entry }) });
          S.keys.set(id, nk);
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
  let data;
  try { data = await api('GET', `/api/v1/nodes/${c.id}/versions`); } catch (e) { return toast(e.message); }
  const rows = data.versions.map((v, i) => h('tr', {},
    h('td', {}, fmtDate(v.createdAt), i === 0 ? ' (current)' : ''),
    h('td', { class: 'num' }, fmtSize(v.size)),
    h('td', { class: 'actions' },
      h('button', { class: 'link', onclick: () => downloadFile(c, v.id) }, 'Download'),
      i > 0 && h('button', { class: 'link', onclick: async () => { d.close(); await act(() => api('POST', `/api/v1/nodes/${c.id}/versions/${v.id}/restore`), 'Version restored'); } }, 'Restore'))));
  const d = dialog(`Versions of ${c.name}`, h('table', {}, h('tbody', {}, rows)), h('form', { method: 'dialog', class: 'row' }, h('button', {}, 'Close')));
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
      h('td', { class: 'num' }, fmtDate(x.share.createdAt)),
      h('td', { class: 'num' }, x.share.expiresAt ? fmtDate(x.share.expiresAt) : 'Never'),
      h('td', { class: 'num' }, x.share.maxDownloads ? `${x.share.downloads || 0} of ${x.share.maxDownloads}` : String(x.share.downloads || 0)),
      h('td', {}, x.share.hasPassword ? 'Password' : 'None'),
      h('td', { class: 'actions' }, revoke(x, 'Revoke link', `The public link to “${x.name}” stops working immediately for everyone who has it.`)));
  });
  const peopleRows = await Promise.all(people.map(async (x) => {
    const pu = await userKeys(x.share.recipientId).catch(() => null);
    const who = pu ? nameOf(pu) : 'Unknown user';
    return h('tr', {}, h('td', {}, label(x)), h('td', {}, who, ' ', trustBadge(pu)),
      h('td', {}, x.share.permission === 'write' ? 'Can edit' : 'Can view'),
      h('td', { class: 'num' }, fmtDate(x.share.createdAt)),
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
      h('button', { onclick: () => { S.acct = null; S.contacts = null; S.keys.clear(); S.spaces.clear(); route(); } }, 'Lock now')),
    h('p', { class: 'note' }, 'The key backup is encrypted: it opens only with your passphrase or recovery code. With it, any backed-up file (.ndne) or WebDAV mirror can be decrypted offline using the noddanas-cli tool.'),
    h('h2', {}, 'Verified people'),
    h('p', { class: 'note' }, 'People whose key fingerprints you compared with them directly. NoddaNAS marks them ✔ wherever they appear and warns you about other accounts that imitate them. This list is encrypted with your own key: the server cannot read or change it.'),
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
    h('p', { class: 'note' }, 'For the noddanas-cli tool and for backing up encrypted files over WebDAV (', `${location.origin}/dav/`, '). WebDAV is read-only and serves ciphertext only.'),
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
    h('p', { class: 'note' }, 'Emergency switch: revoke every public link created by anyone on this server. Links stop working immediately and cannot be restored. ' +
      'Shares with specific people and team folders are not affected. Server operators can do the same from the shell: noddanas revoke-links --all.'),
    h('div', { class: 'toolbar' }, h('button', { class: 'danger', onclick: adminRevokeAllLinks }, 'Revoke all public links (all users)'))];
}
async function adminRevokeAllLinks() {
  const typed = await prompt('Revoke every public link on this server?', 'This affects all users and cannot be undone. Type REVOKE ALL to confirm.');
  if (typed === null) return;
  if (typed.trim() !== 'REVOKE ALL') return toast('Not confirmed. Nothing was revoked.');
  try {
    const { revoked } = await api('POST', '/api/v1/admin/links/revoke-all');
    toast(`Revoked ${revoked} public link${revoked === 1 ? '' : 's'} across the server`);
  } catch (e) { toast(e.message); }
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
    const backup = { format: 'noddanas-keys/v1', bundle: S.bundle, teams };
    saveBlob(new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' }), 'noddanas-keys.json');
  } catch (e) { toast(e.message); }
}

async function signOut() {
  try {
    const { logoutUrl } = await api('POST', '/auth/logout');
    if (logoutUrl && /^https:\/\//.test(logoutUrl)) return location.assign(logoutUrl);
  } catch { /* fall through */ }
  location.assign('/');
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
    const download = async (id, fileKey, fileName) => {
      const b = busy(`Downloading and decrypting ${fileName}…`);
      try {
        const blob = await apiBlob('/api/v1/public/download', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, password, nodeId: id }) });
        saveBlob((await E.decryptFile(blob, fileKey, signerFn, (f) => b.set(f))).blob, fileName);
      } catch (e) { toast(e.message); } finally { b.close(); }
    };
    let body;
    if (target.kind === 'file') {
      body = h('div', { class: 'center' }, h('h1', {}, name), h('p', { class: 'note' }, fmtSize(target.plainSize)),
        h('button', { class: 'primary', onclick: () => download(target.id, key, name) }, 'Download'));
    } else {
      const rows = [];
      for (const c of data.children) {
        const cname = await key.decryptName(c.id, c.nameEnc);
        const ck = await key.unwrapChild(c.id, c.wrappedKey);
        rows.push(h('tr', {}, h('td', {}, h('div', { class: 'name' }, h('span', { class: 'icon' }, c.kind === 'folder' ? '📁' : '📄'),
          c.kind === 'folder' ? h('button', { class: 'link', onclick: () => publicLink(c.id, password) }, cname)
            : h('button', { class: 'link', onclick: () => download(c.id, ck, cname) }, cname))),
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
