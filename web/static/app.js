// NoddaNAS web client.
//
// Written against DOM APIs only (createElement / textContent). The page's
// CSP enforces Trusted Types with no policies, so any string-to-HTML sink
// (innerHTML, insertAdjacentHTML, document.write, ...) would throw: user
// data such as file names can never be interpreted as markup.
//
// Authentication is an HttpOnly session cookie this script cannot read.
// Same-origin fetches send it automatically; the server's CSRF protection
// relies on the browser's Sec-Fetch-Site / Origin headers.

const main = document.getElementById('main');
let me = null;

// ---- tiny DOM helper ----------------------------------------------------------
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'hidden' || k === 'disabled' || k === 'required' || k === 'checked') el[k] = Boolean(v);
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
  toast.timer = setTimeout(() => { t.hidden = true; }, 4000);
}

function fmtSize(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`;
}
const fmtDate = (s) => (s ? new Date(s).toLocaleString() : '');

// ---- API ---------------------------------------------------------------------------
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
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  const isJSON = (r.headers.get('Content-Type') || '').includes('application/json');
  const data = isJSON ? await r.json() : null;
  if (!r.ok) throw new ApiError(r.status, data);
  return data;
}

function uploadFile(folderId, file, overwrite, onProgress) {
  // XMLHttpRequest (not fetch) because it reports upload progress.
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const q = new URLSearchParams({ name: file.name });
    if (overwrite) q.set('overwrite', 'true');
    xhr.open('POST', `/api/v1/nodes/${encodeURIComponent(folderId)}/upload?${q}`);
    xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    xhr.onload = () => {
      let body = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body);
      else reject(new ApiError(xhr.status, body));
    };
    xhr.onerror = () => reject(new ApiError(0, null));
    xhr.send(file);
  });
}

// ---- dialogs -------------------------------------------------------------------------
function dialog(title, ...content) {
  const d = h('dialog', {}, h('h2', {}, title), ...content);
  d.addEventListener('close', () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}

function prompt(title, label, value = '') {
  return new Promise((resolve) => {
    const input = h('input', { value, required: true });
    const d = dialog(title, h('form', { class: 'stack', method: 'dialog', onsubmit: () => resolve(input.value) },
      h('label', {}, label, input),
      h('div', { class: 'row' },
        h('button', { type: 'button', onclick: () => { resolve(null); d.close(); } }, 'Cancel'),
        h('button', { class: 'primary' }, 'OK'))));
    d.addEventListener('cancel', () => resolve(null));
    input.select();
  });
}

function confirmBox(title, text, okLabel = 'OK') {
  return new Promise((resolve) => {
    const d = dialog(title, h('p', {}, text), h('form', { method: 'dialog', class: 'row' },
      h('button', { onclick: () => resolve(false) }, 'Cancel'),
      h('button', { class: 'primary', onclick: () => resolve(true) }, okLabel)));
    d.addEventListener('cancel', () => resolve(false));
  });
}

function showSecret(title, explanation, secret) {
  const box = h('div', { class: 'secret' }, secret);
  dialog(title, h('p', { class: 'note' }, explanation), box,
    h('form', { method: 'dialog', class: 'row' },
      h('button', { type: 'button', onclick: async () => {
        try { await navigator.clipboard.writeText(secret); toast('Copied'); } catch { toast('Copy failed: select and copy manually'); }
      } }, 'Copy'),
      h('button', { class: 'primary' }, 'Done')));
}

// ---- routing -------------------------------------------------------------------------
function navigate(path) {
  history.pushState(null, '', path);
  route();
}

document.addEventListener('click', (e) => {
  const a = e.target.closest('a[data-nav]');
  if (a && !e.metaKey && !e.ctrlKey && !e.shiftKey) {
    e.preventDefault();
    navigate(a.getAttribute('href'));
  }
});
window.addEventListener('popstate', route);

async function route() {
  const path = location.pathname;
  if (path === '/s') return publicLink();
  if (!me) {
    try { me = await api('GET', '/api/v1/me'); } catch (e) {
      if (e.status === 401) return signIn();
      return fatal(e);
    }
    document.getElementById('nav').hidden = false;
  }
  renderQuota();
  for (const a of document.querySelectorAll('nav a')) a.classList.toggle('active', a.getAttribute('href') === path);
  try {
    if (path === '/trash') return await trashView();
    if (path === '/shared') return await sharedView();
    if (path === '/settings') return await settingsView();
    const m = path.match(/^\/f\/([0-9a-f]{32})$/);
    return await folderView(m ? m[1] : me.user.rootId);
  } catch (e) {
    if (e.status === 401) { me = null; return signIn(); }
    fatal(e);
  }
}

function fatal(e) {
  main.replaceChildren(h('div', { class: 'panel center' }, h('p', { class: 'error' }, e.message)));
}

function renderQuota() {
  const q = document.getElementById('quota');
  const u = me.user;
  q.hidden = false;
  q.textContent = `${u.displayName || u.email || ''} · ${fmtSize(u.usedBytes)} of ${fmtSize(u.quotaBytes)} used` +
    (me.readOnly ? ' · read-only' : '');
}

async function refreshMe() {
  me = await api('GET', '/api/v1/me');
  renderQuota();
}

// ---- sign in -------------------------------------------------------------------------
function signIn() {
  const err = new URLSearchParams(location.search).get('error');
  const messages = {
    signin: 'Sign-in failed. Please try again.',
    not_allowed: 'Your account is not permitted to use this NoddaNAS instance.',
  };
  const returnTo = location.pathname === '/' ? '/' : location.pathname;
  main.replaceChildren(h('div', { class: 'panel center' },
    h('h1', {}, 'NoddaNAS'),
    h('p', {}, 'Your private file storage.'),
    err ? h('p', { class: 'error' }, messages[err] || 'Sign-in failed.') : null,
    h('a', { class: 'button primary', href: `/auth/login?return_to=${encodeURIComponent(returnTo)}` }, 'Sign in')));
}

// ---- folder view -----------------------------------------------------------------------
async function loadAllChildren(id) {
  let cursor = '';
  let node = null;
  const children = [];
  do {
    const page = await api('GET', `/api/v1/nodes/${id}/children?limit=1000${cursor ? `&cursor=${cursor}` : ''}`);
    node = page.node;
    children.push(...page.children);
    cursor = page.nextCursor;
  } while (cursor);
  children.sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'folder' ? -1 : 1));
  return { node, children };
}

async function breadcrumbs(node) {
  const trail = [node];
  let cur = node;
  // Walk up only as far as the caller can see (stops at a share's root).
  while (cur.parentId && trail.length < 64) {
    try { cur = await api('GET', `/api/v1/nodes/${cur.parentId}`); } catch { break; }
    trail.unshift(cur);
  }
  const out = [];
  trail.forEach((n, i) => {
    if (i) out.push(h('span', { class: 'sep' }, '/'));
    const label = n.parentId ? n.name : 'Home';
    out.push(i === trail.length - 1 ? h('strong', {}, label) : h('a', { href: folderPath(n), 'data-nav': '' }, label));
  });
  return out;
}

const folderPath = (n) => (n.id === me.user.rootId ? '/' : `/f/${n.id}`);

async function folderView(id) {
  const { node, children } = await loadAllChildren(id);
  const canWrite = node.permission === 'owner' || node.permission === 'write';
  const progress = h('div', { class: 'note' });
  const fileInput = h('input', { type: 'file', multiple: true, hidden: true,
    onchange: () => uploadMany(node.id, fileInput.files, progress) });

  const rows = children.map((c) => fileRow(c, node));
  const table = h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Size'), h('th', {}, 'Modified'), h('th', {}))),
    h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 4, class: 'empty' }, 'This folder is empty.'))));

  const panel = h('div', { class: 'panel dropzone' },
    h('div', { class: 'toolbar' },
      h('div', { class: 'crumbs' }, ...(await breadcrumbs(node))),
      canWrite && h('button', { onclick: async () => {
        const name = await prompt('New folder', 'Name');
        if (name) await act(() => api('POST', `/api/v1/nodes/${node.id}/folders`, { name }), 'Folder created');
      } }, 'New folder'),
      canWrite && h('button', { class: 'primary', onclick: () => fileInput.click() }, 'Upload'),
      fileInput),
    progress, table);

  if (canWrite) {
    panel.addEventListener('dragover', (e) => { e.preventDefault(); panel.classList.add('over'); });
    panel.addEventListener('dragleave', () => panel.classList.remove('over'));
    panel.addEventListener('drop', (e) => {
      e.preventDefault();
      panel.classList.remove('over');
      uploadMany(node.id, e.dataTransfer.files, progress);
    });
  }
  main.replaceChildren(panel);
}

function fileRow(c, parent) {
  const canModify = parent.permission === 'owner' || parent.permission === 'write';
  const isOwner = c.ownerId === me.user.id;
  const name = c.kind === 'folder'
    ? h('a', { href: folderPath(c), 'data-nav': '' }, c.name)
    : h('a', { href: `/api/v1/nodes/${c.id}/content`, download: '' }, c.name);
  return h('tr', {},
    h('td', {}, h('div', { class: 'name' }, h('span', { class: 'icon', 'aria-hidden': 'true' }, c.kind === 'folder' ? '📁' : '📄'), name)),
    h('td', { class: 'num' }, c.kind === 'file' ? fmtSize(c.size) : ''),
    h('td', { class: 'num' }, fmtDate(c.modifiedAt)),
    h('td', { class: 'actions' },
      isOwner && h('button', { class: 'link', onclick: () => shareDialog(c) }, 'Share'),
      c.kind === 'file' && h('button', { class: 'link', onclick: () => versionsDialog(c) }, 'Versions'),
      canModify && h('button', { class: 'link', onclick: async () => {
        const name = await prompt('Rename', 'New name', c.name);
        if (name && name !== c.name) await act(() => api('PATCH', `/api/v1/nodes/${c.id}`, { name, revision: c.revision }), 'Renamed');
      } }, 'Rename'),
      canModify && h('button', { class: 'link danger', onclick: async () => {
        if (await confirmBox('Move to trash', `Move “${c.name}” to the trash?`, 'Move to trash')) {
          await act(() => api('DELETE', `/api/v1/nodes/${c.id}?revision=${c.revision}`), 'Moved to trash');
        }
      } }, 'Delete')));
}

async function act(fn, ok) {
  try {
    await fn();
    if (ok) toast(ok);
  } catch (e) {
    toast(e.message);
  }
  await refreshMe().catch(() => {});
  route();
}

async function uploadMany(folderId, files, progressEl) {
  for (const file of Array.from(files)) {
    const bar = h('div');
    progressEl.replaceChildren(h('div', {}, `Uploading ${file.name}…`), h('div', { class: 'progress' }, bar));
    const onProgress = (f) => { bar.style.width = `${Math.round(f * 100)}%`; };
    try {
      await uploadFile(folderId, file, false, onProgress);
    } catch (e) {
      if (e.status === 409 && e.detail.existingId &&
          await confirmBox('File exists', `“${file.name}” already exists. Upload as a new version?`, 'Upload new version')) {
        try { await uploadFile(folderId, file, true, onProgress); } catch (e2) { toast(`${file.name}: ${e2.message}`); }
      } else if (e.status !== 409) {
        toast(`${file.name}: ${e.message}`);
      }
    }
  }
  progressEl.replaceChildren();
  await refreshMe().catch(() => {});
  route();
}

// ---- versions ---------------------------------------------------------------------------
async function versionsDialog(file) {
  let data;
  try { data = await api('GET', `/api/v1/nodes/${file.id}/versions`); } catch (e) { return toast(e.message); }
  const rows = data.versions.map((v, i) => h('tr', {},
    h('td', {}, fmtDate(v.createdAt), i === 0 ? ' (current)' : ''),
    h('td', { class: 'num' }, fmtSize(v.size)),
    h('td', { class: 'actions' },
      h('a', { href: `/api/v1/nodes/${file.id}/content?version=${v.id}`, download: '' }, 'Download'),
      i > 0 && h('button', { class: 'link', onclick: async () => {
        d.close();
        await act(() => api('POST', `/api/v1/nodes/${file.id}/versions/${v.id}/restore`), 'Version restored');
      } }, 'Restore'))));
  const d = dialog(`Versions of ${file.name}`, h('table', {}, h('tbody', {}, rows)),
    h('form', { method: 'dialog', class: 'row' }, h('button', {}, 'Close')));
}

// ---- sharing -----------------------------------------------------------------------------
async function shareDialog(node) {
  const list = h('tbody');
  const refresh = async () => {
    const { shares } = await api('GET', `/api/v1/nodes/${node.id}/shares`);
    list.replaceChildren(...(shares.length ? shares.map((s) => h('tr', {},
      h('td', {}, s.type === 'link' ? 'Public link' : `User ${s.recipientId.slice(0, 8)}…`),
      h('td', {}, s.permission, s.hasPassword ? ' · password' : '', s.expiresAt ? ` · expires ${fmtDate(s.expiresAt)}` : '',
        s.maxDownloads ? ` · ${s.downloads}/${s.maxDownloads} downloads` : ''),
      h('td', { class: 'actions' }, h('button', { class: 'link danger', onclick: async () => {
        try { await api('DELETE', `/api/v1/shares/${s.id}`); await refresh(); } catch (e) { toast(e.message); }
      } }, 'Revoke')))) : [h('tr', {}, h('td', { class: 'note' }, 'Not shared yet.'))]));
  };

  const email = h('input', { type: 'email', placeholder: 'person@example.com', required: true });
  const perm = h('select', {}, h('option', { value: 'read' }, 'Can view'), h('option', { value: 'write' }, 'Can edit'));
  const pw = h('input', { type: 'password', placeholder: 'optional, 10+ characters', autocomplete: 'new-password' });
  const days = h('input', { type: 'number', min: 1, max: 365, value: 30 });
  const maxDl = h('input', { type: 'number', min: 0, value: 0 });

  const d = dialog(`Share “${node.name}”`,
    h('table', {}, list),
    h('h2', {}, 'Share with a user'),
    h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api('POST', `/api/v1/nodes/${node.id}/shares`, { type: 'user', email: email.value, permission: perm.value });
        email.value = '';
        await refresh();
        toast('Shared');
      } catch (err) { toast(err.message); }
    } }, h('label', {}, 'Email', email), h('label', {}, 'Permission', perm), h('div', { class: 'row' }, h('button', { class: 'primary' }, 'Share'))),
    h('h2', {}, 'Public link (read-only)'),
    h('form', { class: 'stack', onsubmit: async (e) => {
      e.preventDefault();
      const expiresAt = new Date(Date.now() + Number(days.value) * 86400000).toISOString();
      try {
        const res = await api('POST', `/api/v1/nodes/${node.id}/shares`,
          { type: 'link', password: pw.value, expiresAt, maxDownloads: Number(maxDl.value) });
        pw.value = '';
        await refresh();
        showSecret('Public link created', 'Copy this link now. For your security it is stored only as a hash and cannot be shown again.', res.url);
      } catch (err) { toast(err.message); }
    } },
    h('label', {}, 'Password', pw), h('label', {}, 'Expires after (days)', days), h('label', {}, 'Download limit (0 = unlimited)', maxDl),
    h('div', { class: 'row' }, h('button', { class: 'primary' }, 'Create link'))),
    h('form', { method: 'dialog', class: 'row' }, h('button', {}, 'Close')));
  try { await refresh(); } catch (e) { toast(e.message); d.close(); }
}

async function sharedView() {
  const { items } = await api('GET', '/api/v1/shared-with-me');
  const rows = items.map((it) => h('tr', {},
    h('td', {}, h('div', { class: 'name' }, h('span', { class: 'icon' }, it.node.kind === 'folder' ? '📁' : '📄'),
      it.node.kind === 'folder'
        ? h('a', { href: `/f/${it.node.id}`, 'data-nav': '' }, it.node.name)
        : h('a', { href: `/api/v1/nodes/${it.node.id}/content`, download: '' }, it.node.name))),
    h('td', {}, it.share.permission === 'write' ? 'Can edit' : 'Can view'),
    h('td', { class: 'actions' }, h('button', { class: 'link danger', onclick: async () => {
      if (await confirmBox('Leave share', `Remove “${it.node.name}” from your shared items?`, 'Leave')) {
        await act(() => api('DELETE', `/api/v1/shares/${it.share.id}`), 'Removed');
      }
    } }, 'Leave'))));
  main.replaceChildren(h('div', { class: 'panel' }, h('h1', {}, 'Shared with me'),
    h('table', {}, h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { class: 'empty' }, 'Nothing has been shared with you yet.'))))));
}

// ---- trash ---------------------------------------------------------------------------------
async function trashView() {
  const { items } = await api('GET', '/api/v1/trash');
  const rows = items.map((it) => h('tr', {},
    h('td', {}, h('div', { class: 'name' }, h('span', { class: 'icon' }, it.kind === 'folder' ? '📁' : '📄'), it.name)),
    h('td', { class: 'num' }, `deleted ${fmtDate(it.trashedAt)}`),
    h('td', { class: 'num' }, `purged ${fmtDate(it.expiresAt)}`),
    h('td', { class: 'actions' },
      h('button', { class: 'link', onclick: async () => {
        try {
          await api('POST', `/api/v1/trash/${it.id}/restore`);
          toast('Restored');
        } catch (e) {
          if (e.status !== 409) return toast(e.message);
          const name = await prompt('Name in use', 'Restore under a new name', `${it.name} (restored)`);
          if (name) await act(() => api('POST', `/api/v1/trash/${it.id}/restore`, { name }), 'Restored');
        }
        route();
      } }, 'Restore'),
      h('button', { class: 'link danger', onclick: async () => {
        if (await confirmBox('Delete permanently', `Permanently delete “${it.name}”? This cannot be undone.`, 'Delete forever')) {
          await act(() => api('DELETE', `/api/v1/trash/${it.id}`), 'Deleting…');
        }
      } }, 'Delete forever'))));
  main.replaceChildren(h('div', { class: 'panel' },
    h('div', { class: 'toolbar' }, h('h1', { class: 'crumbs' }, 'Trash'),
      items.length > 0 && h('button', { class: 'danger', onclick: async () => {
        if (await confirmBox('Empty trash', 'Permanently delete everything in the trash?', 'Empty trash')) {
          await act(() => api('DELETE', '/api/v1/trash'), 'Emptying trash…');
        }
      } }, 'Empty trash')),
    h('table', {}, h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { class: 'empty' }, 'The trash is empty.'))))));
}

// ---- settings -------------------------------------------------------------------------------
async function settingsView() {
  let aps = [];
  let note = null;
  try { ({ appPasswords: aps } = await api('GET', '/api/v1/app-passwords')); } catch (e) { note = e.message; }
  const name = h('input', { placeholder: 'e.g. Laptop WebDAV', required: true });
  const ro = h('input', { type: 'checkbox' });
  const rows = aps.map((a) => h('tr', {},
    h('td', {}, a.name, a.readOnly ? ' (read-only)' : ''),
    h('td', { class: 'num' }, a.lastUsedAt ? `last used ${fmtDate(a.lastUsedAt)}` : 'never used'),
    h('td', { class: 'actions' }, h('button', { class: 'link danger', onclick: () =>
      act(() => api('DELETE', `/api/v1/app-passwords/${a.id}`), 'Revoked') }, 'Revoke'))));
  main.replaceChildren(h('div', { class: 'panel' },
    h('h1', {}, 'Settings'),
    h('h2', {}, 'App passwords'),
    h('p', { class: 'note' }, 'Use app passwords for WebDAV (', `${location.origin}/dav/`,
      ') and other non-browser clients. Each can be revoked on its own. Your sign-in password is never used here.'),
    note && h('p', { class: 'error' }, note),
    h('table', {}, h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { class: 'note' }, 'No app passwords.')))),
    h('form', { class: 'toolbar', onsubmit: async (e) => {
      e.preventDefault();
      try {
        const res = await api('POST', '/api/v1/app-passwords', { name: name.value, readOnly: ro.checked });
        showSecret('App password created', 'Copy it now: it cannot be shown again. Use any username with this password.', res.token);
        settingsView();
      } catch (err) { toast(err.message); }
    } }, name, h('label', {}, ro, ' read-only'), h('button', { class: 'primary' }, 'Create')),
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

async function signOut() {
  try {
    const { logoutUrl } = await api('POST', '/auth/logout');
    if (logoutUrl && /^https:\/\//.test(logoutUrl)) return location.assign(logoutUrl);
  } catch { /* fall through */ }
  location.assign('/');
}

// ---- public links ------------------------------------------------------------------------------
// The link token lives in the URL fragment, which browsers never send to the
// server. It is passed in POST bodies only, so it stays out of server logs.
async function publicLink(nodeId = '', password = '') {
  const token = location.hash.slice(1);
  document.getElementById('nav').hidden = true;
  let data;
  try {
    data = await api('POST', '/api/v1/public/node', { token, password, nodeId });
  } catch (e) {
    if (e.status === 401) return passwordPrompt(nodeId, e.detail.reason === 'password_wrong');
    return main.replaceChildren(h('div', { class: 'panel center' }, h('h1', {}, 'Link unavailable'), h('p', {}, e.message)));
  }
  const download = (id) => {
    // A same-origin form POST lets the browser save the file while keeping
    // the token out of the URL.
    const form = h('form', { method: 'POST', action: '/api/v1/public/download', hidden: true },
      h('input', { type: 'hidden', name: 'token', value: token }),
      h('input', { type: 'hidden', name: 'password', value: password }),
      h('input', { type: 'hidden', name: 'nodeId', value: id }));
    document.body.append(form);
    form.submit();
    form.remove();
  };
  const n = data.node;
  const body = n.kind === 'file'
    ? h('div', { class: 'center' }, h('h1', {}, n.name), h('p', { class: 'note' }, fmtSize(n.size)),
        h('button', { class: 'primary', onclick: () => download(n.id) }, 'Download'))
    : h('div', {},
        h('div', { class: 'toolbar' }, h('h1', { class: 'crumbs' }, n.name),
          n.id !== data.rootId && h('button', { onclick: () => publicLink('', password) }, 'Back to top')),
        h('table', {}, h('tbody', {}, data.children.length ? data.children.map((c) => h('tr', {},
          h('td', {}, h('div', { class: 'name' }, h('span', { class: 'icon' }, c.kind === 'folder' ? '📁' : '📄'),
            c.kind === 'folder'
              ? h('button', { class: 'link', onclick: () => publicLink(c.id, password) }, c.name)
              : h('button', { class: 'link', onclick: () => download(c.id) }, c.name))),
          h('td', { class: 'num' }, c.kind === 'file' ? fmtSize(c.size) : ''))) : h('tr', {}, h('td', { class: 'empty' }, 'Empty folder.')))));
  main.replaceChildren(h('div', { class: 'panel' }, body,
    data.expiresAt && h('p', { class: 'note' }, `This link expires ${fmtDate(data.expiresAt)}.`)));
}

function passwordPrompt(nodeId, wrong) {
  const pw = h('input', { type: 'password', required: true, autocomplete: 'off' });
  main.replaceChildren(h('div', { class: 'panel center' },
    h('h1', {}, 'Password required'),
    wrong && h('p', { class: 'error' }, 'Wrong password.'),
    h('form', { class: 'toolbar', onsubmit: (e) => { e.preventDefault(); publicLink(nodeId, pw.value); } },
      pw, h('button', { class: 'primary' }, 'Open'))));
  pw.focus();
}

route();
