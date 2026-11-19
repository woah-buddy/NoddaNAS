// Applies the saved appearance before the first paint, so pages never flash
// the wrong theme. It runs synchronously in <head> (a plain same-origin
// script, as the CSP requires) and does one thing: set two attributes on
// <html>, and only to values that pass the same allowlist the server uses.
// Anything else in storage is ignored. The values are only ever matched by
// CSS attribute selectors; they are never inserted as markup or CSS.
(function () {
  'use strict';
  try {
    var saved = JSON.parse(window.localStorage.getItem('noddanas.appearance') || 'null');
    if (!saved || typeof saved !== 'object') return;
    var root = document.documentElement;
    if (saved.mode === 'light' || saved.mode === 'dark' || saved.mode === 'contrast') {
      root.setAttribute('data-theme', saved.mode);
    }
    if (typeof saved.accent === 'string' && /^[a-z][a-z0-9-]{0,23}$/.test(saved.accent)) {
      root.setAttribute('data-accent', saved.accent);
    }
  } catch (e) {
    // Storage blocked or corrupt: keep the defaults.
  }
})();
