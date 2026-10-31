const pct = (n, t) => t ? Math.round(100 * n / t) : 0;
function runPalette(k) { const it = pal && pal.items[k]; closeOverlay(); if (it) it.run(); }
function toggleTheme() { P.theme = isDark() ? 'light' : 'dark'; savePrefs(); applyTheme(); render(); }
function applyTheme() { if (P.theme) document.documentElement.dataset.theme = P.theme; }
