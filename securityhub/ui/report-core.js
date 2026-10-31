const pct = (n, t) => t ? Math.round(100 * n / t) : 0;
function runPalette(k) { const it = pal && pal.items[k]; closeOverlay(); if (it) it.run(); }
