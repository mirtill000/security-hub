const esc = v => String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, c => ESC[c]);
function closeOverlay() { $('#overlay-root').innerHTML = ''; pal = null; }
