/* ---------- theme: 'auto' follows the operating system, 'light' and 'dark' are fixed.
   One preference for the portal and every report (same browser storage key), applied before the first paint
   by the page <head>, kept in sync with system changes and with other open tabs. Inside the portal the
   embedded reports do not decide: the portal sends them its theme. ---------- */
const THEME_KEY = 'securityhub-theme', THEME_MODES = ['auto', 'light', 'dark'];
const THEME_TEXT = {auto: 'System', light: 'Light', dark: 'Dark'};
const THEME_TITLE = {auto: 'follow the system', light: 'light', dark: 'dark'};
const THEME_ICON = {auto: 'monitor', light: 'sun', dark: 'moon'};
const lightQuery = matchMedia('(prefers-color-scheme: light)');
const themeEmbedded = () => document.documentElement.dataset.embedded === '1';
function readTheme() {
  try {
    const t = localStorage.getItem(THEME_KEY);
    if (THEME_MODES.includes(t)) return t;
    // earlier versions: one choice per tool
    const old = [localStorage.getItem('guardhub-theme')].concat(['mailguard-prefs-v31', 'wafguard-prefs-v1', 'ztaguard-prefs-v1']
      .map(k => { try { return (JSON.parse(localStorage.getItem(k) || '{}') || {}).theme; } catch (e) { return null; } }));
    return old.find(x => x === 'light' || x === 'dark') || 'auto';
  } catch (e) { return 'auto'; }  // storage unavailable (sandboxed frame, privacy mode)
}
let themeMode = readTheme();
const isDark = () => { const t = document.documentElement.dataset.theme; return t ? t === 'dark' : !lightQuery.matches; };
function applyTheme() {
  if (themeEmbedded()) return;
  const D = document.documentElement;
  if (themeMode === 'auto') delete D.dataset.theme; else D.dataset.theme = themeMode;
}
function themeChanged() { if (typeof onThemeChange === 'function') onThemeChange(); else render(); }
function setTheme(mode) {
  themeMode = THEME_MODES.includes(mode) ? mode : 'auto';
  try { localStorage.setItem(THEME_KEY, themeMode); } catch (e) { /* storage unavailable: this page only */ }
  applyTheme(); themeChanged();
  if (typeof toast === 'function') toast(`Theme: ${THEME_TITLE[themeMode]}`);
}
function toggleTheme() { setTheme(THEME_MODES[(THEME_MODES.indexOf(themeMode) + 1) % THEME_MODES.length]); }
const themeActions = () => THEME_MODES.map(m => [`Theme: ${THEME_TITLE[m]}${m === themeMode ? ' (current)' : ''}`, () => setTheme(m)]);
function themeControl() {
  return `<div class="seg theme-seg" role="group" aria-label="Theme">${THEME_MODES.map(m =>
    `<button type="button" data-theme-mode="${m}" aria-pressed="${m === themeMode}" title="Theme: ${THEME_TITLE[m]}${m === 'auto' ? ` (now ${isDark() ? 'dark' : 'light'})` : ''}">${icon(THEME_ICON[m], 14)}<span>${THEME_TEXT[m]}</span></button>`).join('')}</div>`;
}
document.addEventListener('click', e => { const b = e.target.closest('[data-theme-mode]'); if (b) setTheme(b.dataset.themeMode); });
const onSystemTheme = () => { if (themeMode === 'auto' && !themeEmbedded()) themeChanged(); };
if (lightQuery.addEventListener) lightQuery.addEventListener('change', onSystemTheme); else lightQuery.addListener(onSystemTheme);
addEventListener('storage', e => { if (e.key === THEME_KEY && !themeEmbedded()) { themeMode = readTheme(); applyTheme(); themeChanged(); } });
