(function () {
'use strict';
/* @include core.js */
/* @include report-core.js */
/* ================= data ================= */
const D = JSON.parse(document.getElementById('mg-data').textContent);
const T = D.tests, M = D.meta || {}, TEN = D.tenant || {}, diff = D.diff;
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
const $ = (s, r) => (r || document).querySelector(s);
const uniq = a => [...new Set(a.filter(Boolean))].sort();
const scoreCls = n => n === null || n === undefined ? '' : n >= 80 ? 'hi' : n >= 50 ? 'mid' : 'lo';
const gradeOf = n => n === null || n === undefined ? '-' : n >= 90 ? 'A' : n >= 80 ? 'B' : n >= 65 ? 'C' : n >= 50 ? 'D' : 'F';
const ST = {passed: ['pass', '\u2713', 'Passed'], failed: ['fail', '\u2715', 'Failed'], investigate: ['warn', '?', 'Investigate'],
  skipped: ['na', '\u00B7', 'Skipped'], planned: ['none', '\u2013', 'Planned'], error: ['dns', '!', 'Error'], other: ['none', '\u2013', 'Other']};
const ST_ORDER = ['failed', 'investigate', 'passed', 'error', 'skipped', 'planned', 'other'];
const LV = {high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown'};
const LV_ORDER = ['high', 'medium', 'low', 'unknown'];
const st = s => ST[s] || ST.other;
const pill = (s, extra) => { const m = st(s); return `<span class="pill s-${m[0]}"><span class="sym" aria-hidden="true">${m[1]}</span>${esc(m[2])}${extra ? ` <span class="d">${esc(extra)}</span>` : ''}</span>`; };
const riskPill = r => `<span class="pill ${({high: 's-fail', medium: 's-warn', low: 's-null'})[r] || 's-na'}">${esc(LV[r] || r)}</span>`;
const lvl = v => `<span class="lvl lvl-${esc(v)}">${esc(LV[v] || v)}</span>`;
T.forEach((t, i) => { t._i = i; t._text = (t.id + ' ' + t.title + ' ' + t.category + ' ' + t.sfi + ' ' + t.tags.join(' ')).toLowerCase(); });
const PILLARS = D.pillars.map(p => p.pillar);
function score(ts) { let n = 0, d = 0; ts.forEach(t => { const c = {passed: 1, investigate: 0.5, failed: 0}[t.status]; if (c === undefined) return;
  const w = D.weights.risk[t.risk] || 2; n += w * c; d += w; }); return d ? Math.round(100 * n / d) : null; }

/* ================= icons ================= */
const ICONS = {
  grid: '<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"/>', list: '<path d="M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5zM3 13l9 5 9-5"/>', diff: '<path d="M7 4v16M3.5 7.5 7 4l3.5 3.5M17 20V4M13.5 16.5 17 20l3.5-3.5"/>',
  building: '<path d="M4 21V4h11v17M15 9h5v12M8 8h3M8 12h3M8 16h3"/>', search: '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4-4"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>', x: '<path d="M6 6l12 12M18 6 6 18"/>', left: '<path d="m15 6-6 6 6 6"/>', right: '<path d="m9 6 6 6-6 6"/>',
  link: '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3A4.5 4.5 0 0 0 13 4.6l-1 1M14 10a4.5 4.5 0 0 0-6.4 0l-3 3A4.5 4.5 0 0 0 11 19.4l1-1"/>',
  print: '<path d="M6 9V3h12v6M6 18H4v-7h16v7h-2M8 14h8v7H8z"/>', download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>', filter: '<path d="M3 5h18l-7 8.5V19l-4 2v-7.5L3 5z"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>', key: '<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.4 8.6 8 9.5 4.6-.9 8-4.5 8-9.5V6l-8-3z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>', bolt: '<path d="M13 2 4 14h7l-1 8 9-12h-7l1-8z"/>'
};
const icon = (n, s) => `<svg class="ico" width="${s || 16}" height="${s || 16}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;
function ring(v) { const r = 26, c = 2 * Math.PI * r, off = c * (1 - (v || 0) / 100);
  return `<svg class="ring ${scoreCls(v)}" width="64" height="64" viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="${r}" class="ring-bg"/><circle cx="32" cy="32" r="${r}" class="ring-fg" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 32 32)"/></svg>`; }
function statusRing(t) { const m = st(t.status); return `<div class="st-badge c-${m[0]}" aria-hidden="true">${m[1]}</div>`; }

/* ================= safe markdown (TestResult / TestDescription) ================= */
function inline(s) {
  let h = esc(s).replace(/&lt;br\s*\/?&gt;/gi, '<br>');
  h = h.replace(/`([^`]+)`/g, '<code>$1</code>');
  h = h.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, txt, url) => /^(https?:|mailto:)/i.test(url) ? `<a href="${url}" target="_blank" rel="noopener noreferrer">${txt}</a>` : txt);
  h = h.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/__([^_]+)__/g, '<b>$1</b>');
  h = h.replace(/(^|[\s(])\*([^*\s][^*]*?)\*(?=[\s).,;:!?]|$)/g, '$1<i>$2</i>');
  h = h.replace(/(https?:\/\/[^\s<"]+)(?![^<]*<\/a>)(?![^<]*">)/g, m => `<a href="${m}" target="_blank" rel="noopener noreferrer">${m}</a>`);
  return h;
}
function md(src) {
  if (!src) return '';
  const lines = String(src).replace(/\r\n?/g, '\n').split('\n'), out = [];
  let i = 0;
  const cells = l => l.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
  while (i < lines.length) {
    const l = lines[i];
    if (!l.trim()) { i++; continue; }
    if (/^\s*```/.test(l)) { const b = []; i++; while (i < lines.length && !/^\s*```/.test(lines[i])) b.push(lines[i++]); i++; out.push(`<pre class="record">${esc(b.join('\n'))}</pre>`); continue; }
    const h = l.match(/^\s*(#{1,6})\s+(.*)$/);
    if (h) { const lv = Math.min(6, h[1].length + 2); out.push(`<h${lv} class="md-h">${inline(h[2])}</h${lv}>`); i++; continue; }
    if (/^\s*\|.*\|\s*$/.test(l) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
      const head = cells(l); i += 2; const rows = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) rows.push(cells(lines[i++]));
      out.push(`<div class="md-table"><table><thead><tr>${head.map(c => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(c => `<td>${inline(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
      continue;
    }
    if (/^\s*([-*+]|\d+\.)\s+/.test(l)) {
      const ordered = /^\s*\d+\./.test(l), items = [];
      while (i < lines.length && /^\s*([-*+]|\d+\.)\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*([-*+]|\d+\.)\s+/, '')); i++;
        while (i < lines.length && lines[i].trim() && !/^\s*([-*+]|\d+\.)\s+/.test(lines[i]) && /^\s{2,}/.test(lines[i])) items[items.length - 1] += ' ' + lines[i++].trim(); }
      out.push(`<${ordered ? 'ol' : 'ul'} class="md-list">${items.map(x => `<li>${inline(x)}</li>`).join('')}</${ordered ? 'ol' : 'ul'}>`);
      continue;
    }
    if (/^\s*>/.test(l)) { const b = []; while (i < lines.length && /^\s*>/.test(lines[i])) b.push(lines[i++].replace(/^\s*>\s?/, '')); out.push(`<blockquote class="note-box">${inline(b.join(' '))}</blockquote>`); continue; }
    if (/^\s*(-{3,}|\*{3,})\s*$/.test(l)) { out.push('<hr class="md-hr">'); i++; continue; }
    const p = [];
    while (i < lines.length && lines[i].trim() && !/^\s*(#{1,6}\s|```|\||([-*+]|\d+\.)\s|>)/.test(lines[i])) p.push(lines[i++]);
    if (!p.length) { out.push(`<p>${inline(lines[i++])}</p>`); continue; }
    out.push(`<p>${p.map(inline).join('<br>')}</p>`);
  }
  return `<div class="md">${out.join('')}</div>`;
}

/* ================= preferences & state ================= */
const PREF_KEY = 'ztaguard-prefs-v1';
const P = {density: 'comfortable', size: 50, theme: null, group: 'none'};
try { Object.assign(P, JSON.parse(localStorage.getItem(PREF_KEY) || '{}')); } catch (e) { /* storage unavailable */ }
const savePrefs = () => { try { localStorage.setItem(PREF_KEY, JSON.stringify(P)); } catch (e) { /* ignore */ } };
const FKEYS = ['q', 'status', 'pillar', 'risk', 'impact', 'cost', 'category', 'sfi', 'license', 'tag', 'changed', 'quick'];
const blank = () => Object.fromEntries(FKEYS.map(k => [k, '']));
const S = Object.assign({route: 'overview', sort: {k: 'priority', d: -1}, page: 1, open: null, dtab: 'result', cursor: -1, filtersOpen: false}, blank());
const ROUTES = [
  {id: 'overview', label: 'Overview', icon: 'grid', show: () => true},
  {id: 'tests', label: 'Tests', icon: 'list', show: () => true, count: () => T.length},
  {id: 'categories', label: 'Categories', icon: 'layers', show: () => true, count: () => uniq(T.map(t => t.category)).length},
  {id: 'changes', label: 'Changes', icon: 'diff', show: () => !!diff, count: () => T.filter(t => t.change && (t.change.new || t.change.from)).length},
  {id: 'tenant', label: 'Tenant', icon: 'building', show: () => !!(D.tenant_info || TEN.id)}
];
function toHash() {
  const p = new URLSearchParams();
  FKEYS.forEach(k => { if (S[k]) p.set(k, S[k]); });
  if (S.sort.k !== 'priority' || S.sort.d !== -1) p.set('sort', (S.sort.d < 0 ? '-' : '') + S.sort.k);
  if (S.page > 1) p.set('page', S.page);
  if (S.open !== null) { p.set('d', T[S.open].id); if (S.dtab !== 'result') p.set('t', S.dtab); }
  const qs = p.toString();
  return '#/' + S.route + (qs ? '?' + qs : '');
}
function fromHash() {
  const h = location.hash.replace(/^#\/?/, ''), qi = h.indexOf('?');
  const route = qi >= 0 ? h.slice(0, qi) : h, p = new URLSearchParams(qi >= 0 ? h.slice(qi + 1) : '');
  Object.assign(S, blank());
  S.route = ROUTES.some(r => r.id === route && r.show()) ? route : 'overview';
  FKEYS.forEach(k => { if (p.has(k)) S[k] = p.get(k); });
  const so = p.get('sort'); S.sort = so ? {k: so.replace(/^-/, ''), d: so.startsWith('-') ? -1 : 1} : {k: 'priority', d: -1};
  S.page = Math.max(1, +p.get('page') || 1);
  const d = p.get('d'), t = d ? T.find(x => x.id === d) : null;
  S.open = t ? t._i : null; S.dtab = p.get('t') || 'result';
}
function go(ch, push) { Object.assign(S, ch); const h = toHash(); if (location.hash !== h) history[push === false ? 'replaceState' : 'pushState'](null, '', h); render(); }
window.addEventListener('popstate', () => { fromHash(); render(); });
const filterTo = extra => go(Object.assign(blank(), {route: 'tests', open: null, page: 1, cursor: -1}, extra));

/* ================= filtering ================= */
function matches(t) {
  const q = S.q.trim().toLowerCase();
  if (q && !t._text.includes(q)) return false;
  if (S.status && !S.status.split(',').includes(t.status)) return false;
  if (S.pillar && !t.pillars.includes(S.pillar)) return false;
  if (S.risk && t.risk !== S.risk) return false;
  if (S.impact && t.impact !== S.impact) return false;
  if (S.cost && t.cost !== S.cost) return false;
  if (S.category && t.category !== S.category) return false;
  if (S.sfi && t.sfi !== S.sfi) return false;
  if (S.license && t.license !== S.license) return false;
  if (S.tag && !t.tags.includes(S.tag)) return false;
  if (S.quick && !t.quick_win) return false;
  if (S.changed) { const c = t.change; if (!c || !(c.new || c.from)) return false; if (S.changed !== '1' && c.kind !== S.changed && !(S.changed === 'new' && c.new)) return false; }
  return true;
}
const RANK = {high: 3, medium: 2, low: 1, unknown: 0};
const SORTERS = {priority: t => t.priority, title: t => t.title.toLowerCase(), id: t => t.id, status: t => ST_ORDER.indexOf(t.status),
  risk: t => RANK[t.risk], impact: t => RANK[t.impact], cost: t => RANK[t.cost], category: t => t.category.toLowerCase(), pillar: t => t.pillars.join(',')};
function list() {
  const a = T.filter(matches), fn = SORTERS[S.sort.k] || SORTERS.priority, d = S.sort.d;
  return a.sort((x, y) => { const p = fn(x), q = fn(y); return (p < q ? -1 : p > q ? 1 : 0) * d || RANK[y.risk] - RANK[x.risk] || x.title.localeCompare(y.title); });
}
const CHIP_LABEL = {q: v => `Search "${v}"`, status: v => 'Status: ' + v.split(',').map(s => st(s)[2]).join(' or '), pillar: v => `Pillar ${v}`,
  risk: v => `Risk ${LV[v]}`, impact: v => `User impact ${LV[v]}`, cost: v => `Effort ${LV[v]}`, category: v => v, sfi: v => `SFI: ${v}`,
  license: v => `License ${v}`, tag: v => `#${v}`, changed: v => v === '1' ? 'Changed since baseline' : `Change: ${v}`, quick: () => 'Quick wins'};

/* ================= frame ================= */
const isDark = () => { const t = document.documentElement.dataset.theme; return t ? t === 'dark' : !matchMedia('(prefers-color-scheme: light)').matches; };
function side() {
  const sc = D.score, g = gradeOf(sc);
  return `<div class="brand"><div class="brand-mark">${icon('shield', 18)}</div><div><b>ZTAGuard</b><small>Zero Trust posture</small></div></div>
    <button class="posture" data-route="overview" title="Tenant grade"><span class="letter g-${g}">${g}</span><span><b class="num">${sc === null ? '-' : sc + '/100'}</b><br>${esc(TEN.name || TEN.domain || 'Tenant')}</span></button>
    <nav class="nav" aria-label="Sections">${ROUTES.filter(r => r.show()).map((r, k) => { const c = r.count ? r.count() : null;
      return `<button class="nav-item" data-route="${r.id}"${S.route === r.id ? ' aria-current="page"' : ''} title="${esc(r.label)} (${k + 1})">${icon(r.icon)}<span>${esc(r.label)}</span>${c !== null ? `<span class="count">${c}</span>` : ''}</button>`; }).join('')}
      <div class="nav-sep">Pillars</div>
      ${D.pillars.map(p => `<button class="nav-item${S.route === 'tests' && S.pillar === p.pillar ? ' on' : ''}" data-pillar="${esc(p.pillar)}"><span class="pdot ${scoreCls(p.score)}"></span><span>${esc(p.pillar)}${pillarSankeys(p.pillar).length ? ' <span class="faint" title="Includes charts">\u25D4</span>' : ''}</span><span class="count">${p.passed}/${p.total}</span></button>`).join('')}</nav>
    <div class="side-foot">
      <button class="nav-item" data-action="about">${icon('info')}<span>About this report</span></button>
      <button class="nav-item" data-action="keys">${icon('key')}<span>Keyboard shortcuts</span><span class="count"><span class="kbd">?</span></span></button>
      <button class="nav-item" data-action="theme">${icon(isDark() ? 'sun' : 'moon')}<span>${isDark() ? 'Light theme' : 'Dark theme'}</span></button></div>`;
}
function topbar() {
  const r = ROUTES.find(x => x.id === S.route) || ROUTES[0];
  const n = S.route === 'tests' ? list().length : null;
  const sub = S.route === 'tests' ? (n === T.length ? `${T.length} tests` : `${n} of ${T.length} tests`) : S.route === 'overview' ? `${esc(TEN.name || '')} ${TEN.executed_at ? 'assessed ' + esc(fmtDate(TEN.executed_at)) : ''}` : '';
  return `<h1>${esc(S.route === 'tests' && S.pillar ? S.pillar : r.label)}</h1><span class="sub">${sub}</span><span class="spacer"></span>
    <button class="cmdk" data-action="palette" aria-label="Search tests and actions">${icon('search')}<span class="lbl">Search tests, categories, actions</span><span class="kbd">Ctrl K</span></button>
    <button class="btn" data-action="print-exec">${icon('print')}<span>Executive PDF</span></button>`;
}
function fmtDate(s) { const d = new Date(s); return isNaN(d) ? s : d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'; }

/* ================= overview ================= */
function overview() {
  const c = s => T.filter(t => t.status === s).length;
  const sc = D.score, g = gradeOf(sc), outdated = TEN.latest_version && TEN.version && TEN.latest_version !== TEN.version;
  const kpi = (v, l, cls, attrs) => `<button class="kpi ${cls || ''}" ${attrs}><b>${v}</b><span>${esc(l)}</span></button>`;
  let h = `<div class="print-head"><h1>Zero Trust posture: ${esc(M.title)}</h1><p class="muted">${esc(TEN.domain || '')} ${TEN.executed_at ? ', assessed ' + esc(fmtDate(TEN.executed_at)) : ''}</p></div>
  <div class="ov-top"><section class="card grade-card"><div class="letter g-${g}">${g}</div><div class="lbl">Tenant grade</div>
    <div class="avg">${sc === null ? '-' : sc}<small>/100</small></div>
    <div class="lbl">Risk-weighted pass rate${diff && diff.score_before !== null ? `, <span class="${sc >= diff.score_before ? 'delta-up' : 'delta-down'}">${sc - diff.score_before >= 0 ? '+' : ''}${sc - diff.score_before} since baseline</span>` : ''}</div></section>
  <section class="card kpi-card">${kpi(T.length, 'tests', '', 'data-route="tests"')}${kpi(c('passed'), 'passed', 'k-pass', 'data-status="passed"')}
    ${kpi(c('failed'), 'failed', 'k-fail', 'data-status="failed"')}${kpi(c('investigate'), 'to investigate', 'k-warn', 'data-status="investigate"')}
    ${kpi(c('skipped') + c('planned') + c('error') + c('other'), 'skipped, planned or error', '', 'data-status="skipped,planned,error,other"')}</section></div>`;
  if (outdated) h += `<p class="note-box" style="margin-bottom:16px">Assessment run with module version ${esc(TEN.version)}; version ${esc(TEN.latest_version)} is available and may include more tests.</p>`;
  const viz = vizCards();
  const flows = uniq(VIZ().sankeys.map(s => s.pillar)).filter(Boolean);
  if (viz.length || flows.length) h += `<div class="section-title" style="margin-top:8px"><h2>Tenant posture</h2><p>From the tenant data collected by the assessment${flows.length ? `. Authentication and device flows are in ${flows.map(p => `<button class="link" data-pillar="${esc(p)}">${esc(p)}</button>`).join(' and ')}` : ''}</p></div>${viz.length ? `<div class="viz-grid">${viz.join('')}</div>` : ''}<div class="section-title"><h2>Assessment results</h2></div>`;
  h += '<div class="ov-grid">';
  const present = new Set();
  h += `<section class="card span2"><header><h2>Pillars</h2><p>Test results per Zero Trust pillar. Select a segment to list those tests.</p></header><div class="body"><div class="cov">${D.pillars.map(p => {
    const segs = ST_ORDER.filter(s => p[s]).map(s => { present.add(s); return `<button class="c-${st(s)[0]}" style="flex:${p[s]}" data-pillar="${esc(p.pillar)}" data-pst="${s}" title="${esc(p.pillar + ': ' + p[s] + ' ' + st(s)[2].toLowerCase())}" aria-label="${esc(p.pillar + ': ' + p[s] + ' ' + st(s)[2].toLowerCase())}"></button>`; }).join('');
    return `<div class="cov-row" style="grid-template-columns:110px minmax(0,1fr) 92px"><button class="link" data-pillar="${esc(p.pillar)}" style="color:var(--text)">${esc(p.pillar)}</button><div class="cov-bar">${segs}</div><span class="cov-num"><span class="score ${scoreCls(p.score)}">${p.score === null ? '-' : p.score}</span> <span class="faint">${p.passed}/${p.total}</span></span></div>`; }).join('')}</div>
    <div class="legend">${ST_ORDER.filter(s => present.has(s)).map(s => `<span><i class="dot c-${st(s)[0]}"></i>${st(s)[2]}</span>`).join('')}<span class="faint">Score = pass rate weighted by risk</span></div></div></section>`;
  // risk x status
  const rs = ['high', 'medium', 'low'], cols = [['failed', 'var(--fail)'], ['investigate', 'var(--warn)'], ['passed', 'var(--pass)']];
  const cnt = (r, s) => T.filter(t => t.risk === r && t.status === s).length, mx = Math.max(1, ...rs.flatMap(r => cols.map(c => cnt(r, c[0]))));
  h += `<section class="card"><header><h2>Risk and result</h2></header><div class="body"><div class="rm"><div class="rm-row" style="grid-template-columns:70px repeat(3,minmax(0,1fr))"><span></span>${cols.map(c => `<span class="rm-head">${st(c[0])[2]}</span>`).join('')}</div>
    ${rs.map(r => `<div class="rm-row" style="grid-template-columns:70px repeat(3,minmax(0,1fr))">${riskPill(r)}${cols.map(([s, col]) => { const v = cnt(r, s);
      return `<button class="rm-cell${v ? '' : ' zero'}" style="background:color-mix(in srgb, ${col} ${v ? 12 + Math.round(48 * v / mx) : 4}%, transparent)" data-risk="${r}" data-rst="${s}" aria-label="${v} ${r} risk tests ${s}">${v}</button>`; }).join('')}</div>`).join('')}</div></div></section>`;
  const fix = T.filter(t => t.priority > 0).sort((a, b) => b.priority - a.priority).slice(0, 7);
  h += `<section class="card"><header><h2>Fix first</h2><p>Risk, effort and user impact</p></header><div class="body"><ul class="rows">${fix.map(t => `<li><button class="r-btn" data-open="${t._i}"><span class="r-main">${esc(t.title)}</span><span class="r-val">${riskPill(t.risk)}</span>
    <span class="r-sub">${esc(t.pillars.join(', '))}, ${st(t.status)[2].toLowerCase()}, effort ${esc((LV[t.cost] || '').toLowerCase())}</span></button></li>`).join('') || '<li class="muted">Nothing to fix.</li>'}</ul></div></section>`;
  const quick = T.filter(t => t.quick_win).sort((a, b) => b.priority - a.priority);
  h += `<section class="card"><header><h2>Quick wins</h2><p>Low effort, low user impact</p><span class="act"><button class="link" data-quick="1">All ${quick.length}</button></span></header><div class="body"><ul class="rows">${quick.slice(0, 6).map(t => `<li><button class="r-btn" data-open="${t._i}"><span class="r-main">${esc(t.title)}</span><span class="r-val">${riskPill(t.risk)}</span>
    <span class="r-sub">${esc(t.category)}</span></button></li>`).join('') || '<li class="muted">No quick wins left.</li>'}</ul></div></section>`;
  const sfi = uniq(T.map(t => t.sfi));
  if (sfi.length) h += `<section class="card"><header><h2>Secure Future Initiative</h2><p>Pass rate per SFI pillar</p></header><div class="body">${sfi.map(s => { const ts = T.filter(t => t.sfi === s), ev = ts.filter(t => ['passed', 'failed', 'investigate'].includes(t.status)), ok = ts.filter(t => t.status === 'passed').length;
    return `<button class="bar-row" data-sfi="${esc(s)}"><span>${esc(s)}</span><span class="bar"><i class="b-pass" style="width:${pct(ok, ev.length)}%"></i></span><span>${ok}/${ev.length}</span></button>`; }).join('')}</div></section>`;
  const ov = (D.tenant_info || {}).TenantOverview || (D.tenant_info || {}).tenantOverview;
  if (ov && typeof ov === 'object') { const nums = Object.entries(ov).filter(([, v]) => typeof v === 'number').slice(0, 8);
    if (nums.length) h += `<section class="card"><header><h2>Tenant</h2><p>${esc(TEN.domain || '')}</p></header><div class="body"><div class="stat-strip">${nums.map(([k, v]) => `<div class="stat"><b>${v.toLocaleString()}</b><span>${esc(k.replace(/([a-z])([A-Z])/g, '$1 $2'))}</span></div>`).join('')}</div></div></section>`; }
  if (diff) h += `<section class="card"><header><h2>Since the baseline</h2><p>${esc(diff.baseline_date ? fmtDate(diff.baseline_date) : diff.baseline)}</p></header><div class="body"><div class="stat-strip">
    <button class="stat" data-changed="fixed"><b class="delta-up">${diff.fixed}</b><span>fixed</span></button><button class="stat" data-changed="regressed"><b class="delta-down">${diff.regressed}</b><span>regressed</span></button>
    <button class="stat" data-changed="new"><b>${diff.new_tests}</b><span>new tests</span></button><button class="stat" data-route="changes"><b>${diff.removed_tests.length}</b><span>removed</span></button></div></div></section>`;
  return h + '</div>';
}

/* ================= tests ================= */
const PRESETS = () => [['All tests', {}], ['Failed, high risk', {status: 'failed', risk: 'high'}], ['Failed or investigate', {status: 'failed,investigate'}],
  ['Quick wins', {quick: '1'}], ...(diff ? [['Regressed', {changed: 'regressed'}], ['Fixed', {changed: 'fixed'}]] : []), ['Skipped', {status: 'skipped'}]];
function presetActive(p) { const t = Object.assign(blank(), p[1]); return FKEYS.every(k => (S[k] || '') === (t[k] || '')); }
function tests() {
  const all = list(), pages = Math.max(1, Math.ceil(all.length / P.size));
  if (S.page > pages) S.page = pages;
  const items = all.slice((S.page - 1) * P.size, S.page * P.size);
  const chips = FKEYS.filter(k => S[k]).map(k => [k, CHIP_LABEL[k](S[k])]);
  const counts = PRESETS().map(p => { const keep = {}; FKEYS.forEach(k => keep[k] = S[k]); Object.assign(S, blank(), p[1]); const n = T.filter(matches).length; Object.assign(S, keep); return n; });
  let h = pillarPanel() + `<div class="presets" role="group" aria-label="Saved views">${PRESETS().map((p, k) => `<button class="preset" data-preset="${k}" aria-pressed="${presetActive(p)}">${esc(p[0])}<span class="n">${counts[k]}</span></button>`).join('')}</div>
  <div class="toolbar"><div class="search-box">${icon('search')}<input type="search" id="q" placeholder="Filter by title, ID, category or tag" value="${esc(S.q)}" aria-label="Filter tests"></div>
    <button class="btn" data-action="filters" aria-expanded="${S.filtersOpen}">${icon('filter')}Filters${chips.length ? `<span class="badge-n">${chips.length}</span>` : ''}</button><span class="spacer"></span>
    <label class="field" style="flex-direction:row;align-items:center;gap:8px;display:flex">Group<select data-k="group" aria-label="Group by">${[['none', 'None'], ['category', 'Category'], ['pillar', 'Pillar'], ['risk', 'Risk']].map(([v, l]) => `<option value="${v}"${P.group === v ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
    <div class="seg" role="group" aria-label="Density"><button data-density="comfortable" aria-pressed="${P.density === 'comfortable'}">Comfortable</button><button data-density="compact" aria-pressed="${P.density === 'compact'}">Compact</button></div>
    <button class="btn" data-action="csv">${icon('download')}CSV</button></div>`;
  if (S.filtersOpen) h += filterPanel();
  h += `<div class="chips">${chips.length ? chips.map(([k, l]) => `<span class="chip">${esc(l)}<button data-chip="${k}" aria-label="Remove filter ${esc(l)}">${icon('x', 12)}</button></span>`).join('') + '<button class="link" data-action="clear">Clear all</button>' : `<span>${all.length} tests</span>`}</div>`;
  if (!all.length) return h + `<div class="grid-wrap"><div class="empty"><b>No test matches these filters</b><button class="btn" data-action="clear">Clear filters</button></div></div>`;
  return h + `<div class="grid-wrap" id="grid">${table(P.group === 'none' ? items : all)}</div>` + (P.group === 'none' ? pager(all.length, pages) : '');
}
function filterPanel() {
  const sel = (k, label, opts, fmt) => `<label class="field">${esc(label)}<select data-k="${k}"><option value="">All</option>${opts.map(o => `<option value="${esc(o)}"${S[k] === o ? ' selected' : ''}>${esc(fmt ? fmt(o) : o)}</option>`).join('')}</select></label>`;
  return `<div class="filter-panel">${sel('status', 'Status', ST_ORDER.filter(s => T.some(t => t.status === s)), s => st(s)[2])}${sel('pillar', 'Pillar', PILLARS)}
    ${sel('risk', 'Risk', LV_ORDER.filter(v => T.some(t => t.risk === v)), v => LV[v])}${sel('impact', 'User impact', LV_ORDER.filter(v => T.some(t => t.impact === v)), v => LV[v])}
    ${sel('cost', 'Implementation effort', LV_ORDER.filter(v => T.some(t => t.cost === v)), v => LV[v])}${sel('category', 'Category', uniq(T.map(t => t.category)))}
    ${uniq(T.map(t => t.sfi)).length ? sel('sfi', 'SFI pillar', uniq(T.map(t => t.sfi))) : ''}${uniq(T.map(t => t.license)).length ? sel('license', 'Minimum license', uniq(T.map(t => t.license))) : ''}
    ${uniq(T.flatMap(t => t.tags)).length ? sel('tag', 'Tag', uniq(T.flatMap(t => t.tags))) : ''}
    ${diff ? sel('changed', 'Change', ['1', 'fixed', 'regressed', 'changed', 'new'], v => ({'1': 'Any change', fixed: 'Fixed', regressed: 'Regressed', changed: 'Other change', new: 'New test'})[v]) : ''}</div>`;
}
function th(k, label, cls) { const cur = S.sort.k === k ? (S.sort.d > 0 ? 'ascending' : 'descending') : 'none';
  return `<th class="${cls || ''}" aria-sort="${cur}"><button class="sort" data-sort="${k}">${esc(label)}</button></th>`; }
function row(t, k) {
  const ch = t.change, chHtml = !ch ? '' : ch.new ? '<span class="tag">new</span>' : ch.from ? `<span class="tag ${ch.kind === 'fixed' ? 'chg-up' : ch.kind === 'regressed' ? 'chg-down' : ''}">${esc(ch.kind)}: was ${esc(st(ch.from)[2].toLowerCase())}</span>` : '';
  return `<tr data-row="${t._i}" class="${k === S.cursor ? 'cursor ' : ''}${S.open === t._i ? 'active' : ''}"><td>${pill(t.status)}</td>
    <td class="sticky"><button class="dom" data-open="${t._i}" style="word-break:normal">${esc(t.title)}</button>${P.density !== 'compact' ? `<div class="dom-sub">${esc(t.id)}, ${esc(t.category)}${t.license ? ', ' + esc(t.license) : ''}</div>` : ''}${chHtml ? '<div style="margin-top:3px">' + chHtml + '</div>' : ''}</td>
    <td class="nowrap">${esc(t.pillars.join(', '))}</td><td>${riskPill(t.risk)}</td><td>${lvl(t.impact)}</td><td>${lvl(t.cost)}</td><td class="r num">${t.priority || '<span class="faint">0</span>'}</td></tr>`;
}
function table(items) {
  const head = `<thead><tr>${th('status', 'Status')}${th('title', 'Test', 'sticky')}${th('pillar', 'Pillar')}${th('risk', 'Risk')}${th('impact', 'User impact')}${th('cost', 'Effort')}${th('priority', 'Priority', 'r')}</tr></thead>`;
  if (P.group === 'none') return `<table class="grid${P.density === 'compact' ? ' compact' : ''}">${head}<tbody>${items.map(row).join('')}</tbody></table>`;
  const key = {category: t => [t.category], pillar: t => t.pillars, risk: t => [LV[t.risk]]}[P.group];
  const groups = {};
  items.forEach(t => key(t).forEach(g => (groups[g] = groups[g] || []).push(t)));
  const names = Object.keys(groups).sort((a, b) => P.group === 'risk' ? LV_ORDER.indexOf(a.toLowerCase()) - LV_ORDER.indexOf(b.toLowerCase()) : a.localeCompare(b));
  return `<table class="grid${P.density === 'compact' ? ' compact' : ''}">${head}<tbody>${names.map(g => { const ts = groups[g], sc = score(ts), f = ts.filter(t => t.status === 'failed').length;
    return `<tr class="grp"><td colspan="7"><b>${esc(g)}</b> <span class="faint">${ts.length} tests, ${f} failed</span> ${sc === null ? '' : `<span class="score ${scoreCls(sc)}">${sc}</span>`}</td></tr>${ts.map(row).join('')}`; }).join('')}</tbody></table>`;
}
function pager(total, pages) {
  const cur = S.page, nums = [];
  for (let p = 1; p <= pages; p++) if (p === 1 || p === pages || Math.abs(p - cur) <= 2) nums.push(p);
  let prev = 0, out = '';
  nums.forEach(p => { if (p - prev > 1) out += '<span class="faint">\u2026</span>'; out += `<button class="btn small" data-page="${p}"${p === cur ? ' aria-current="page"' : ''}>${p}</button>`; prev = p; });
  return `<nav class="pager" aria-label="Pagination"><span>Rows ${total ? (cur - 1) * P.size + 1 : 0} to ${Math.min(cur * P.size, total)} of ${total}
    <select data-k="size" aria-label="Rows per page" style="margin-left:8px">${[25, 50, 100, 250].map(s => `<option value="${s}"${s === P.size ? ' selected' : ''}>${s} per page</option>`).join('')}</select></span>
    ${pages > 1 ? `<div class="pages"><button class="btn small" data-page="${cur - 1}"${cur <= 1 ? ' disabled' : ''}>${icon('left', 14)}Previous</button>${out}<button class="btn small" data-page="${cur + 1}"${cur >= pages ? ' disabled' : ''}>Next${icon('right', 14)}</button></div>` : ''}
    <span class="faint">Keys: <span class="kbd">j</span> <span class="kbd">k</span> move, <span class="kbd">Enter</span> open</span></nav>`;
}

/* ================= tenant visuals (TenantInfo): sankey, donut, splits, OS bars ================= */
const VIZ_TITLES = {
  overviewauthmethodsprivilegedusers: ['Privileged users auth methods', 'Strongest authentication method registered by privileged users.', 'Identity'],
  overviewauthmethodsallusers: ['All users auth methods', 'Strongest authentication method registered by all users.', 'Identity'],
  overviewcamfaallusers: ['User authentication', 'Sign-ins protected by Conditional Access policies enforcing multifactor authentication.', 'Identity'],
  overviewcadevicesallusers: ['Device sign-ins', 'Sign-ins by device management and compliance state.', 'Devices'],
  desktopdevicessummary: ['Desktop devices', 'Join type and compliance of desktop devices.', 'Devices'],
  mobilesummary: ['Mobile devices', 'Platform and compliance of mobile devices.', 'Devices']
};
const VIZ_ORDER = Object.keys(VIZ_TITLES);
const normKey = k => String(k).toLowerCase().replace(/[^a-z0-9]/g, '');
const human = k => String(k).replace(/^Overview/, '').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
const num = v => { const n = typeof v === 'number' ? v : parseFloat(v); return isFinite(n) ? n : 0; };
const fmtK = n => n >= 1e6 ? (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K' : String(Math.round(n));
function ciGet(o, ...names) { if (!o || typeof o !== 'object') return undefined; const m = {}; Object.keys(o).forEach(k => { m[normKey(k)] = o[k]; }); for (const n of names) { const v = m[normKey(n)]; if (v !== undefined && v !== null) return v; } return undefined; }
function asLinks(arr) {
  if (!Array.isArray(arr) || !arr.length) return null;
  const ok = arr.filter(x => x && typeof x === 'object' && ciGet(x, 'source') !== undefined && ciGet(x, 'target') !== undefined);
  if (ok.length < Math.max(1, arr.length / 2)) return null;
  return ok.map(x => ({source: String(ciGet(x, 'source')), target: String(ciGet(x, 'target')), value: num(ciGet(x, 'value'))}));
}
function nodeClass(name) {
  const n = name.toLowerCase();
  if (/single ?factor|no ca|non.?compliant|unmanaged|unprotected|not covered|no mfa|password only|^none$|disabled/.test(n)) return 'bad';
  if (/phish.?resistant|passkey|whfb|windows hello|fido|certificate|^mfa$|multifactor|^compliant|^protected|ca applied|sensor installed|covered/.test(n)) return 'good';
  if (/phishable|phone|sms|voice|authenticator|email|otp|software|registered/.test(n)) return 'warn';
  if (/managed|joined/.test(n)) return 'mid';
  if (/^(ios|ipados|android|windows|macos|linux)$/.test(n)) return 'plat';
  return 'root';
}
const VIZ_COLOR = {good: 'var(--pass)', bad: 'var(--fail)', warn: 'var(--warn)', mid: '#e8735a', plat: 'var(--null)', root: '#f08a24', purple: '#9b6fd6'};
function discoverVisuals(info) {
  const out = {sankeys: [], splits: [], osbars: []};
  if (!info || typeof info !== 'object') return out;
  const seen = new Set();
  (function walk(o, key, depth) {
    if (!o || typeof o !== 'object' || depth > 6 || seen.has(o)) return;
    seen.add(o);
    const links = Array.isArray(o) ? asLinks(o) : asLinks(ciGet(o, 'nodes', 'links', 'data'));
    if (links && links.some(l => l.value > 0)) {
      const meta = VIZ_TITLES[normKey(key)] || [human(key), '', /device|desktop|mobile/i.test(key) ? 'Devices' : /auth|mfa|ca|sign/i.test(key) ? 'Identity' : ''];
      out.sankeys.push({key, title: meta[0], sub: (!Array.isArray(o) && ciGet(o, 'description')) || meta[1], pillar: meta[2], links});
      return;
    }
    if (!Array.isArray(o)) {
      const nums = Object.entries(o).filter(([, v]) => typeof v === 'number' || (typeof v === 'string' && v.trim() !== '' && isFinite(+v)));
      const pick = (re, not) => nums.filter(([k]) => re.test(normKey(k)) && !(not && not.test(normKey(k))));
      const pairs = [
        [pick(/^compliant|compliantcount|compliantdevice/, /non/), pick(/noncompliant/), 'Device compliance', ['Compliant', 'Non-compliant'], ['good', 'bad']],
        [pick(/corporate/), pick(/personal/), 'Device ownership', ['Corporate', 'Personal'], ['plat', 'purple']],
        [pick(/^protected|protectedcount/, /un/), pick(/unprotected/), human(key) || 'Protection', ['Protected', 'Unprotected'], ['good', 'bad']]];
      pairs.forEach(([a, b, title, labels, cls]) => { if (a.length && b.length) out.splits.push({key, title: /^(\d+|data|value)?$/.test(String(key)) ? title : (VIZ_TITLES[normKey(key)] ? title : title), parts: [[labels[0], num(a[0][1]), cls[0]], [labels[1], num(b[0][1]), cls[1]]]}); });
      const OS = ['windows', 'macos', 'ios', 'android', 'linux', 'ipados', 'chromeos'];
      const osKeys = Object.keys(o).filter(k => OS.some(os => normKey(k) === os || normKey(k) === os + 'count'));
      if (osKeys.length >= 2) {
        const OSL = {windows: 'Windows', macos: 'macOS', ios: 'iOS', android: 'Android', linux: 'Linux', ipados: 'iPadOS', chromeos: 'ChromeOS'};
        const rows = osKeys.map(k => { const v = o[k], label = OSL[normKey(k).replace(/count$/, '')] || human(k);
          if (v && typeof v === 'object') { const e = Object.entries(v).filter(([, x]) => isFinite(+x));
            const isTot = kk => /total/.test(normKey(kk)) || ['all', 'count'].includes(normKey(kk)); const tot = e.find(([kk]) => isTot(kk)), cov = e.find(([kk]) => !isTot(kk));
            return cov ? {label, covered: num(cov[1]), total: tot ? num(tot[1]) : num(cov[1]), metric: human(cov[0])} : null; }
          return isFinite(+v) ? {label, covered: num(v), total: null, metric: ''} : null; }).filter(Boolean);
        if (rows.length >= 2) out.osbars.push({key, title: rows.some(r => r.total !== null) ? 'Device summary' : 'Devices by operating system', rows});
      }
    }
    (Array.isArray(o) ? o.map((v, i) => [i, v]) : Object.entries(o)).forEach(([k, v]) => { if (v && typeof v === 'object') walk(v, Array.isArray(o) ? key : k, depth + 1); });
  })(info, 'TenantInfo', 0);
  out.sankeys.sort((a, b) => { const ia = VIZ_ORDER.indexOf(normKey(a.key)), ib = VIZ_ORDER.indexOf(normKey(b.key)); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
  if (!out.splits.some(s => s.title === 'Device compliance')) {  // derive it from the device sankeys
    let ok = 0, bad = 0;
    out.sankeys.filter(s => /desktop|mobile/i.test(s.key)).forEach(s => s.links.forEach(l => { const c = nodeClass(l.target); if (/^compliant/i.test(l.target)) ok += l.value; else if (c === 'bad' && /compliant/i.test(l.target)) bad += l.value; }));
    if (ok + bad) out.splits.unshift({key: 'derived', title: 'Device compliance', parts: [['Compliant', ok, 'good'], ['Non-compliant', bad, 'bad']], derived: true});
  }
  return out;
}
let vizUid = 0;
function sankeySvg(rawLinks) {
  const links0 = rawLinks.filter(l => l.value > 0 && l.source !== l.target);
  if (!links0.length) return '<p class="muted">No data.</p>';
  const W = 640, H = 300, NW = 10, PAD = 14, uid = 'sk' + (++vizUid);
  const nodes = [], idx = {};
  const node = n => { if (!(n in idx)) { idx[n] = nodes.length; nodes.push({name: n, ins: [], outs: [], depth: 0}); } return nodes[idx[n]]; };
  const L = links0.map(l => { const s = node(l.source), t = node(l.target), o = {s, t, v: l.value}; s.outs.push(o); t.ins.push(o); return o; });
  for (let it = 0; it < nodes.length; it++) { let ch = false; L.forEach(l => { if (l.t.depth < l.s.depth + 1) { l.t.depth = l.s.depth + 1; ch = true; } }); if (!ch) break; }
  nodes.forEach(n => { n.d0 = n.depth; });
  const maxD = Math.max(1, ...nodes.map(n => n.depth));
  nodes.forEach(n => { if (!n.outs.length) n.depth = maxD; n.value = Math.max(n.ins.reduce((a, l) => a + l.v, 0), n.outs.reduce((a, l) => a + l.v, 0)); });
  const cols = Array.from({length: maxD + 1}, (_, d) => nodes.filter(n => n.depth === d));
  const ky = Math.min(...cols.filter(c => c.length).map(c => (H - PAD * (c.length - 1)) / (c.reduce((a, n) => a + n.value, 0) || 1)));
  const minH = 2;
  cols.forEach((c, d) => {
    if (d > 0) c.sort((a, b) => { const bc = n => { const w = n.ins.reduce((s, l) => s + l.v, 0) || 1; return n.ins.reduce((s, l) => s + (l.s.y0 + l.s.h / 2) * l.v, 0) / w; }; return bc(a) - bc(b); });
    const tot = c.reduce((a, n) => a + Math.max(minH, n.value * ky), 0) + PAD * (c.length - 1);
    let y = Math.max(0, (H - tot) / 2);
    c.forEach(n => { n.x = d * (W - NW) / maxD; n.h = Math.max(minH, n.value * ky); n.y0 = y; y += n.h + PAD; });
  });
  nodes.forEach(n => { let sy = n.y0; n.outs.sort((a, b) => a.t.y0 - b.t.y0).forEach(l => { l.sy = sy; l.h = Math.max(1, l.v * ky); sy += l.v * ky; });
    let ty = n.y0; n.ins.sort((a, b) => a.s.y0 - b.s.y0).forEach(l => { l.ty = ty; ty += l.v * ky; }); });
  const total = nodes.filter(n => !n.ins.length).reduce((a, n) => a + n.value, 0) || 1;
  const col = n => VIZ_COLOR[nodeClass(n.name)] || VIZ_COLOR.root;
  let defs = '', paths = '';
  L.forEach((l, i) => { const x0 = l.s.x + NW, x1 = l.t.x, xm = (x0 + x1) / 2, y0 = l.sy, y1 = l.ty, h = l.h;
    defs += `<linearGradient id="${uid}g${i}" gradientUnits="userSpaceOnUse" x1="${x0}" x2="${x1}" y1="0" y2="0"><stop offset="0" stop-color="${col(l.s)}"/><stop offset="1" stop-color="${col(l.t)}"/></linearGradient>`;
    paths += `<path class="sk-link" d="M${x0},${y0}C${xm},${y0} ${xm},${y1} ${x1},${y1}L${x1},${y1 + h}C${xm},${y1 + h} ${xm},${y0 + h} ${x0},${y0 + h}Z" fill="url(#${uid}g${i})"><title>${esc(l.s.name)} to ${esc(l.t.name)}: ${l.v.toLocaleString()} (${pct(l.v, total)}%)</title></path>`; });
  const rects = nodes.map(n => { const last = n.depth === maxD, tx = last ? n.x - 6 : n.x + NW + 6, ty = n.y0 + n.h / 2;
    return `<rect x="${n.x}" y="${n.y0}" width="${NW}" height="${n.h}" rx="2" fill="${col(n)}"><title>${esc(n.name)}: ${n.value.toLocaleString()} (${pct(n.value, total)}%)</title></rect>
      <text x="${tx}" y="${ty}" dy="0.35em" text-anchor="${last ? 'end' : 'start'}" class="sk-lbl">${esc(n.name)} <tspan class="sk-pct">${pct(n.value, total)}%</tspan></text>`; }).join('');
  let split = nodes.filter(n => !n.ins.length);
  if (split.length === 1) { let cur = split[0]; while (cur.outs.length === 1) cur = cur.outs[0].t; split = cur.outs.map(l => l.t); }
  const foot = split.length > 1 ? `<div class="viz-foot">${split.slice(0, 4).map(n => `<div><span><i class="dot" style="background:${col(n)}"></i>${esc(n.name)}</span><b>${pct(n.value, total)}<small>%</small></b></div>`).join('')}<div><span>Total</span><b>${fmtK(total)}</b></div></div>` : '';
  return `<svg class="sankey" viewBox="-2 -4 ${W + 4} ${H + 8}" role="img" aria-label="Flow diagram"><defs>${defs}</defs>${paths}${rects}</svg>${foot}`;
}
function donutSvg(parts) {
  const total = parts.reduce((a, p) => a + p[1], 0) || 1, r = 70, c = 2 * Math.PI * r;
  let off = 0;
  const arcs = parts.map(([lbl, v, cls]) => { const len = c * v / total, gap = parts.filter(p => p[1] > 0).length > 1 ? 3 : 0;
    const s = `<circle cx="100" cy="100" r="${r}" fill="none" stroke="${VIZ_COLOR[cls] || 'var(--accent)'}" stroke-width="30" stroke-dasharray="${Math.max(0, len - gap).toFixed(2)} ${c.toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 100 100)"><title>${esc(lbl)}: ${v.toLocaleString()} (${pct(v, total)}%)</title></circle>`; off += len; return s; }).join('');
  return `<svg class="donut" viewBox="0 0 200 200" role="img" aria-label="${esc(parts.map(p => p[0] + ' ' + pct(p[1], total) + '%').join(', '))}">${arcs}<text x="100" y="98" text-anchor="middle" class="dn-v">${fmtK(total)}</text><text x="100" y="118" text-anchor="middle" class="dn-l">total</text></svg>`;
}
function splitBar(parts) {
  const total = parts.reduce((a, p) => a + p[1], 0) || 1;
  return `<div class="bar" style="height:12px">${parts.map(([l, v, cls]) => `<i style="width:${pct(v, total)}%;background:${cls === 'purple' ? '#9b6fd6' : VIZ_COLOR[cls]}" title="${esc(l)}"></i>`).join('')}</div>
    <div class="viz-foot" style="border:0;padding:12px 0 0">${parts.map(([l, v, cls]) => `<div><span><i class="dot" style="background:${cls === 'purple' ? '#9b6fd6' : VIZ_COLOR[cls]}"></i>${esc(l)}</span><b>${pct(v, total)}<small>%</small></b><span class="faint">${fmtK(v)}</span></div>`).join('')}</div>`;
}
function osBars(rows) {
  const max = Math.max(1, ...rows.map(r => r.total !== null ? r.total : r.covered));
  const metric = (rows.find(r => r.metric) || {}).metric;
  return `<div class="osb">${rows.map(r => { const tot = r.total !== null ? r.total : r.covered;
    return `<div class="osb-row"><span>${esc(r.label)}</span><div class="osb-track"><div class="osb-tot" style="width:${(100 * tot / max).toFixed(1)}%">${r.total !== null ? `<i style="width:${pct(r.covered, tot)}%"></i>` : ''}</div></div>
      <span class="num">${r.total !== null ? `${fmtK(r.covered)}/${fmtK(r.total)} <span class="faint">${pct(r.covered, r.total)}%</span>` : fmtK(r.covered)}</span></div>`; }).join('')}</div>
    ${metric ? `<div class="legend"><span><i class="dot" style="background:var(--accent)"></i>${esc(metric)}</span><span><i class="dot" style="background:color-mix(in srgb, var(--accent) 35%, transparent)"></i>Not covered</span></div>` : ''}`;
}
let _viz = null;
const VIZ = () => _viz || (_viz = discoverVisuals(D.tenant_info));
const pillarSankeys = p => VIZ().sankeys.filter(s => s.pillar === p);
function sankeyCards(list) {
  return list.map(s => `<section class="card viz"><header><h2>${esc(s.title)}</h2></header>${s.sub ? `<p class="viz-sub">${esc(s.sub)}</p>` : ''}<div class="body">${sankeySvg(s.links)}</div></section>`);
}
function pillarPanel() {
  const list = S.pillar ? pillarSankeys(S.pillar) : [];
  if (!list.length) return '';
  return `<details class="viz-panel" id="viz-panel"${P.vizOpen === false ? '' : ' open'}><summary><b>${esc(S.pillar)} posture</b> <span class="faint">${list.length} chart${list.length === 1 ? '' : 's'} from the tenant data</span></summary>
    <div class="viz-grid" style="margin:12px 0 4px">${sankeyCards(list).join('')}</div></details>`;
}
function vizCards(onlyUnmapped) {
  const v = VIZ();
  const cards = [];
  const link = p => p ? `<span class="act"><button class="link" data-pillar="${esc(p)}">${esc(p)} tests</button></span>` : '';
  if (onlyUnmapped) return sankeyCards(v.sankeys.filter(s => !s.pillar));
  if (false) v.sankeys.forEach(s => cards.push(`<section class="card viz"><header><h2>${esc(s.title)}</h2>${link(s.pillar)}</header>${s.sub ? `<p class="viz-sub">${esc(s.sub)}</p>` : ''}<div class="body">${sankeySvg(s.links)}</div></section>`));
  v.osbars.sort((a, b) => (b.title === 'Device summary') - (a.title === 'Device summary'));
  v.osbars.forEach((o, k) => {
    const dsk = v.sankeys.find(s => /desktop/i.test(s.key)), mob = v.sankeys.find(s => /mobile/i.test(s.key));
    const sum = s => s.links.filter(l => !s.links.some(x => x.target === l.source)).reduce((a, l) => a + l.value, 0);
    cards.push(`<section class="card viz"><header><h2>${esc(o.title)}</h2>${link('Devices')}</header><p class="viz-sub">${o.title === 'Device summary' ? 'Devices by operating system and coverage.' : 'Managed devices by operating system.'}</p><div class="body">${osBars(o.rows)}
      ${k === 0 && dsk && mob ? splitBar([['Desktops', sum(dsk), 'plat'], ['Mobiles', sum(mob), 'purple']]) : ''}</div></section>`); });
  v.splits.forEach(s => cards.push(`<section class="card viz"><header><h2>${esc(s.title)}</h2>${s.title === 'Device compliance' ? link('Devices') : ''}</header>${s.derived ? '<p class="viz-sub">Derived from the desktop and mobile device flows.</p>' : ''}<div class="body">
    <div class="donut-wrap">${donutSvg(s.parts.map(p => [p[0], p[1], p[2] === 'purple' ? 'purple' : p[2]]))}</div>${splitBar(s.parts)}</div></section>`));
  return cards;
}

/* ================= categories, changes, tenant ================= */
function categories() {
  const g = {};
  T.forEach(t => (g[t.category] = g[t.category] || []).push(t));
  const rows = Object.entries(g).map(([k, ts]) => ({k, ts, sc: score(ts), f: ts.filter(t => t.status === 'failed').length, inv: ts.filter(t => t.status === 'investigate').length,
    hi: ts.filter(t => t.status === 'failed' && t.risk === 'high').length, pil: uniq(ts.flatMap(t => t.pillars)).join(', ')}))
    .sort((a, b) => (a.sc === null) - (b.sc === null) || a.sc - b.sc || b.f - a.f);
  return `<div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Category</th><th>Pillar</th><th class="r">Tests</th><th>Score</th><th class="r">Failed</th><th class="r">High-risk failed</th><th class="r">Investigate</th></tr></thead><tbody>
    ${rows.map(x => `<tr><td class="sticky"><button class="dom" data-category="${esc(x.k)}" style="word-break:normal">${esc(x.k)}</button></td><td class="sub">${esc(x.pil)}</td><td class="r num">${x.ts.length}</td>
      <td>${x.sc === null ? '<span class="faint">not evaluated</span>' : `<div class="scorecell" style="justify-content:flex-start"><span class="score ${scoreCls(x.sc)}">${x.sc}</span><span class="mini" style="width:110px"><i class="${scoreCls(x.sc)}" style="width:${x.sc}%"></i></span></div>`}</td>
      <td class="r num">${x.f}</td><td class="r num">${x.hi ? `<span class="cnt crit">${x.hi}</span>` : 0}</td><td class="r num">${x.inv}</td></tr>`).join('')}</tbody></table></div>`;
}
function changes() {
  const ch = T.filter(t => t.change && (t.change.new || t.change.from)).sort((a, b) => ({regressed: 0, changed: 1, fixed: 2})[a.change.kind] - ({regressed: 0, changed: 1, fixed: 2})[b.change.kind] || b.priority - a.priority);
  return `<div class="stat-strip" style="margin-bottom:16px"><div class="stat"><b class="delta-up">${diff.fixed}</b><span>fixed</span></div><div class="stat"><b class="delta-down">${diff.regressed}</b><span>regressed</span></div>
    <div class="stat"><b>${diff.changed}</b><span>other changes</span></div><div class="stat"><b>${diff.new_tests}</b><span>new tests</span></div>
    <div class="stat"><b>${diff.score_before === null ? '-' : diff.score_before} \u2192 ${diff.score_after === null ? '-' : diff.score_after}</b><span>score</span></div></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th>Change</th><th class="sticky">Test</th><th>Before</th><th>Now</th><th>Risk</th></tr></thead><tbody>
    ${ch.map(t => `<tr data-row="${t._i}"><td>${t.change.new ? '<span class="tag">new test</span>' : `<span class="tag ${t.change.kind === 'fixed' ? 'chg-up' : t.change.kind === 'regressed' ? 'chg-down' : ''}">${esc(t.change.kind)}</span>`}</td>
      <td class="sticky"><button class="dom" data-open="${t._i}" style="word-break:normal">${esc(t.title)}</button><div class="dom-sub">${esc(t.id)}</div></td>
      <td>${t.change.from ? pill(t.change.from) : '<span class="faint">-</span>'}</td><td>${pill(t.status)}</td><td>${riskPill(t.risk)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No changes.</td></tr>'}</tbody></table></div>
    ${diff.removed_tests.length ? `<p class="muted" style="margin-top:12px">No longer in the assessment: ${diff.removed_tests.map(esc).join(', ')}</p>` : ''}`;
}
function tree(v, depth) {
  if (v === null || v === undefined) return '<span class="faint">null</span>';
  if (typeof v !== 'object') return `<span class="mono">${esc(v)}</span>`;
  const entries = Array.isArray(v) ? v.map((x, i) => [i, x]) : Object.entries(v);
  if (!entries.length) return '<span class="faint">empty</span>';
  if (Array.isArray(v) && v.every(x => x && typeof x === 'object' && !Array.isArray(x)) && v.length <= 200) {
    const cols = uniq(v.flatMap(x => Object.keys(x))).slice(0, 8);
    if (cols.every(c => v.every(x => x[c] === undefined || x[c] === null || typeof x[c] !== 'object')))
      return `<div class="md-table"><table><thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${v.map(x => `<tr>${cols.map(c => `<td class="mono">${esc(x[c] === undefined ? '' : x[c])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  }
  return `<div class="kvtree">${entries.slice(0, 300).map(([k, x]) => typeof x === 'object' && x !== null
    ? `<details${depth < 1 ? ' open' : ''}><summary><b>${esc(k)}</b> <span class="faint">${Array.isArray(x) ? x.length + ' items' : Object.keys(x).length + ' fields'}</span></summary><div class="kvtree-in">${tree(x, depth + 1)}</div></details>`
    : `<div class="kvrow"><span>${esc(k)}</span>${tree(x, depth + 1)}</div>`).join('')}</div>`;
}
function tenant() {
  const kv = (l, v) => `<div><span>${esc(l)}</span><b>${v ? esc(v) : '<span class="faint">none</span>'}</b></div>`;
  let h = `<section class="card" style="margin-bottom:16px"><header><h2>Assessment</h2></header><div class="body"><div class="kv">${kv('Tenant', TEN.name)}${kv('Domain', TEN.domain)}${kv('Tenant ID', TEN.id)}${kv('Run by', TEN.account)}
    ${kv('Executed', TEN.executed_at ? fmtDate(TEN.executed_at) : '')}${kv('Module version', TEN.version)}${kv('Latest version', TEN.latest_version)}${kv('Source file', M.source)}</div></div></section>`;
  const viz = vizCards(true);
  if (viz.length) h += `<div class="viz-grid">${viz.join('')}</div>`;
  if (D.summary) h += `<section class="card" style="margin-bottom:16px"><header><h2>Summary from the module</h2><p>TestResultSummary as produced by the assessment</p></header><div class="body">${tree(D.summary, 0)}</div></section>`;
  if (D.tenant_info) h += `<section class="card"><header><h2>Tenant information</h2><p>Raw TenantInfo collected by the assessment</p></header><div class="body">${tree(D.tenant_info, 0)}</div></section>`;
  return h;
}

/* ================= test drawer ================= */
const DTABS = [{id: 'result', label: 'Result', show: t => !!t.result}, {id: 'guidance', label: 'Guidance', show: t => !!t.description},
  {id: 'details', label: 'Details', show: () => true}];
function drawerBody(t, tab) {
  if (tab === 'result') return `<section class="dr-sec">${md(t.result)}</section>`;
  if (tab === 'guidance') return `<section class="dr-sec">${md(t.description)}</section>`;
  const kv = (l, v) => `<div><span>${esc(l)}</span><b>${v ? v : '<span class="faint">none</span>'}</b></div>`;
  return `<section class="dr-sec"><div class="kv">${kv('Test ID', esc(t.id))}${kv('Status', pill(t.status) + (t.status_raw && t.status_raw.toLowerCase() !== t.status ? ' <span class="faint">' + esc(t.status_raw) + '</span>' : ''))}
    ${kv('Risk', riskPill(t.risk))}${kv('User impact', lvl(t.impact))}${kv('Implementation effort', lvl(t.cost))}${kv('Priority', String(t.priority))}
    ${kv('Pillar', esc(t.pillars.join(', ')))}${kv('Category', esc(t.category))}${kv('SFI pillar', esc(t.sfi))}${kv('Minimum license', esc(t.license))}
    ${kv('Applies to', esc(t.applies_to.join(', ')))}${kv('Tags', esc(t.tags.join(', ')))}${t.skipped_reason ? kv('Skipped because', esc(t.skipped_reason)) : ''}
    ${t.change ? kv('Since baseline', t.change.new ? 'new test' : t.change.from ? esc(t.change.kind + ', was ' + st(t.change.from)[2].toLowerCase()) : 'unchanged') : ''}</div></section>`;
}
let lastOpen = null;
function drawer() {
  const root = $('#drawer-root');
  if (S.open === null) { if (lastOpen !== null) { root.innerHTML = ''; document.body.classList.remove('locked'); const b = document.querySelector(`[data-open="${lastOpen}"]`); if (b) b.focus({preventScroll: true}); } lastOpen = null; return; }
  const t = T[S.open], lst = list(), pos = lst.findIndex(x => x._i === t._i);
  const prev = pos > 0 ? lst[pos - 1]._i : null, next = pos >= 0 && pos < lst.length - 1 ? lst[pos + 1]._i : null;
  const tabs = DTABS.filter(x => x.show(t));
  if (S.dtab !== 'all' && !tabs.some(x => x.id === S.dtab)) S.dtab = tabs[0].id;
  const body = S.dtab === 'all' ? tabs.map(x => `<h2 class="dr-print-title">${esc(x.label)}</h2>` + drawerBody(t, x.id)).join('') : drawerBody(t, S.dtab);
  const fresh = lastOpen === null;
  root.innerHTML = `<div class="scrim${fresh ? ' enter' : ''}" data-action="close"></div><aside class="drawer${fresh ? ' enter' : ''}" role="dialog" aria-modal="true" aria-labelledby="dr-title">
    <header class="dr-head"><div class="dr-nav"><button class="btn icon ghost" data-open="${prev}" ${prev === null ? 'disabled' : ''} aria-label="Previous test" title="Previous (k)">${icon('left')}</button>
      <button class="btn icon ghost" data-open="${next}" ${next === null ? 'disabled' : ''} aria-label="Next test" title="Next (j)">${icon('right')}</button><span>${pos >= 0 ? `${pos + 1} of ${lst.length}` : ''}</span><span class="spacer"></span>
      <button class="btn ghost small" data-action="copy-link">${icon('link', 14)}Copy link</button><button class="btn ghost small" data-action="print-test">${icon('print', 14)}Print</button>
      <button class="btn icon ghost" data-action="close" id="dr-close" aria-label="Close" title="Close (Esc)">${icon('x')}</button></div>
      <div class="dr-id">${statusRing(t)}<div style="min-width:0"><h2 id="dr-title" style="word-break:normal">${esc(t.title)}</h2>
        <div class="meta">${pill(t.status)}${riskPill(t.risk)}<span class="tag">${esc(t.id)}</span>${t.pillars.map(p => `<span class="tag">${esc(p)}</span>`).join('')}<span class="tag">${esc(t.category)}</span>
        <span class="t">User impact ${esc((LV[t.impact] || '').toLowerCase())}, effort ${esc((LV[t.cost] || '').toLowerCase())}${t.license ? ', ' + esc(t.license) : ''}</span></div></div></div>
      <nav class="dr-tabs" role="tablist">${tabs.map(x => `<button role="tab" data-dtab="${x.id}" aria-selected="${S.dtab === x.id}">${esc(x.label)}</button>`).join('')}</nav></header>
    <div class="dr-body" id="dr-body">${body}</div></aside>`;
  document.body.classList.add('locked');
  if (fresh) { const c = $('#dr-close'); if (c) c.focus({preventScroll: true}); }
  lastOpen = S.open;
}

/* ================= overlays ================= */
let pal = null;
function paletteItems(q) {
  q = q.trim().toLowerCase(); const items = [];
  ROUTES.filter(r => r.show()).forEach(r => { if (!q || r.label.toLowerCase().includes(q)) items.push({g: 'Go to', t: r.label, h: '', run: () => go({route: r.id, open: null})}); });
  PILLARS.forEach(p => { if (!q || p.toLowerCase().includes(q)) items.push({g: 'Pillars', t: p, h: '', run: () => filterTo({pillar: p})}); });
  (q ? T.filter(t => t._text.includes(q)) : T.filter(t => t.priority > 0).sort((a, b) => b.priority - a.priority)).slice(0, q ? 10 : 5)
    .forEach(t => items.push({g: 'Tests', t: t.title, h: st(t.status)[2], run: () => go({open: t._i, dtab: 'result'})}));
  if (q) uniq(T.map(t => t.category)).filter(c => c.toLowerCase().includes(q)).slice(0, 5).forEach(c => items.push({g: 'Categories', t: c, h: '', run: () => filterTo({category: c})}));
  [['Toggle light or dark theme', toggleTheme], ['Executive summary as PDF', printExec], ['Export filtered tests as CSV', () => exportCsv(list())], ['Clear all filters', () => filterTo({})], ['Keyboard shortcuts', showKeys]]
    .forEach(([t, fn]) => { if (!q || t.toLowerCase().includes(q)) items.push({g: 'Actions', t, h: '', run: fn}); });
  return items;
}
function openPalette() {
  pal = {q: '', idx: 0, items: paletteItems('')};
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-label="Command palette"><div class="pal-input">${icon('search', 18)}<input id="pal-q" placeholder="Search tests, pillars, categories and actions" autocomplete="off" role="combobox" aria-expanded="true" aria-controls="pal-list"><span class="kbd">Esc</span></div>
    <ul class="pal-list" id="pal-list" role="listbox"></ul><div class="pal-foot"><span><span class="kbd">\u2191</span> <span class="kbd">\u2193</span> move</span><span><span class="kbd">Enter</span> open</span><span><span class="kbd">Esc</span> close</span></div></div></div>`;
  renderPalette(); $('#pal-q').focus();
}
function renderPalette() {
  let g = '', h = '';
  pal.items.forEach((it, k) => { if (it.g !== g) { g = it.g; h += `<li class="pal-group" role="presentation">${esc(g)}</li>`; } h += `<li class="pal-item" role="option" id="pal-${k}" data-pal="${k}" aria-selected="${k === pal.idx}"><span class="ptitle">${esc(it.t)}</span><span class="phint">${esc(it.h)}</span></li>`; });
  $('#pal-list').innerHTML = h || '<li class="pal-group">No results</li>';
  const c = $('#pal-' + pal.idx); if (c) c.scrollIntoView({block: 'nearest'});
}
function dialog(title, body) { $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dlg-t"><header><h2 id="dlg-t">${esc(title)}</h2><button class="btn icon ghost" data-action="overlay-close" aria-label="Close">${icon('x')}</button></header><div class="dbody">${body}</div></div></div>`;
  const b = $('#overlay-root [data-action="overlay-close"]'); if (b) b.focus(); }
function showKeys() { const k = [['Ctrl K or /', 'Search tests, pillars and actions'], ['1 to 5', 'Switch section'], ['j / k', 'Next or previous test'], ['Enter', 'Open the highlighted test'], ['f', 'Show or hide filters'], ['Esc', 'Close the detail or dialog'], ['?', 'This help']];
  dialog('Keyboard shortcuts', `<table class="keys">${k.map(([a, b]) => `<tr><td><span class="kbd">${esc(a)}</span></td><td>${esc(b)}</td></tr>`).join('')}</table>`); }
function showAbout() {
  dialog('About this report', `<div class="kv" style="margin-bottom:14px"><div><span>Generated</span><b>${esc(M.generated)}</b></div><div><span>Tool</span><b>ZTAGuard ${esc(M.version)}</b></div><div><span>Source</span><b>${esc(M.source)}</b></div><div><span>Tests</span><b>${T.length}</b></div></div>
    <ul style="margin:0;padding-left:18px;color:var(--muted)"><li>Results come from the Microsoft Zero Trust Assessment module; this report only re-presents them.</li>
    <li>Score: pass rate weighted by risk (High ${D.weights.risk.high}, Medium ${D.weights.risk.medium}, Low ${D.weights.risk.low}); Investigate counts half; skipped, planned and errors are excluded.</li>
    <li>Priority: risk weight on failed or investigate tests, divided by implementation effort and user impact.</li><li>Quick wins: failed or investigate, high or medium risk, low effort, low user impact.</li>
    <li>Skipped tests often depend on licenses or permissions: they are not evidence that the tenant meets the recommendation.</li></ul>`);
}
function toast(m) { const t = document.createElement('div'); t.className = 'toast'; t.textContent = m; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 2600); }
function copyText(text, ok) { const done = () => toast(ok || 'Copied');
  const fb = () => { const t = document.createElement('textarea'); t.value = text; t.style.position = 'fixed'; t.style.opacity = '0'; document.body.appendChild(t); t.select(); try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed'); } t.remove(); };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fb); else fb(); }
const csvCell = v => { let s = String(v === null || v === undefined ? '' : v); if (/^[=+\-@\t\r|%]/.test(s)) s = "'" + s; return /[";\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
function exportCsv(rows) {
  const head = ['test_id', 'title', 'status', 'risk', 'user_impact', 'effort', 'pillars', 'category', 'sfi_pillar', 'license', 'priority', 'quick_win'];
  const body = rows.map(t => [t.id, t.title, t.status, t.risk, t.impact, t.cost, t.pillars.join('|'), t.category, t.sfi, t.license, t.priority, t.quick_win ? 'yes' : '']);
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['\ufeff' + [head, ...body].map(r => r.map(csvCell).join(';')).join('\r\n')], {type: 'text/csv;charset=utf-8'}));
  a.download = 'zta-tests.csv'; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); toast('Downloaded zta-tests.csv');
}
function printExec() { if (S.route !== 'overview' || S.open !== null) go({route: 'overview', open: null}); document.body.classList.add('print-exec'); setTimeout(() => window.print(), 60); }
function printTest() { const prev = S.dtab; S.dtab = 'all'; drawer(); document.body.classList.add('print-drawer'); window.__restore = prev; setTimeout(() => window.print(), 60); }
window.addEventListener('afterprint', () => { document.body.classList.remove('print-exec', 'print-drawer'); if (window.__restore) { S.dtab = window.__restore; window.__restore = null; drawer(); } });

/* ================= render & events ================= */
const VIEWS = {overview, tests, categories, changes, tenant};
function render() {
  applyTheme();
  $('#side').innerHTML = side(); $('#topbar').innerHTML = topbar(); $('#view').innerHTML = (VIEWS[S.route] || overview)();
  drawer();
  document.title = (S.open !== null ? T[S.open].title + ' - ' : '') + 'Zero Trust posture - ' + (M.title || '');
}
function keepFocus(id) { const el = document.getElementById(id), pos = el ? el.selectionStart : null; render(); const n = document.getElementById(id); if (n) { n.focus(); if (pos !== null) n.setSelectionRange(pos, pos); } }
document.addEventListener('click', e => {
  const t = e.target.closest('button, [data-open], tr[data-row], [data-pal], [data-overlay], .scrim');
  if (!t) return;
  const ds = t.dataset;
  if (ds.overlay !== undefined && e.target === t) { closeOverlay(); return; }
  if (ds.pal !== undefined) { runPalette(+ds.pal); return; }
  if (ds.open !== undefined && ds.open !== 'null') { go({open: +ds.open, dtab: S.open === +ds.open ? S.dtab : 'result'}); return; }
  if (ds.route) { go({route: ds.route, open: null, page: 1, cursor: -1}); window.scrollTo(0, 0); return; }
  if (ds.pillar !== undefined) { filterTo(ds.pst ? {pillar: ds.pillar, status: ds.pst} : {pillar: ds.pillar}); return; }
  if (ds.status) { filterTo({status: ds.status}); return; }
  if (ds.risk) { filterTo({risk: ds.risk, status: ds.rst}); return; }
  if (ds.sfi) { filterTo({sfi: ds.sfi}); return; }
  if (ds.quick) { filterTo({quick: '1'}); return; }
  if (ds.changed) { filterTo({changed: ds.changed}); return; }
  if (ds.category) { filterTo({category: ds.category}); return; }
  if (ds.preset !== undefined) { filterTo(Object.assign({}, PRESETS()[+ds.preset][1])); return; }
  if (ds.chip) { S[ds.chip] = ''; go({page: 1}, false); return; }
  if (ds.sort) { const k = ds.sort; go({sort: {k, d: S.sort.k === k ? -S.sort.d : (['title', 'category', 'id', 'pillar', 'status'].includes(k) ? 1 : -1)}, page: 1}, false); return; }
  if (ds.page) { go({page: +ds.page, cursor: -1}, false); const g = $('#grid'); if (g) g.scrollTop = 0; return; }
  if (ds.density) { P.density = ds.density; savePrefs(); render(); return; }
  if (ds.dtab) { go({dtab: ds.dtab}, false); const b = $('#dr-body'); if (b) b.scrollTop = 0; return; }
  if (t.tagName === 'TR' && ds.row !== undefined && !e.target.closest('a, button, input')) { go({open: +ds.row, dtab: 'result'}); return; }
  const acts = {close: () => go({open: null}), palette: openPalette, about: showAbout, keys: showKeys, theme: toggleTheme, 'overlay-close': closeOverlay,
    'print-exec': printExec, 'print-test': printTest, 'copy-link': () => copyText(location.href, 'Link copied'), filters: () => { S.filtersOpen = !S.filtersOpen; render(); },
    clear: () => filterTo({}), csv: () => exportCsv(list())};
  if (acts[ds.action]) acts[ds.action]();
});
document.addEventListener('toggle', e => { if (e.target.id === 'viz-panel') { P.vizOpen = e.target.open; savePrefs(); } }, true);
document.addEventListener('change', e => {
  const t = e.target, k = t.dataset.k;
  if (k === 'size') { P.size = +t.value; savePrefs(); go({page: 1}, false); }
  else if (k === 'group') { P.group = t.value; savePrefs(); render(); }
  else if (k) go({[k]: t.value, page: 1, cursor: -1}, false);
});
let qt = null;
document.addEventListener('input', e => {
  if (e.target.id === 'pal-q') { pal.q = e.target.value; pal.items = paletteItems(pal.q); pal.idx = 0; renderPalette(); return; }
  if (e.target.id !== 'q') return;
  clearTimeout(qt); const v = e.target.value;
  qt = setTimeout(() => { Object.assign(S, {q: v, page: 1, cursor: -1}); history.replaceState(null, '', toHash()); keepFocus('q'); }, 160);
});
document.addEventListener('keydown', e => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal ? closeOverlay() : openPalette(); return; }
  if (pal) {
    if (e.key === 'ArrowDown') { e.preventDefault(); pal.idx = Math.min(pal.items.length - 1, pal.idx + 1); renderPalette(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); pal.idx = Math.max(0, pal.idx - 1); renderPalette(); }
    else if (e.key === 'Enter') { e.preventDefault(); runPalette(pal.idx); } else if (e.key === 'Escape') { e.preventDefault(); closeOverlay(); }
    return;
  }
  if (e.key === 'Escape') { if ($('#overlay-root').innerHTML) closeOverlay(); else if (S.open !== null) go({open: null}); else if (typing) e.target.blur(); return; }
  if ($('#overlay-root').innerHTML) { if (e.key === 'Tab') { const f = [...$('#overlay-root').querySelectorAll('button, input')]; if (f.length) { e.preventDefault(); const i = f.indexOf(document.activeElement); f[(i + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus(); } } return; }
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === '/') { e.preventDefault(); openPalette(); return; }
  if (e.key === '?') { showKeys(); return; }
  if (S.open !== null) { const l = list(), p = l.findIndex(x => x._i === S.open);
    if ((e.key === 'j' || e.key === ']') && p < l.length - 1) go({open: l[p + 1]._i}, false); else if ((e.key === 'k' || e.key === '[') && p > 0) go({open: l[p - 1]._i}, false); return; }
  const n = parseInt(e.key, 10), vis = ROUTES.filter(r => r.show());
  if (n >= 1 && n <= vis.length) { go({route: vis[n - 1].id, open: null, page: 1, cursor: -1}); return; }
  if (S.route === 'tests') {
    const items = P.group === 'none' ? list().slice((S.page - 1) * P.size, S.page * P.size) : list();
    if (e.key === 'f') { S.filtersOpen = !S.filtersOpen; render(); return; }
    if (!items.length || P.group !== 'none') return;
    if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); S.cursor = Math.min(items.length - 1, S.cursor + 1); render(); const r = $('tr.cursor'); if (r) r.scrollIntoView({block: 'nearest'}); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); S.cursor = Math.max(0, S.cursor - 1); render(); const r = $('tr.cursor'); if (r) r.scrollIntoView({block: 'nearest'}); }
    else if (e.key === 'Enter' && S.cursor >= 0) { e.preventDefault(); go({open: items[S.cursor]._i, dtab: 'result'}); }
  }
});
applyTheme(); fromHash(); history.replaceState(null, '', toHash()); render();
})();
