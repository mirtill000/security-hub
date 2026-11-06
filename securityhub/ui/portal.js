(function () {
'use strict';
/* @include core.js */
const H = JSON.parse(document.getElementById('hub-data').textContent);
const RP = H.reports, M = H.meta;
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
const $ = (s, r) => (r || document).querySelector(s);
const scoreCls = n => n === null || n === undefined ? '' : n >= 80 ? 'hi' : n >= 50 ? 'mid' : 'lo';
const ICONS = {
  grid: '<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"/>', shield: '<path d="M12 3 4 6v6c0 5 3.4 8.6 8 9.5 4.6-.9 8-4.5 8-9.5V6l-8-3z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
  pra: '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v2"/>', ias: '<circle cx="9" cy="8" r="3.5"/><path d="M3 20c.8-3.4 3.2-5.5 6-5.5s4.4 1.4 5.3 3M15.5 14.5h5v5h-5zM16.5 14.5v-1.5a1.5 1.5 0 0 1 3 0v1.5"/>', proofpoint: '<path d="M3 6h18v12H3zM3 7l9 6 9-6"/><path d="M12 3l7 3v0"/>', edr: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4M9.5 10l2 2 3.5-3.5"/>', email: '<path d="M3 5h18v14H3zM3 6l9 7 9-7"/>', dns: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>', waf: '<path d="M4 6h16M4 12h16M4 18h16M8 6v6M16 12v6M12 18v-6"/>', zta: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20c1.2-3.6 4-5.5 7-5.5s5.8 1.9 7 5.5"/>',
  other: '<path d="M6 3h9l4 4v14H6zM14 3v5h5"/>', ext: '<path d="M14 4h6v6M20 4l-9 9M18 14v6H4V6h6"/>', download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
  left: '<path d="m15 6-6 6 6 6"/>', sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>', monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>', link: '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3A4.5 4.5 0 0 0 13 4.6l-1 1M14 10a4.5 4.5 0 0 0-6.4 0l-3 3A4.5 4.5 0 0 0 11 19.4l1-1"/>',
  trend: '<path d="M3 17l6-6 4 4 8-8M15 7h6v6"/>', search: '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4-4"/>', x: '<path d="M6 6l12 12M18 6 6 18"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>', assets: '<path d="M12 3 3 7.5l9 4.5 9-4.5L12 3z"/><path d="m3 12 9 4.5 9-4.5M3 16.5 12 21l9-4.5"/>', print: '<path d="M6 9V3h12v6M6 18H4v-7h16v7h-2M8 14h8v7H8z"/>'
};
const icon = (n, s) => `<svg class="ico" width="${s || 16}" height="${s || 16}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ICONS.other}</svg>`;

/* ---------- theme (shared logic in theme.js): the portal decides for the embedded reports ---------- */
function onThemeChange() {
  const t = isDark() ? 'dark' : 'light';
  Object.values(frames).forEach(f => { try { f.el.contentWindow.postMessage({mgHubTheme: t}, '*'); } catch (e) { /* ignore */ } });
  render();
}

/* ---------- embedded reports: one sandboxed frame per report, created on first use ---------- */
const frames = {};
// Inside the portal each report hides its own sidebar and top bar: the portal shows its sections and owns search.
const EMB_CSS = 'html[data-embedded] .app{grid-template-columns:minmax(0,1fr)!important}html[data-embedded] .side,html[data-embedded] .topbar,html[data-embedded] [data-action="copy-link"]{display:none!important}html[data-embedded] .content{padding-top:22px}html[data-embedded] .grid-wrap{max-height:calc(100vh - 200px)}';
const BOOT = (id, hash, th, emb) => `<script>(function(){var ID=${JSON.stringify(id)},D=document.documentElement;try{D.dataset.theme=${JSON.stringify(th)};}catch(e){}
${hash ? `try{history.replaceState(null,'',${JSON.stringify(hash)});}catch(e){location.hash=${JSON.stringify(hash)};}` : ''}
${emb ? `D.dataset.embedded='1';var st=document.createElement('style');st.textContent=${JSON.stringify(EMB_CSS)};(document.head||D).appendChild(st);
var last='',timer=null;function txt(el){return el?el.textContent.replace(/\\s+/g,' ').trim():'';}
function snap(){timer=null;var items=[].slice.call(document.querySelectorAll('#side .nav-item')).map(function(b){var c=b.querySelector('.count'),label='';
[].forEach.call(b.children,function(n){if(!label&&n.tagName==='SPAN'&&!n.classList.contains('count')&&!n.classList.contains('pdot'))label=txt(n);});
return {route:b.getAttribute('data-route'),pillar:b.getAttribute('data-pillar'),action:b.getAttribute('data-action'),label:(label||txt(b)).replace(/\\s+[^\\w\\s]+$/,''),count:c?txt(c):'',current:b.getAttribute('aria-current')==='page'||b.classList.contains('on')};})
.filter(function(x){return x.route||x.pillar||x.action==='about'||x.action==='keys';});
var tb=document.getElementById('topbar'),h1=tb&&tb.querySelector('h1'),sub=tb&&tb.querySelector('.sub');
var msg={mgHub:1,id:ID,hash:location.hash,nav:items,heading:txt(h1),sub:txt(sub),pdf:!!document.querySelector('[data-action="print-exec"]')};
var key=JSON.stringify(msg);if(key!==last){last=key;try{parent.postMessage(msg,'*');}catch(e){}}}
function later(){if(!timer)timer=setTimeout(snap,60);}
new MutationObserver(later).observe(D,{childList:true,subtree:true});addEventListener('hashchange',later);addEventListener('popstate',later);addEventListener('load',later);
addEventListener('keydown',function(e){var typing=/^(INPUT|TEXTAREA|SELECT)$/.test(e.target&&e.target.tagName);
if(((e.ctrlKey||e.metaKey)&&String(e.key).toLowerCase()==='k')||(e.key==='/'&&!typing)){e.preventDefault();e.stopImmediatePropagation();try{parent.postMessage({mgHub:1,id:ID,key:'palette'},'*');}catch(x){}}},true);
addEventListener('message',function(e){if(e.source!==parent||!e.data)return;var d=e.data;if(d.mgHubTheme)D.dataset.theme=d.mgHubTheme;
if(typeof d.mgHubGo==='string')location.hash=d.mgHubGo;
if(d.mgHubClick){var c=d.mgHubClick,sel=c.route?'#side .nav-item[data-route="'+c.route+'"]':c.pillar?'#side .nav-item[data-pillar="'+String(c.pillar).replace(/["\\\\]/g,'')+'"]':c.action?'[data-action="'+c.action+'"]':null;
var el=sel&&document.querySelector(sel);if(el)el.click();}});` : ''}
})();<\/script>`;
const html = id => JSON.parse(document.getElementById('rep-' + id).textContent);
function reportDoc(id, hash, emb) {
  const src = html(id), boot = BOOT(id, hash, isDark() ? 'dark' : 'light', emb !== false);
  return /<head[^>]*>/i.test(src) ? src.replace(/<head[^>]*>/i, m => m + boot) : boot + src;
}
function ensureFrame(id, hash) {
  if (frames[id]) { if (hash && hash !== frames[id].hash) frames[id].el.contentWindow.postMessage({mgHubGo: hash}, '*'); return frames[id]; }
  const el = document.createElement('iframe');
  el.className = 'rep-frame';
  el.title = RP.find(r => r.id === id).title;
  el.setAttribute('sandbox', 'allow-scripts allow-popups allow-downloads allow-modals');
  el.src = URL.createObjectURL(new Blob([reportDoc(id, hash)], {type: 'text/html'}));
  $('#frames').appendChild(el);
  frames[id] = {el, hash: hash || '', nav: [], heading: '', sub: '', pdf: false};
  return frames[id];
}
const tell = (id, msg) => { const f = frames[id]; if (f) f.el.contentWindow.postMessage(msg, '*'); };
window.addEventListener('message', e => {
  const d = e.data;
  if (!d || !d.mgHub) return;
  const f = frames[d.id];
  if (!f || e.source !== f.el.contentWindow) return;  // only trust our own frames
  if (d.key === 'palette') { openPalette(); return; }
  if (typeof d.hash === 'string') f.hash = d.hash;
  if (d.nav) Object.assign(f, {nav: d.nav, heading: d.heading || '', sub: d.sub || '', pdf: !!d.pdf});
  if (S.route === 'r' && S.id === d.id) { const h = toHash(); if (location.hash !== h) history.replaceState(null, '', h); chrome(); }
});

/* ---------- history (trends) ---------- */
const SERIES = (M.history && M.history.series) || [], RUNS = (M.history && M.history.runs) || [];
const seriesFor = (key, r) => SERIES.find(s => s.key === key && s.area === r.type && s.subject === (r.subject || ''));
const hasTrends = () => SERIES.some(s => s.points.length >= 2);
const fmtD = iso => { const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleDateString(undefined, {year: 'numeric', month: 'short', day: 'numeric'}); };
function spark(s) {
  if (!s || s.points.length < 2) return '';
  const pts = s.points, t0 = Date.parse(pts[0][0]), t1 = Date.parse(pts[pts.length - 1][0]) || t0 + 1;
  const pc = s.unit === '%' || s.unit === '/100', top = pc ? 100 : Math.max(...pts.map(p => p[1])) * 1.1 || 1;
  const xy = pts.map(p => [((Date.parse(p[0]) - t0) / ((t1 - t0) || 1)) * 100, 28 - (p[1] / top) * 26]);
  return `<svg class="spark" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true"><polyline points="${xy.map(p => p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ')}"/>
    <circle cx="${xy[xy.length - 1][0].toFixed(1)}" cy="${xy[xy.length - 1][1].toFixed(1)}" r="2.2"/></svg>`;
}
function histDelta(s) {
  if (!s || s.points.length < 2) return '';
  const a = s.points[s.points.length - 2], b = s.points[s.points.length - 1], d = Math.round((b[1] - a[1]) * 10) / 10;
  const u = s.unit === '/100' ? ' pts' : s.unit === '%' ? ' pts' : '';
  return d === 0 ? `<span class="exec-trend">unchanged since ${esc(fmtD(a[0]))}</span>` : `<span class="exec-trend ${d > 0 ? 'up' : 'down'}">${d > 0 ? '\u25B2 +' : '\u25BC '}${d}${u} since ${esc(fmtD(a[0]))}</span>`;
}
function lineChart(s) {
  const W = 560, H = 200, L = 38, R = 18, T = 16, B = 30, pts = s.points;
  const pc = s.unit === '%' || s.unit === '/100', top = pc ? 100 : Math.max(...pts.map(p => p[1]), s.target || 0) * 1.15 || 1;
  const t0 = Date.parse(pts[0][0]), t1 = Date.parse(pts[pts.length - 1][0]);
  const x = t => L + ((Date.parse(t) - t0) / ((t1 - t0) || 1)) * (W - L - R), y = v => H - B - (v / top) * (H - T - B);
  const path = pts.map((p, i) => `${i ? 'L' : 'M'}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join('');
  const grid = [0, 0.5, 1].map(f => `<line x1="${L}" x2="${W - R}" y1="${y(top * f).toFixed(1)}" y2="${y(top * f).toFixed(1)}" class="tg"/><text x="${L - 6}" y="${(y(top * f) + 3).toFixed(1)}" text-anchor="end" class="ta">${Math.round(top * f)}</text>`).join('');
  const tgt = s.target && s.target <= top ? `<line x1="${L}" x2="${W - R}" y1="${y(s.target).toFixed(1)}" y2="${y(s.target).toFixed(1)}" class="tt"/><text x="${W - R}" y="${(y(s.target) - 5).toFixed(1)}" text-anchor="end" class="ttl">Target ${s.target}</text>` : '';
  const dots = pts.map((p, i) => `<circle cx="${x(p[0]).toFixed(1)}" cy="${y(p[1]).toFixed(1)}" r="${i === pts.length - 1 ? 4 : 3}" class="${i === pts.length - 1 ? 'tl' : 'td'}"><title>${esc(fmtD(p[0]))}: ${p[1]}${esc(s.unit)}</title></circle>`).join('');
  const lbls = pts.map((p, i) => (i === 0 || i === pts.length - 1 || pts.length <= 6) ? `<text x="${x(p[0]).toFixed(1)}" y="${H - 8}" text-anchor="${i === 0 ? 'start' : i === pts.length - 1 ? 'end' : 'middle'}" class="ta">${esc(fmtD(p[0]))}</text>` : '').join('');
  const vlab = pts.map((p, i) => `<text x="${x(p[0]).toFixed(1)}" y="${(y(p[1]) - 9).toFixed(1)}" text-anchor="${i === 0 ? 'start' : i === pts.length - 1 ? 'end' : 'middle'}" class="tv">${p[1]}</text>`).join('');
  return `<svg class="tchart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(s.label)} over time: ${esc(pts.map(p => fmtD(p[0]) + ' ' + p[1] + s.unit).join(', '))}">${grid}${tgt}<path d="${path}" class="tp"/>${dots}${vlab}${lbls}</svg>`;
}
const KORDER = ['score', 'spoof', 'dnssec', 'caa', 'waf', 'pp_routing', 'pp_clicks', 'pp_delivered', 'edr_protect', 'edr_health', 'edr_coverage', 'ias_corporate', 'ias_priv_pwd', 'ias_inactive', 'pra_mfa', 'pra_recorded', 'pra_vendor', 'zt', 'mfa', 'pr', 'dev'];
function trends() {
  const dup = s => s.key === 'zt' && SERIES.some(o => o.key === 'score' && o.area === s.area && o.subject === s.subject);
  const ss = SERIES.filter(s => s.points.length >= 2 && !dup(s)).sort((a, b) => KORDER.indexOf(a.key) - KORDER.indexOf(b.key) || a.area.localeCompare(b.area));
  if (!ss.length) return '<div class="card empty"><b>No history yet</b>Generate the portal with reports from two or more assessments (for example one folder per quarter) to see trends.</div>';
  const first = RUNS[0], last = RUNS[RUNS.length - 1];
  const lab = {email: 'Email security', dns: 'DNS security', waf: 'Imperva Cloud WAF', edr: 'SentinelOne EDR', proofpoint: 'Proofpoint', ias: 'SAP Cloud Identity', pra: 'BeyondTrust PRA', zta: 'Microsoft Zero Trust'};
  return `<div class="section-title"><h2>Trends</h2><p>${RUNS.length} assessments from ${esc(fmtD(first.date))} to ${esc(fmtD(last.date))}</p></div>
    <div class="trend-grid">${ss.map(s => { const a = s.points[0], b = s.points[s.points.length - 1], d = Math.round((b[1] - a[1]) * 10) / 10;
      return `<section class="card"><header><h2>${esc(s.label)}</h2><span class="act"><span class="hub-type">${icon(s.area, 14)}${esc(lab[s.area] || s.area)}</span></span></header>
        <div class="body"><div class="trend-now"><b>${esc(b[1])}<small>${esc(s.unit)}</small></b>${histDelta(s)}<span class="exec-trend ${d > 0 ? 'up' : d < 0 ? 'down' : ''}">${d > 0 ? '+' : ''}${d} since ${esc(fmtD(a[0]))}</span></div>${lineChart(s)}</div></section>`; }).join('')}</div>
    <details class="card exec-detail" style="margin-top:16px"><summary><b>Assessments included</b> <span class="faint">${RUNS.length}</span></summary><div class="body"><table class="keys">
      ${RUNS.map(r => `<tr><td>${esc(fmtD(r.date))}</td><td>${esc(r.label)}</td><td class="mono">${esc(r.file)}</td><td>${r.current ? '<span class="pill s-pass">current, embedded</span>' : '<span class="faint">history</span>'}</td></tr>`).join('')}</table></div></details>`;
}

/* ---------- assets: one view per organization domain across e-mail/DNS, WAF, certificates, tenant ---------- */
const INV = M.inventory || {assets: [], summary: {}}, AS = INV.assets || [], AQ = () => (S.aq || '').trim().toLowerCase();
const hasAssets = () => AS.length > 0;
const A_FILTERS = [['all', 'All', () => true], ['risk', 'At risk', a => a.status === 'bad'], ['attention', 'Needs attention', a => a.status === 'warn'],
  ['gaps', 'Coverage gaps', a => a.coverage_gap], ['expiring', 'Expiring', a => a.expiries.some(e => e.days !== null && e.days <= 30)],
  ['incomplete', 'Not verified', a => a.incomplete]];
const dmarcTxt = d => `<span class="${d.dmarc_state === 'enforced' ? 'tx-good' : d.dmarc_state === 'spoofable' ? 'tx-bad' : 'faint'}">${esc(d.dmarc)}</span>`;
const protPill = p => p === null || p === undefined ? '<span class="pill s-na">not verified</span>' : `<span class="pill ${p ? 's-pass' : 's-fail'}">${p ? 'yes' : 'no'}</span>`;
const CTL = {valid: 's-pass', partial: 's-warn', warning: 's-warn', missing: 's-none', misconfigured: 's-fail', error: 's-fail', invalid: 's-fail', bogus: 's-fail'};
const ctlPill = v => v ? `<span class="pill ${CTL[v] || 's-na'}">${esc(v)}</span>` : '<span class="faint">-</span>';
const scoreTxt = n => n === null || n === undefined ? '<span class="faint">-</span>' : `<span class="score ${scoreCls(n)}">${esc(n)}</span>`;
const stPill = st => { const x = AREA_ST[st || 'unknown']; return `<span class="pill s-${x[1]}">${esc(x[0])}</span>`; };
const tierTag = t => `<span class="tag tier-${esc(t)}">${esc(t)}</span>`;
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const SEP = '<span class="faint"> \u00b7 </span>';
function expiryTxt(e) {
  if (!e || e.days === null || e.days === undefined) return '<span class="faint">-</span>';
  const cls = e.days < 0 || e.days <= (e.kind === 'certificate' ? 7 : 14) ? 'tx-bad' : e.days <= (e.kind === 'certificate' ? 30 : 60) ? 'tx-warn' : 'faint';
  const when = e.days < 0 ? `expired ${plural(-e.days, 'day')} ago` : e.days > 730 ? `in ${Math.floor(e.days / 365)} years` : `in ${plural(e.days, 'day')}`;
  return `<span class="${cls}">${when}</span>`;
}
function mailTxt(a) {  // Proofpoint filtering of the asset's mail domains
  const m = a.mail || [];
  if (!m.length) return '';
  const nf = m.filter(x => x.filtered === false).length;
  return `${SEP}${nf ? `<span class="faint">${nf} not via Proofpoint</span>` : m.every(x => x.filtered) ? '<span class="tx-good">via Proofpoint</span>' : '<span class="faint">Proofpoint not verified</span>'}`;
}
const sigCount = a => { const c = a.signals.filter(x => x.severity === 'critical').length, w = a.signals.filter(x => x.severity === 'warning').length;
  return (c ? `<span class="pill s-fail">${c} critical</span> ` : '') + (w ? `<span class="pill s-warn">${w} warning</span>` : '') || '<span class="faint">none</span>'; };
const A_PAGE = 50, TIER_RANK = {critical: 0, high: 1, medium: 2, low: 3}, ST_RANK = {bad: 0, warn: 1, unknown: 2, good: 3};
const num = (v, none) => v === null || v === undefined ? none : v;
const A_SORT = {
  risk: a => a._rank, asset: a => a.key, tier: a => TIER_RANK[a.tier] ?? 9, status: a => ST_RANK[a.status] ?? 9,
  dns: a => num(a.dns_score, 1e3), web: a => num(a.web_score, 1e3), expiry: a => a.next_expiry ? num(a.next_expiry.days, 1e6) : 1e6,
  signals: a => -(a.signals.filter(x => x.severity === 'critical').length * 1000 + a.signals.filter(x => x.severity === 'warning').length)};
AS.forEach((a, i) => { a._rank = i; });
function sortedAssets(rows) {
  const k = (S.asort || {}).k || 'risk', d = (S.asort || {}).d || 1, f = A_SORT[k] || A_SORT.risk;
  return rows.slice().sort((x, y) => { const a = f(x), b = f(y); return (a < b ? -1 : a > b ? 1 : x._rank - y._rank) * d; });
}
function ath(k, label, sticky) {
  const cur = (S.asort || {}).k === k ? ((S.asort.d > 0) ? 'ascending' : 'descending') : 'none';
  return `<th${sticky ? ' class="sticky"' : ''} aria-sort="${cur}"><button class="sort" data-asort="${k}">${esc(label)}</button></th>`;
}
function assetMatches(a) {
  const q = AQ(); if (!q) return true;
  return [a.key, ...a.owners, ...a.bus, ...a.dns.map(d => d.domain), ...a.web.map(w => w.domain), ...(a.mail || []).map(m => m.domain)].some(x => String(x).toLowerCase().includes(q));
}
function assetList() {
  const f = (A_FILTERS.find(x => x[0] === S.af) || A_FILTERS[0]), all = sortedAssets(AS.filter(f[2]).filter(assetMatches)), sm = INV.summary || {};
  const pages = Math.max(1, Math.ceil(all.length / A_PAGE)); S.apage = Math.min(Math.max(1, S.apage || 1), pages);
  const rows = all.slice((S.apage - 1) * A_PAGE, S.apage * A_PAGE);
  const pager = pages > 1 ? `<nav class="pager" aria-label="Pagination"><span>Rows ${(S.apage - 1) * A_PAGE + 1} to ${Math.min(S.apage * A_PAGE, all.length)} of ${all.length}</span>
    <div class="pages"><button class="btn small" data-apage="${S.apage - 1}"${S.apage <= 1 ? ' disabled' : ''}>Previous</button><span class="faint">Page ${S.apage} of ${pages}</span>
    <button class="btn small" data-apage="${S.apage + 1}"${S.apage >= pages ? ' disabled' : ''}>Next</button></div></nav>` : '';
  const presets = A_FILTERS.map(([k, l, fn]) => `<button class="preset" data-af="${k}" aria-pressed="${S.af === k}">${esc(l)}<span class="n">${AS.filter(fn).length}</span></button>`).join('');
  const body = rows.map(a => { const root = a.dns.find(d => d.domain === a.key) || a.dns[0], byp = a.web.filter(w => w.profile === 'bypass').length, unp = a.web.filter(w => w.protected === false).length;
    return `<tr data-asset="${esc(a.key)}"><td class="sticky"><button class="dom" data-asset="${esc(a.key)}">${esc(a.key)}</button><div class="dom-sub">${esc([...a.owners, ...a.bus].join(', ') || ' ')}</div></td>
      <td>${tierTag(a.tier)}</td><td>${stPill(a.status)}</td>
      <td>${root ? `${scoreTxt(a.dns_score)}${SEP}<span class="faint">DMARC</span> ${dmarcTxt(root)}${a.dns.length > 1 ? `${SEP}<span class="faint">${plural(a.dns.length, 'domain')}</span>` : ''}` : '<span class="faint">not assessed</span>'}${mailTxt(a)}</td>
      <td>${a.web.length ? `${scoreTxt(a.web_score)}${SEP}<span class="faint">${plural(a.web.length, 'site')}</span>${byp ? `${SEP}<span class="tx-bad">${byp} in bypass</span>` : unp ? `${SEP}<span class="tx-warn">${unp} not blocking</span>` : ''}` : '<span class="faint">none</span>'}</td>
      <td class="nowrap">${expiryTxt(a.next_expiry)}</td>
      <td><div class="asset-sig">${sigCount(a)}${a.signals[0] ? `<span class="asset-sig-t">${esc(a.signals[0].text)}</span>` : ''}</div></td></tr>`; }).join('');
  return `<div class="section-title"><h2>Assets</h2><p>${plural(sm.total || 0, 'organization domain')}: ${plural(sm.domains || 0, 'mail domain')} and ${plural(sm.websites || 0, 'website')} joined across reports, with the problems that only show when areas are seen together</p></div>
    <div class="presets" role="group" aria-label="Filter assets">${presets}</div>
    <div class="toolbar"><div class="search-box">${icon('search')}<input id="aq" type="search" placeholder="Filter by domain, website, owner, business unit" value="${esc(S.aq || '')}" aria-label="Filter assets"></div><span class="spacer"></span><span class="faint" id="a-count">${plural(all.length, 'asset')}</span></div>
    ${rows.length ? `<div class="grid-wrap asset-grid"><table class="grid"><thead><tr>${ath('asset', 'Asset', true)}${ath('tier', 'Tier')}${ath('status', 'Status')}${ath('dns', 'E-mail and DNS')}${ath('web', 'Websites (WAF)')}${ath('expiry', 'Next expiry')}${ath('signals', 'Signals')}</tr></thead><tbody>${body}</tbody></table></div>${pager}`
      : '<div class="card empty"><b>No assets match</b>Change the filter or the search text.</div>'}
    <p class="faint exec-note">Assets are grouped by the domains assessed for e-mail security; websites join the domain they belong to. Scores are the lowest of each area.</p>`;
}
const openBtn = (rid, h, label) => rid ? `<button class="btn" data-go="${esc(rid)}" data-h="${esc(h || '')}">${esc(label || 'Open')}</button>` : '';
function assetDetail(a) {
  if (!a) return '<div class="card empty"><b>Asset not found</b>It is not in the latest reports.</div>';
  const sig = a.signals.length ? `<section class="card exec-actions asset-signals"><header><h2>Signals</h2><p>Problems of this asset across areas, most severe first</p></header><div class="body"><ul>
    ${a.signals.map(x => `<li><button class="exec-act"${x.report ? ` data-go="${esc(x.report)}" data-h="${esc(x.hash)}"` : ''}><span class="sev-bar sev-${esc(x.severity)}"></span>
      <span class="exec-act-main"><b>${esc(x.text)}</b><span class="exec-act-rec">${esc(SIG_LABEL[x.code] || '')}</span></span><span class="exec-act-meta"><span class="pill ${({critical: 's-fail', warning: 's-warn'})[x.severity] || 's-null'}">${esc(x.severity)}</span></span></button></li>`).join('')}</ul></div></section>`
    : '<section class="card"><div class="body muted">No cross-area signals for this asset.</div></section>';
  const dns = a.dns.length ? `<div class="grid-wrap asset-sub"><table class="grid"><thead><tr><th>Domain</th><th>Score</th><th>DMARC</th><th>SPF</th><th>CAA</th><th>DNSSEC</th><th>Main finding</th><th></th></tr></thead><tbody>
    ${a.dns.map(d => `<tr data-go="${esc(d.report)}" data-h="${esc(d.hash)}"><td><b>${esc(d.domain)}</b><div class="dom-sub">${esc(d.profile || '')}</div></td><td>${scoreTxt(d.score)}</td>
      <td><span class="pill ${d.dmarc_state === 'enforced' ? 's-pass' : d.dmarc_state === 'spoofable' ? 's-fail' : 's-na'}">${esc(d.dmarc)}</span></td><td>${ctlPill(d.spf)}</td><td>${ctlPill(d.caa)}</td><td>${ctlPill(d.dnssec)}</td>
      <td class="sub">${esc(d.main)}</td><td>${openBtn(d.report, d.hash)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="muted">Not in the e-mail and DNS assessment.</p>';
  const web = a.web.length ? `<div class="grid-wrap asset-sub"><table class="grid"><thead><tr><th>Website</th><th>Score</th><th>Mode</th><th>Blocks attacks</th><th>Certificate</th><th>Main finding</th><th></th></tr></thead><tbody>
    ${a.web.map(w => `<tr data-go="${esc(w.report)}" data-h="${esc(w.hash)}"><td><b>${esc(w.domain)}</b><div class="dom-sub">${esc(w.account || '')}</div></td><td>${scoreTxt(w.score)}</td>
      <td><span class="pill ${w.profile === 'bypass' ? 's-fail' : w.profile === 'protected' ? 's-pass' : 's-warn'}">${esc(w.profile)}</span></td>
      <td>${protPill(w.protected)}</td>
      <td class="nowrap">${w.cert_expires ? esc(w.cert_expires) + ' ' : ''}${expiryTxt({kind: 'certificate', days: w.cert_days !== null && w.cert_days !== undefined ? w.cert_days : w.served_cert_days})}</td>
      <td class="sub">${esc(w.main)}</td><td>${openBtn(w.report, w.hash)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="muted">No website of this domain is protected by the WAF assessed.</p>';
  const mail = (a.mail || []).length ? `<div class="grid-wrap asset-sub"><table class="grid"><thead><tr><th>Mail domain</th><th>Score</th><th>Filtered by Proofpoint</th><th>MX</th><th>Threats delivered</th><th>Main finding</th><th></th></tr></thead><tbody>
    ${a.mail.map(m => `<tr data-go="${esc(m.report)}" data-h="${esc(m.hash)}"><td><b>${esc(m.domain)}</b><div class="dom-sub">${esc(m.platform || '')}</div></td><td>${scoreTxt(m.score)}</td>
      <td>${protPill(m.filtered)}</td><td class="sub mono">${esc(m.mx.join(', '))}</td><td class="r num">${m.delivered ? `<b class="tx-bad">${esc(m.delivered)}</b>` : '0'}${m.self_spoof ? ` <span class="tx-bad">(${esc(m.self_spoof)} from the domain itself)</span>` : ''}</td>
      <td class="sub">${esc(m.main)}</td><td>${openBtn(m.report, m.hash)}</td></tr>`).join('')}</tbody></table></div>` : '';
  const exp = a.expiries.length ? `<table class="keys asset-exp">${a.expiries.map(e => `<tr><td>${esc(e.name)}</td><td class="faint">${esc(e.kind)}, ${esc(e.source)}</td><td class="mono">${esc(e.date || '')}</td><td class="r">${expiryTxt(e)}</td></tr>`).join('')}</table>`
    : '<p class="muted">No certificate or registration date known.</p>';
  const t = a.tenant;
  const kv = [['Lowest score', scoreTxt(a.score)], ['E-mail and DNS', a.dns.length ? `${scoreTxt(a.dns_score)} <span class="faint">${plural(a.dns.length, 'domain')}</span>` : '<span class="faint">not assessed</span>'],
    ['Websites', a.web.length ? `${scoreTxt(a.web_score)} <span class="faint">${plural(a.web.length, 'site')}</span>` : '<span class="faint">none</span>'],
    ['Next expiry', a.next_expiry ? `${expiryTxt(a.next_expiry)} <span class="faint">${esc(a.next_expiry.kind)}</span>` : '<span class="faint">-</span>'],
    ['Microsoft tenant', t ? `${scoreTxt(t.score)} <span class="faint">${esc(t.name)}</span>` : '<span class="faint">not linked</span>'],
    ['Owners', esc([...a.owners, ...a.bus].join(', ') || '-')]];
  return `<section class="card asset-head"><div class="body"><div class="asset-title"><h2>${esc(a.key)}</h2>${stPill(a.status)}${tierTag(a.tier)}<span class="spacer"></span>${t ? openBtn(t.report, t.hash, 'Zero Trust report') : ''}</div>
      <div class="kv">${kv.map(([k, v]) => `<div><span>${esc(k)}</span><b>${v}</b></div>`).join('')}</div></div></section>
    ${sig}
    <section class="card asset-card"><header><span class="hub-type">${icon('dns', 14)}E-mail and DNS security</span></header><div class="body">${dns}</div></section>
    ${mail ? `<section class="card asset-card"><header><span class="hub-type">${icon('proofpoint', 14)}Mail filtering (Proofpoint)</span></header><div class="body">${mail}</div></section>` : ''}
    <section class="card asset-card"><header><span class="hub-type">${icon('waf', 14)}Websites protected by the WAF</span></header><div class="body">${web}</div></section>
    <section class="card asset-card"><header><span class="hub-type">${icon('info', 14)}Certificates and registrations</span></header><div class="body">${exp}</div></section>`;
}
const SIG_LABEL = {
  WEB_AND_MAIL_EXPOSED: 'Cross-area: the website can be attacked directly and the domain can be used for phishing in its name',
  WEB_BYPASS: 'Set the website back to active mode in the WAF', WEB_ORIGIN_EXPOSED: 'Restrict the origin to the WAF addresses only',
  WEB_NOT_BLOCKING: 'Set SQL injection, XSS, RFI and illegal resource access to block', DNS_TAKEOVER: 'Remove the reference or register the domain',
  MAIL_SPOOFABLE: 'Move DMARC to p=quarantine, then p=reject', EXPIRED: 'Renew now', EXPIRING: 'Plan the renewal',
  DNS_AXFR_OPEN: 'Allow zone transfers only to the secondary name servers (ACL or TSIG)',
  WEB_NO_CAA: 'Publish CAA records naming only the certificate authorities you use',
  DATA_INCOMPLETE: 'Re-run the assessment with every check, or fix the DNS / API errors shown in the report',
  DNS_NOT_MONITORED: 'Coverage gap: add the domain to the DNS / e-mail assessment',
  SELF_SPOOF_DELIVERED: 'Cross-area: attackers already use the domain as sender. Move DMARC to p=reject and review the Proofpoint spoofing rules',
  MAIL_NOT_IN_PROOFPOINT: 'Coverage gap: add the domain to the Proofpoint assessment, or route its mail through Proofpoint'};
function assetsView() { return S.asset ? assetDetail(AS.find(a => a.key === S.asset)) : assetList(); }
function assetsCard() {
  const top = AS.filter(a => a.status === 'bad' || a.status === 'warn').slice(0, 5);
  if (!top.length) return '';
  return `<section class="card exec-actions"><header><h2>Assets needing attention</h2><p>Domains and websites seen across e-mail/DNS, WAF and certificates</p></header>
    <div class="body"><ul>${top.map(a => `<li><button class="exec-act" data-asset="${esc(a.key)}"><span class="sev-bar sev-${a.status === 'bad' ? 'critical' : 'warning'}"></span>
      <span class="exec-act-main"><b>${esc(a.key)}</b><span class="exec-act-rec">${esc((a.signals[0] || {}).text || 'Lowest score ' + a.score)}</span></span>
      <span class="exec-act-meta">${tierTag(a.tier)}<span class="exec-act-n">${plural(a.signals.length, 'signal')}</span></span></button></li>`).join('')}</ul>
      <button class="btn" data-assets style="margin-top:10px">All ${plural(AS.length, 'asset')}</button></div></section>`;
}

/* ---------- cross-module risks: people and endpoints joined across Proofpoint, SAP IAS, PRA and EDR ---------- */
const LK = M.links || {links: [], summary: {}}, LINKS = LK.links || [];
const AREA_LAB = {email: 'Email security', dns: 'DNS security', waf: 'Imperva Cloud WAF', edr: 'SentinelOne EDR', proofpoint: 'Proofpoint', ias: 'SAP Cloud Identity', pra: 'BeyondTrust PRA', zta: 'Microsoft Zero Trust'};
function linksCard() {
  const sm = LK.summary || {};
  if (!LINKS.length) return (sm.areas || []).length > 1 ? `<section class="card"><div class="body muted">No cross-module risk: ${esc(sm.people_joined || 0)} people and
    ${esc(sm.pra_targets_matched || 0)} privileged access targets were joined across ${esc((sm.areas || []).map(a => AREA_LAB[a] || a).join(', '))}.</div></section>` : '';
  const shown = S.lall ? LINKS : LINKS.slice(0, 6);
  return `<section class="card exec-actions links-card"><header><h2>Cross-module risks</h2><p>The same person or endpoint seen by different tools: risks that no single report shows</p></header>
    <div class="body"><ul>${shown.map(x => `<li><div class="exec-act link-row"><span class="sev-bar sev-${esc(x.severity)}"></span>
      <span class="exec-act-main"><b>${esc(x.title)}</b><span class="exec-act-rec">${esc(x.text)}</span><span class="link-fix">${esc(x.fix)}</span>
        <span class="link-refs">${x.refs.map(r => `<button class="btn small" data-go="${esc(r.report)}" data-h="${esc(r.hash)}">${icon(r.area, 14)}${esc(r.label)}</button>`).join('')}</span></span>
      <span class="exec-act-meta"><span class="pill ${x.severity === 'critical' ? 's-fail' : 's-warn'}">${esc(x.severity)}</span></span></div></li>`).join('')}</ul>
      ${LINKS.length > 6 ? `<button class="btn" data-lall style="margin-top:10px">${S.lall ? 'Show fewer' : `All ${plural(LINKS.length, 'risk')}`}</button>` : ''}
      ${sm.pra_targets_by_address ? `<p class="faint exec-note">${plural(sm.pra_targets_by_address, 'PRA target')} defined by IP address could not be compared with the EDR host names.</p>` : ''}</div></section>`;
}

/* ---------- state & routing: #/overview, #/trends, #/assets[?a=<asset>|?f=<filter>] or #/r/<id>?h=<report hash> ---------- */
const S = {route: 'overview', id: null, asset: null, af: 'all', aq: '', asort: {k: 'risk', d: 1}, apage: 1};
let aqTimer = null;
function toHash() { if (S.route === 'trends') return '#/trends';
  if (S.route === 'assets') return '#/assets' + (S.asset ? '?a=' + encodeURIComponent(S.asset) : S.af !== 'all' ? '?f=' + S.af : ''); if (S.route !== 'r') return '#/overview'; const f = frames[S.id]; return `#/r/${S.id}${f && f.hash ? '?h=' + encodeURIComponent(f.hash) : ''}`; }
function fromHash() {
  if (location.hash === '#/trends' && hasTrends()) return {route: 'trends', id: null, inner: ''};
  const am = location.hash.match(/^#\/assets(?:\?(.*))?$/);
  if (am && hasAssets()) { const q = new URLSearchParams(am[1] || ''); return {route: 'assets', id: null, inner: '', asset: q.get('a'), af: q.get('f') || 'all'}; }
  const m = location.hash.match(/^#\/r\/([^?]+)(?:\?h=(.*))?$/);
  if (m && RP.some(r => r.id === m[1])) return {route: 'r', id: m[1], inner: m[2] ? decodeURIComponent(m[2]) : ''};
  return {route: 'overview', id: null, inner: ''};
}
function open(id, inner, push) {
  S.route = 'r'; S.id = id;
  ensureFrame(id, inner);
  const h = `#/r/${id}${inner ? '?h=' + encodeURIComponent(inner) : (frames[id].hash ? '?h=' + encodeURIComponent(frames[id].hash) : '')}`;
  if (location.hash !== h) history[push === false ? 'replaceState' : 'pushState'](null, '', h);
  render();
  frames[id].el.focus();
}
function page(route, push) { S.route = route; S.id = null; if (route !== 'assets') S.asset = null; const h = toHash(); if (location.hash !== h) history[push === false ? 'replaceState' : 'pushState'](null, '', h); render(); window.scrollTo(0, 0); }
const home = push => page('overview', push);
function openAsset(key, push) { S.asset = key; page('assets', push); }
window.addEventListener('popstate', () => { const r = fromHash(); if (r.route === 'r') { open(r.id, r.inner, false); return; } S.asset = r.asset || null; S.af = r.af || 'all'; page(r.route, false); });

/* ---------- chrome ---------- */
function subNav(r) {
  const f = frames[r.id];
  if (!f || !f.nav.length) return '<div class="hub-sub"><span class="faint hub-subload">Loading sections\u2026</span></div>';
  const item = (x, attr) => `<button class="nav-item hub-subitem" ${attr}${x.current ? ' aria-current="page"' : ''}><span>${esc(x.label)}</span>${x.count ? `<span class="count">${esc(x.count)}</span>` : ''}</button>`;
  const routes = f.nav.filter(x => x.route), pillars = f.nav.filter(x => x.pillar);
  return `<div class="hub-sub">${routes.map(x => item(x, `data-sub-route="${esc(x.route)}"`)).join('')}
    ${pillars.length ? `<div class="hub-subsep">Pillars</div>${pillars.map(x => item(x, `data-sub-pillar="${esc(x.pillar)}"`)).join('')}` : ''}</div>`;
}
function side() {
  return `<div class="brand"><div class="brand-mark">${icon('shield', 18)}</div><div><b>GuardHub</b>${M.title ? `<small>${esc(M.title)}</small>` : ''}</div></div>
    <nav class="nav" aria-label="Portal"><button class="nav-item" data-home${S.route === 'overview' ? ' aria-current="page"' : ''}>${icon('grid')}<span>Overview</span></button>
      ${hasTrends() ? `<button class="nav-item" data-trends${S.route === 'trends' ? ' aria-current="page"' : ''}>${icon('trend')}<span>Trends</span><span class="count">${RUNS.length}</span></button>` : ''}
      ${hasAssets() ? `<button class="nav-item" data-assets${S.route === 'assets' ? ' aria-current="page"' : ''}>${icon('assets')}<span>Assets</span><span class="count">${AS.length}</span></button>` : ''}
      <div class="nav-sep">Reports</div>
      ${RP.map(r => { const on = S.route === 'r' && S.id === r.id;
        return `<button class="nav-item hub-item${on ? ' on' : ''}" data-open="${r.id}"${on && !(frames[r.id] && frames[r.id].nav.some(x => x.current)) ? ' aria-current="page"' : ''} title="${esc(r.title)}">${icon(r.type)}
          <span class="hub-name"><span>${esc(r.label)}</span><small>${esc(r.subtitle || r.file)}</small></span><span class="hub-grade g-${esc(r.grade)}">${esc(r.grade)}</span></button>${on ? subNav(r) : ''}`; }).join('')}</nav>
    <div class="side-foot">${S.route === 'r' && frames[S.id] && frames[S.id].nav.some(x => x.action === 'keys') ? `<button class="nav-item" data-sub-action="keys">${icon('info')}<span>Report shortcuts</span></button>` : ''}
      <button class="nav-item" data-action="about">${icon('info')}<span>About this portal</span></button>
      ${themeControl()}</div>`;
}
const searchBtn = `<button class="cmdk" data-action="palette" aria-label="Search all reports">${icon('search')}<span class="lbl">Search all reports</span><span class="kbd">Ctrl K</span></button>`;
function topbar() {
  if (S.route === 'assets' && S.asset) return `<button class="btn icon ghost" data-assets aria-label="Back to the assets" title="Assets">${icon('left')}</button>
    <div class="hub-crumb"><span class="faint">Assets</span><span class="faint">/</span><h1>${esc(S.asset)}</h1></div><span class="spacer"></span>${searchBtn}<button class="btn" data-action="print">${icon('print')}<span>Print</span></button>`;
  if (S.route === 'assets') return `<h1>Assets</h1><span class="sub">${plural(AS.length, 'asset')} across reports</span><span class="spacer"></span>${searchBtn}<button class="btn" data-action="print">${icon('print')}<span>Print</span></button>`;
  if (S.route === 'trends') return `<h1>Trends</h1><span class="sub">${RUNS.length} assessments</span><span class="spacer"></span>${searchBtn}<button class="btn" data-action="print">${icon('print')}<span>Print</span></button>`;
  if (S.route !== 'r') return `<h1>${esc(M.title || 'Overview')}</h1><span class="sub">${RP.length} report${RP.length === 1 ? '' : 's'}, portal generated ${esc(M.generated)}</span><span class="spacer"></span>
    ${searchBtn}<button class="btn" data-action="print">${icon('print')}<span>Print overview</span></button>`;
  const r = RP.find(x => x.id === S.id), f = frames[S.id] || {};
  return `<button class="btn icon ghost" data-home aria-label="Back to the overview" title="Overview">${icon('left')}</button>
    <div class="hub-crumb"><span class="faint">${esc(r.label)}</span>${f.heading ? `<span class="faint">/</span><h1>${esc(f.heading)}</h1>` : `<h1 class="sr-only">${esc(r.label)}</h1>`}</div><span class="sub">${esc(f.sub || r.subtitle)}</span><span class="spacer"></span>
    ${searchBtn}${f.pdf ? `<button class="btn" data-action="report-pdf">${icon('print')}<span>Executive PDF</span></button>` : ''}
    <button class="btn icon ghost" data-action="copy-link" title="Copy link to this view" aria-label="Copy link to this view">${icon('link')}</button>
    <button class="btn icon ghost" data-action="newtab" title="Open in a new tab" aria-label="Open in a new tab">${icon('ext')}</button>
    <button class="btn icon ghost" data-action="download" title="Download the report" aria-label="Download the report">${icon('download')}</button>`;
}
function chrome() { $('#side').innerHTML = side(); $('#topbar').innerHTML = topbar(); }

/* ---------- overview ---------- */
const MAXAGE = M.max_age_days || {email: 2, dns: 2, proofpoint: 2, waf: 2, edr: 2, ias: 2, pra: 2, zta: 35};
function fresh(r) {
  const t = Date.parse(r.date), age = isNaN(t) ? null : (Date.now() - t) / 864e5, lim = MAXAGE[r.type];
  return {age, lim, stale: age !== null && lim !== undefined && age > lim,
    txt: age === null ? '' : age < 1 ? 'today' : `${Math.floor(age)} day${Math.floor(age) === 1 ? '' : 's'} old`};
}
const freshTag = r => { const f = fresh(r); if (f.age === null) return '';
  return `<span class="fresh${f.stale ? ' stale' : ''}" title="Data from ${esc(fmtD(r.date))}; flagged as stale after ${esc(f.lim)} days">${f.stale ? '\u26A0 ' : ''}Data ${esc(f.txt)}${f.stale ? ` (limit ${esc(f.lim)} days)` : ''}</span>${(M.failed || {})[r.type] ? ' <span class="fresh stale" title="' + esc(M.failed[r.type].error || '') + '">\u26A0 Last update failed</span>' : ''}`; };
const FAILED = M.failed || {};
function staleBanner() {
  const fl = RP.filter(r => FAILED[r.type]);
  const st = RP.filter(r => r.exec && fresh(r).stale && !FAILED[r.type]);
  if (!st.length && !fl.length) return '';
  return `<div class="card stale-banner" role="status">${fl.length ? `<b>Last update failed:</b> ${fl.map(r => `${esc(r.label)} (${esc(FAILED[r.type].error || 'error')}): the data shown is from ${esc(fmtD(r.date))}`).join('; ')}. See the run log on the server.` : ''}
    ${st.length ? `${fl.length ? '<br>' : ''}<b>Incomplete picture:</b> ${st.map(r => `${esc(r.label)} data is ${esc(fresh(r).txt)} (limit ${esc(fresh(r).lim)} days)`).join('; ')}.
    Figures for ${st.length === 1 ? 'this area' : 'these areas'} may not reflect the current state: re-run the assessment.` : ''}</div>`;
}
const deltaTxt = d => !d || (d.improved === null && d.worsened === null) ? '' :
  `<span class="delta-up">${d.improved || 0} better</span>, <span class="delta-down">${d.worsened || 0} worse</span> since the baseline`;
const AREA_ST = {good: ['On track', 'pass'], warn: ['Needs attention', 'warn'], bad: ['At risk', 'fail'], unknown: ['Not verified', 'na']};
const NOUN = {email: ['domain', 'domains'], dns: ['domain', 'domains'], waf: ['website', 'websites'], edr: ['endpoint', 'endpoints'], proofpoint: ['domain', 'domains'], ias: ['user', 'users'], pra: ['object', 'objects']};
function tone(k) {
  if (k.value === null || k.value === undefined) return 'na';
  const v = k.unit === '/100' || k.unit === '%' ? k.value : null;
  if (v === null) return k.hib ? 'good' : (k.value ? 'bad' : 'good');
  return k.hib ? (v >= 90 ? 'good' : v >= 70 ? 'warn' : 'bad') : (v <= 10 ? 'good' : v <= 30 ? 'warn' : 'bad');
}
const trendChip = (t, unit) => t === null || t === undefined ? '' : t === 0 ? '<span class="exec-trend">no change since baseline</span>'
  : `<span class="exec-trend ${t > 0 ? 'up' : 'down'}">${t > 0 ? '\u25B2 +' : '\u25BC '}${t}${unit || ''} since baseline</span>`;
function overview() {
  const PF = M.portfolio || {}, areas = RP.filter(r => r.exec);
  const order = ['spoof', 'pp_routing', 'pp_clicks', 'dnssec', 'caa', 'waf', 'edr_protect', 'edr_coverage', 'ias_priv_pwd', 'ias_corporate', 'pra_mfa', 'pra_vendor', 'pra_recorded', 'edr_health', 'pp_delivered', 'ias_inactive', 'zt', 'mfa', 'pr', 'dev'];
  const kpis = areas.flatMap(r => r.exec.kpis.map(k => ({...k, r}))).sort((a, b) => order.indexOf(a.key) - order.indexOf(b.key)).slice(0, 8);
  const hero = `<section class="card exec-hero"><div><p class="exec-kicker">${esc(M.title)}</p><h2 class="exec-headline">${esc(PF.sentence || '')}</h2>
      <div class="exec-chips">${RP.map(r => { const st = AREA_ST[(r.exec || {}).status || 'unknown']; return `<button class="exec-chip" data-open="${r.id}"><i class="dot c-${st[1]}"></i>${esc(r.label)}<span>${esc(st[0])}${FAILED[r.type] ? ' \u00b7 update failed' : fresh(r).stale ? ' \u00b7 stale data' : ''}</span></button>`; }).join('')}</div></div>
    <div class="exec-meta">${RP.length} report${RP.length === 1 ? '' : 's'}<br>Portal generated ${esc(M.generated)}</div></section>`;
  const kpiHtml = kpis.length ? `<div class="exec-kpis" style="--kcols:${kpis.length <= 4 ? kpis.length : kpis.length % 4 === 0 || kpis.length === 7 ? 4 : 3}">${kpis.map(k => { const t = tone(k), v = k.value === null || k.value === undefined ? null : k.value;
    return `<button class="exec-kpi t-${t}" data-go="${k.r.id}" data-h="${esc(k.hash)}" title="Open in ${esc(k.r.label)}">
      <span class="exec-kpi-lbl">${esc(k.label)}</span><b>${v === null ? '-' : esc(v)}<small>${esc(k.unit)}</small></b>
      ${v !== null && (k.unit === '%' || k.unit === '/100') ? `<span class="exec-bar"><i style="width:${Math.max(0, Math.min(100, v))}%"></i>${k.target ? `<em style="left:${k.target}%" title="Target ${k.target}"></em>` : ''}</span>` : ''}
      <span class="exec-kpi-det">${esc(k.detail)}</span>${spark(seriesFor(k.key, k.r))}${histDelta(seriesFor(k.key, k.r)) || trendChip(k.trend, k.unit === '/100' ? ' pts' : '')}</button>`; }).join('')}</div>` : '';
  const areaHtml = `<div class="exec-areas">${RP.map(r => { const x = r.exec, st = AREA_ST[(x || {}).status || 'unknown'];
    return `<section class="card exec-area"><header><span class="hub-type">${icon(r.type)}${esc(r.label)}</span><span class="act"><span class="pill s-${st[1]}">${esc(st[0])}</span></span></header>
      <div class="body"><div class="exec-area-head"><span class="letter g-${esc(r.grade)}">${esc(r.grade)}</span><div><b class="num">${r.score === null || r.score === undefined ? '-' : esc(r.score)}<small>/100</small></b>
        <div class="lbl">${esc(r.subtitle || r.title)}</div>${freshTag(r)}${histDelta(seriesFor('score', r)) || (x ? trendChip(x.trend, r.type === 'zta' ? ' pts' : ' pts avg') : '')}</div>${spark(seriesFor('score', r)) ? `<div class="area-spark">${spark(seriesFor('score', r))}</div>` : ''}</div>
      ${x ? `<ul class="exec-side">${x.side.map(([l, v, tn]) => `<li><span>${esc(l)}</span><b class="tx-${esc(tn)}">${esc(v)}</b></li>`).join('')}</ul>` : '<p class="muted">Not a Guard report: open it to view the content.</p>'}
      <button class="btn" data-open="${r.id}" style="margin-top:auto;align-self:flex-start">Open report</button></div></section>`; }).join('')}</div>`;
  const acts = PF.actions || [];
  const actHtml = acts.length ? `<section class="card exec-actions"><header><h2>Priority actions</h2><p>The few changes that remove the most risk, grouped by problem across assets</p></header><div class="body"><ul>
    ${acts.map(a => `<li><button class="exec-act" data-go="${esc(a.report)}" data-h="${esc(a.hash)}"><span class="sev-bar sev-${esc(a.severity)}"></span>
      <span class="exec-act-main"><b>${esc(a.title)}</b><span class="exec-act-rec">${esc(a.rec)}</span></span>
      <span class="exec-act-meta"><span class="hub-type">${icon(a.area, 14)}${esc(a.label)}</span>
        <span class="exec-act-n">${a.area === 'zta' ? 'single control' : a.count === null || a.count === undefined ? 'console setting' : `${esc(a.count)} ${(NOUN[a.area] || ['asset', 'assets'])[a.count === 1 ? 0 : 1]}${a.share !== null && a.share !== undefined ? ` <span class="faint">(${esc(a.share)}%)</span>` : ''}`}${a.critical_tier ? `, <span class="tx-bad">${esc(a.critical_tier)} critical tier</span>` : ''}</span></span></button></li>`).join('')}</ul></div></section>` : '';
  const risks = RP.flatMap(r => (r.top || []).map((t, k) => ({...t, r, k}))).sort((a, b) => (a.severity === 'critical' ? 0 : 1) - (b.severity === 'critical' ? 0 : 1) || a.k - b.k).slice(0, 20);
  const riskCell = t => t.score !== null && t.score !== undefined ? `<span class="score ${scoreCls(t.score)}">${esc(t.score)}</span>` : `<span class="pill ${({high: 's-fail', medium: 's-warn', low: 's-null'})[t.risk] || 's-na'}">${esc(t.risk || '')}</span>`;
  const detail = risks.length ? `<details class="card exec-detail"><summary><b>Most exposed assets and controls</b> <span class="faint">${risks.length} items, for analysts</span></summary>
    <div class="grid-wrap" style="max-height:none;border:0;border-radius:0"><table class="grid"><thead><tr><th>Source</th><th class="sticky">Item</th><th>Score or risk</th><th>Main finding</th></tr></thead><tbody>
    ${risks.map(t => `<tr data-go="${t.r.id}" data-h="${esc(t.hash)}"><td class="nowrap"><span class="hub-type">${icon(t.r.type, 14)}${esc(t.r.label)}</span></td><td class="sticky"><button class="dom" style="word-break:normal" data-go="${t.r.id}" data-h="${esc(t.hash)}">${esc(t.item)}</button></td>
      <td>${riskCell(t)}</td><td class="sub">${esc(t.detail)}</td></tr>`).join('')}</tbody></table></div></details>` : '';
  return `<div class="print-head"><h1>${esc(M.title || 'GuardHub')}</h1><p class="muted">Generated ${esc(M.generated)}</p></div>
    ${staleBanner()}${areaHtml}
    ${kpiHtml ? `<div class="section-title exec-sec"><h2>Key indicators</h2><p>Outcomes measured across all reports. Select one to see the affected items.</p></div>${kpiHtml}` : ''}
    ${actHtml}${linksCard()}${assetsCard()}${detail}
    <p class="faint exec-note">Each tool scores on its own scale: grades are not comparable across areas. Targets on the bars mark the expected end state.</p>`;
}
function render() {
  applyTheme();
  chrome();
  const inReport = S.route === 'r';
  document.body.classList.toggle('in-report', inReport);
  $('#view').innerHTML = inReport ? '' : S.route === 'trends' ? trends() : S.route === 'assets' ? assetsView() : overview();
  Object.entries(frames).forEach(([id, f]) => { f.el.hidden = !(inReport && id === S.id); });
  const r = inReport ? RP.find(x => x.id === S.id) : null;
  document.title = (r ? r.label + ' - ' : S.route === 'trends' ? 'Trends - ' : S.route === 'assets' ? (S.asset ? S.asset + ' - ' : '') + 'Assets - ' : '') + (M.title || 'GuardHub');
}

/* ---------- search across all reports ---------- */
let INDEX = null, pal = null;
function payloadOf(id) {
  const m = html(id).match(/<script type="application\/json" id="mg-data">([\s\S]*?)<\/script>/);
  try { return m ? JSON.parse(m[1]) : null; } catch (e) { return null; }
}
function buildIndex() {
  INDEX = [];
  RP.forEach(r => {
    const p = payloadOf(r.id);
    if (!p) return;
    const enc = encodeURIComponent;
    if (r.type === 'zta') {
      (p.tests || []).forEach(t => INDEX.push({r, t: t.title, h: `${t.status}, ${t.risk} risk`, go: '#/tests?d=' + enc(t.id), s: `${t.title} ${t.id} ${t.category}`.toLowerCase()}));
      [...new Set((p.tests || []).map(t => t.category))].forEach(c => INDEX.push({r, t: c, h: 'category', go: '#/tests?category=' + enc(c), s: String(c).toLowerCase(), kind: 'f'}));
    } else {
      (p.results || []).forEach(x => INDEX.push({r, t: x.domain, h: `score ${x.overall_score}${x.owner ? ', ' + x.owner : ''}`, go: '#/domains?d=' + enc(x.domain), s: `${x.domain} ${x.owner || ''} ${x.bu || ''} ${x.site_id || ''}`.toLowerCase()}));
      const n = {};
      (p.results || []).forEach(x => new Set((x.issues || []).map(i => i.code)).forEach(c => { n[c] = (n[c] || 0) + 1; }));
      Object.entries(n).forEach(([c, k]) => { const f = (p.findings || {})[c]; if (f) INDEX.push({r, t: f[2], h: `${k} affected`, go: '#/domains?finding=' + enc(c), s: `${f[2]} ${f[1]} ${c}`.toLowerCase(), kind: 'f'}); });
    }
  });
}
function paletteItems(q) {
  q = q.trim().toLowerCase();
  const out = [], add = (g, t, h, run) => out.push({g, t, h, run});
  [['Overview', () => home()], ...(hasTrends() ? [['Trends', () => page('trends')]] : []), ...(hasAssets() ? [['Assets', () => openAsset(null)]] : [])].forEach(([t, fn]) => { if (!q || t.toLowerCase().includes(q)) add('Go to', t, '', fn); });
  RP.forEach(r => { if (!q || r.label.toLowerCase().includes(q) || (r.subtitle || '').toLowerCase().includes(q)) add('Reports', r.label, r.subtitle, () => open(r.id, '')); });
  if (S.route === 'r' && frames[S.id]) frames[S.id].nav.filter(x => x.route || x.pillar).forEach(x => { if (!q || x.label.toLowerCase().includes(q)) add('In this report', x.label, x.count, () => tell(S.id, {mgHubClick: x.route ? {route: x.route} : {pillar: x.pillar}})); });
  if (q) {
    AS.filter(a => [a.key, ...a.owners, ...a.dns.map(d => d.domain), ...a.web.map(w => w.domain)].some(x => String(x).toLowerCase().includes(q))).slice(0, 6)
      .forEach(a => add('Assets', a.key, `${AREA_ST[a.status][0]}, ${plural(a.signals.length, 'signal')}`, () => openAsset(a.key)));
    if (!INDEX) buildIndex();
    const per = {};
    INDEX.filter(e => e.s.includes(q)).forEach(e => { const k = e.r.id + (e.kind || ''); per[k] = (per[k] || 0) + 1;
      if (per[k] <= (e.kind ? 4 : 6)) add(e.r.label + (e.kind ? ', findings' : ''), e.t, e.h, () => open(e.r.id, e.go)); });
  }
  [...themeActions(), ['Print this page', () => window.print()]].forEach(([t, fn]) => { if (!q || t.toLowerCase().includes(q)) add('Actions', t, '', fn); });
  return out;
}
function openPalette() {
  pal = {idx: 0, items: paletteItems('')};
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-label="Search all reports"><div class="pal-input">${icon('search', 18)}<input id="pal-q" placeholder="Search domains, websites, tests, findings across all reports" autocomplete="off" role="combobox" aria-expanded="true" aria-controls="pal-list"><span class="kbd">Esc</span></div>
    <ul class="pal-list" id="pal-list" role="listbox"></ul><div class="pal-foot"><span><span class="kbd">\u2191</span> <span class="kbd">\u2193</span> move</span><span><span class="kbd">Enter</span> open</span><span><span class="kbd">Esc</span> close</span></div></div></div>`;
  renderPalette();
  $('#pal-q').focus();
}
function renderPalette() {
  let g = '', h = '';
  pal.items.forEach((it, k) => { if (it.g !== g) { g = it.g; h += `<li class="pal-group" role="presentation">${esc(g)}</li>`; }
    h += `<li class="pal-item" role="option" id="pal-${k}" data-pal="${k}" aria-selected="${k === pal.idx}"><span class="ptitle">${esc(it.t)}</span><span class="phint">${esc(it.h || '')}</span></li>`; });
  $('#pal-list').innerHTML = h || '<li class="pal-group">No results</li>';
  const c = $('#pal-' + pal.idx); if (c) c.scrollIntoView({block: 'nearest'});
}
function runPalette(k) { const it = pal && pal.items[k]; closeOverlay(); if (it) it.run(); }

/* ---------- actions ---------- */
function toast(m) { const t = document.createElement('div'); t.className = 'toast'; t.textContent = m; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 2400); }
function copyText(text, ok) { const done = () => toast(ok);
  const fb = () => { const t = document.createElement('textarea'); t.value = text; t.style.position = 'fixed'; t.style.opacity = '0'; document.body.appendChild(t); t.select(); try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed'); } t.remove(); };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fb); else fb(); }
function about() {
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dlg-t"><header><h2 id="dlg-t">About this portal</h2><button class="btn icon ghost" data-action="close" aria-label="Close">${icon('x')}</button></header>
    <div class="dbody"><p style="margin-bottom:10px">Generated ${esc(M.generated)} with GuardHub ${esc(M.version)}.</p>
    <table class="keys">${RP.map(r => `<tr><td>${esc(r.label)}</td><td class="mono">${esc(r.file)}</td><td class="r">${(r.size / 1048576).toFixed(1)} MB</td>${r.history > 1 ? `<td class="faint">${r.history} runs</td>` : '<td></td>'}</tr>`).join('')}</table>
    <p class="muted" style="margin-top:12px">Grades are computed by each tool on its own scale and are not comparable across tools. Each report runs in an isolated frame: it cannot read the portal or the other reports. Search covers every domain, website, test and finding in the embedded reports.</p>
    <p class="muted" style="margin-top:8px">Shortcuts: <span class="kbd">Ctrl K</span> search, <span class="kbd">0</span> overview, <span class="kbd">1</span>-<span class="kbd">${RP.length}</span> reports${hasTrends() ? ', <span class="kbd">t</span> trends' : ''}${hasAssets() ? ', <span class="kbd">a</span> assets' : ''}.</p></div></div></div>`;
}
document.addEventListener('click', e => {
  const t = e.target.closest('button, tr[data-go], tr[data-asset], [data-overlay], [data-pal]');
  if (!t) return;
  const ds = t.dataset;
  if (ds.overlay !== undefined && e.target === t) { closeOverlay(); return; }
  if (ds.pal !== undefined) { runPalette(+ds.pal); return; }
  if (ds.home !== undefined) { home(); return; }
  if (ds.trends !== undefined) { page('trends'); return; }
  if (ds.assets !== undefined) { openAsset(null); return; }
  if (ds.lall !== undefined) { S.lall = !S.lall; render(); return; }
  if (ds.asset) { openAsset(ds.asset); window.scrollTo(0, 0); return; }
  if (ds.af) { S.af = ds.af; S.apage = 1; history.replaceState(null, '', toHash()); render(); return; }
  if (ds.asort) { const k = ds.asort; S.asort = {k, d: S.asort && S.asort.k === k ? -S.asort.d : 1}; S.apage = 1; $('#view').innerHTML = assetsView(); return; }
  if (ds.apage) { S.apage = +ds.apage; $('#view').innerHTML = assetsView(); const g = $('.asset-grid'); if (g) g.scrollIntoView({block: 'start'}); return; }
  if (ds.open) { if (S.route === 'r' && S.id === ds.open && frames[ds.open]) tell(ds.open, {mgHubClick: {route: 'overview'}}); else open(ds.open, ''); return; }
  if (ds.subRoute) { tell(S.id, {mgHubClick: {route: ds.subRoute}}); frames[S.id].el.focus(); return; }
  if (ds.subPillar) { tell(S.id, {mgHubClick: {pillar: ds.subPillar}}); frames[S.id].el.focus(); return; }
  if (ds.subAction) { tell(S.id, {mgHubClick: {action: ds.subAction}}); return; }
  if (ds.go) { open(ds.go, ds.h || ''); return; }
  const r = RP.find(x => x.id === S.id);
  const acts = {
    theme: toggleTheme, about, close: closeOverlay, print: () => window.print(), palette: openPalette,
    'report-pdf': () => tell(S.id, {mgHubClick: {action: 'print-exec'}}),
    'copy-link': () => copyText(location.href, 'Link to this view copied'),
    newtab: () => { const f = frames[S.id]; const w = window.open(URL.createObjectURL(new Blob([reportDoc(S.id, f ? f.hash : '', false)], {type: 'text/html'})), '_blank', 'noopener'); if (!w) toast('Allow pop-ups to open the report in a new tab'); },
    download: () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([html(S.id)], {type: 'text/html'})); a.download = r ? r.file : 'report.html'; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); }
  };
  if (acts[ds.action]) acts[ds.action]();
});
document.addEventListener('input', e => {
  if (e.target.id === 'pal-q' && pal) { pal.items = paletteItems(e.target.value); pal.idx = 0; renderPalette(); }
  if (e.target.id === 'aq') {  // filter after a short pause: a large inventory is not re-rendered at every key
    S.aq = e.target.value; S.apage = 1; clearTimeout(aqTimer);
    aqTimer = setTimeout(() => { const el = $('#aq'), pos = el ? el.selectionStart : null; $('#view').innerHTML = assetsView(); const n = $('#aq'); if (n) { n.focus(); if (pos !== null) n.setSelectionRange(pos, pos); } }, 140);
  }
});
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal ? closeOverlay() : openPalette(); return; }
  if (pal) {
    if (e.key === 'ArrowDown') { e.preventDefault(); pal.idx = Math.min(pal.items.length - 1, pal.idx + 1); renderPalette(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); pal.idx = Math.max(0, pal.idx - 1); renderPalette(); }
    else if (e.key === 'Enter') { e.preventDefault(); runPalette(pal.idx); }
    else if (e.key === 'Escape') { e.preventDefault(); closeOverlay(); }
    return;
  }
  if (e.key === 'Escape' && $('#overlay-root').innerHTML) { closeOverlay(); return; }
  if (/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === '/') { e.preventDefault(); openPalette(); return; }
  const n = parseInt(e.key, 10);
  if (e.key === '0') home(); else if (e.key === 't' && hasTrends()) page('trends'); else if (e.key === 'a' && hasAssets()) openAsset(null); else if (n >= 1 && n <= RP.length) open(RP[n - 1].id, '');
});

applyTheme();
const start = fromHash();
if (start.route === 'r') open(start.id, start.inner, false); else page(start.route, false);
})();
