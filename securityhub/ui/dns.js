
(function () {
'use strict';
/* @include core.js */
/* @include report-core.js */
/* @include asset-report.js */
/* ================= data ================= */
const D = JSON.parse(document.getElementById('mg-data').textContent);
const R = D.results, CHECKS = D.checks, L = D.labels, ATTR = D.attrs, M = D.meta || {};
const FIND = D.findings, FW = D.frameworks, COMP = D.compliance;
const VIEW = M.view || 'combined', TITLE = M.title || 'Email security posture';
const TOOL = {email: 'MailGuard Email', dns: 'MailGuard DNS'}[VIEW] || 'MailGuard DNS';
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
const $ = (s, r) => (r || document).querySelector(s);
const SEV = {critical: 0, warning: 1, info: 2};
const ST = {
  valid: ['pass', '\u2713', 'Pass'], warning: ['warn', '!', 'Warning'], partial: ['warn', '\u25D0', 'Partial'],
  error: ['fail', '\u2715', 'Fail'], misconfigured: ['fail', '\u2715', 'Misconfigured'], bogus: ['fail', '\u2715', 'Bogus'],
  missing: ['none', '\u2013', 'Missing'], null: ['null', '\u2205', 'Null MX'], na: ['na', '\u00B7', 'Not applicable'],
  dns_error: ['dns', '?', 'DNS error'], unknown: ['dns', '?', 'Unknown'], skipped: ['na', '\u00B7', 'Skipped']
};
const ST_ORDER = ['valid', 'partial', 'warning', 'misconfigured', 'error', 'bogus', 'missing', 'null', 'na', 'dns_error', 'unknown', 'skipped'];
const TIER_ORDER = ['critical', 'high', 'medium', 'low'];
const SHORT = {'mta-sts': 'STS', 'tls-rpt': 'TLS', takeover: 'Deps', axfr: 'XFR', consistency: 'Sync', lookalikes: 'Look'};
const DETAIL = {
  mx: r => r.mx.total_count ? `${r.mx.protected_count}/${r.mx.total_count} protected` : '',
  spf: r => r.spf.record ? `${r.spf.lookups}/10 lookups` : '',
  dkim: r => r.dkim.total_selectors ? `${r.dkim.valid_selectors} key${r.dkim.valid_selectors === 1 ? '' : 's'}` : '',
  dmarc: r => r.dmarc.policy ? `p=${r.dmarc.policy}` : '',
  'mta-sts': r => r.mta_sts.mode ? `mode ${r.mta_sts.mode}` : '',
  caa: r => r.caa.issuers.length ? (r.caa.issuers[0] === ';' ? 'no CA allowed' : `${r.caa.issuers.length} CA${r.caa.issuers.length === 1 ? '' : 's'}`) : '',
  axfr: r => r.axfr.servers.length ? `${r.axfr.servers.filter(s => s.result === 'open').length}/${r.axfr.servers.length} open` : '',
  takeover: r => r.takeover.dependencies.length ? `${r.takeover.dependencies.length} deps` : '',
  lookalikes: r => r.lookalikes.registered.length ? `${r.lookalikes.registered.length} found` : ''
};
R.forEach((r, i) => {
  r._i = i;
  r._crit = r.issues.filter(x => x.severity === 'critical').length;
  r._warn = r.issues.filter(x => x.severity === 'warning').length;
  r._codes = new Set(r.issues.map(x => x.code));
  r._st = c => (r[ATTR[c]] || {}).status || 'missing';
});
const hasMeta = R.some(r => r.owner || r.bu || (r.tags && r.tags.length)) || new Set(R.map(r => r.tier)).size > 1;
const diff = D.diff;
const hasReports = R.some(r => r.dmarc_reports && r.dmarc_reports.status !== 'missing') || (D.unscanned_report_domains || []).length > 0;
const hasLook = CHECKS.includes('lookalikes');
const hasAuth = ['spf', 'dkim', 'dmarc'].every(c => CHECKS.includes(c));
const uniq = a => [...new Set(a.filter(Boolean))].sort();

/* ================= icons ================= */
const ICONS = {
  grid: '<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"/>',
  list: '<path d="M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>',
  alert: '<path d="M12 3.5 2.5 20h19L12 3.5zM12 10v4.5M12 17.2h.01"/>',
  diff: '<path d="M7 4v16M3.5 7.5 7 4l3.5 3.5M17 20V4M13.5 16.5 17 20l3.5-3.5"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5zM3 13l9 5 9-5"/>',
  copy: '<path d="M9 9h11v11H9zM5 15H4V4h11v1"/>',
  mail: '<path d="M3 5h18v14H3zM3 6l9 7 9-7"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4-4"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>', monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>', left: '<path d="m15 6-6 6 6 6"/>', right: '<path d="m9 6 6 6-6 6"/>',
  link: '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3A4.5 4.5 0 0 0 13 4.6l-1 1M14 10a4.5 4.5 0 0 0-6.4 0l-3 3A4.5 4.5 0 0 0 11 19.4l1-1"/>',
  print: '<path d="M6 9V3h12v6M6 18H4v-7h16v7h-2M8 14h8v7H8z"/>', download: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
  filter: '<path d="M3 5h18l-7 8.5V19l-4 2v-7.5L3 5z"/>', columns: '<path d="M3 4h18v16H3zM9 4v16M15 4v16"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>', key: '<rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M7 14h10"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.4 8.6 8 9.5 4.6-.9 8-4.5 8-9.5V6l-8-3z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
  chev: '<path d="m9 6 6 6-6 6"/>', arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>'
};
/* ================= small renderers ================= */
const pill = (s, extra) => { const m = st(s); return `<span class="pill s-${m[0]}"><span class="sym" aria-hidden="true">${m[1]}</span>${esc(m[2])}${extra ? ` <span class="d">${esc(extra)}</span>` : ''}</span>`; };
const sq = (s, label) => { const m = st(s); return `<span class="sq c-${m[0]}" title="${esc(label + ': ' + m[2])}" aria-label="${esc(label + ': ' + m[2])}">${m[1]}</span>`; };
/* ================= preferences & state ================= */
const PREF_KEY = 'mailguard-prefs-v31';
const P = {density: 'comfortable', view: 'table', size: 50, hidden: []};
try { Object.assign(P, JSON.parse(localStorage.getItem(PREF_KEY) || '{}')); } catch (e) { /* storage unavailable */ }
const savePrefs = () => { try { localStorage.setItem(PREF_KEY, JSON.stringify(P)); } catch (e) { /* ignore */ } };
const FKEYS = ['q', 'score', 'smin', 'smax', 'tier', 'owner', 'bu', 'tag', 'finding', 'changed', 'comp', 'profile'];
const blank = () => ({q: '', f: {}, score: '', smin: '', smax: '', tier: '', owner: '', bu: '', tag: '', finding: '', changed: '', comp: '', profile: ''});
const S = Object.assign({route: 'overview', sort: {k: 'priority', d: -1}, page: 1, open: null, dtab: 'overview', sel: new Set(),
  groupBy: hasMeta ? 'owner' : 'tier', cursor: -1, menu: null, filtersOpen: false, fsev: '', fq: '', lmx: false, overlay: null}, blank());

/* ================= routing (state in the URL hash: shareable views) ================= */
const ROUTES = [
  {id: 'overview', label: 'Overview', icon: 'grid', show: () => true},
  {id: 'domains', label: 'Domains', icon: 'list', show: () => true, count: () => R.length},
  {id: 'findings', label: 'Findings', icon: 'alert', show: () => true, count: () => findingCounts().length},
  {id: 'changes', label: 'Changes', icon: 'diff', show: () => !!diff, count: () => R.filter(r => r.change && r.change.changed).length},
  {id: 'groups', label: 'Groups', icon: 'layers', show: () => hasMeta},
  {id: 'lookalikes', label: 'Lookalikes', icon: 'copy', show: () => hasLook, count: () => lookRows().length},
  {id: 'reports', label: 'DMARC reports', icon: 'mail', show: () => hasReports}
];
window.addEventListener('popstate', () => { fromHash(); render(); });

/* ================= filtering ================= */
function matches(r) {
  const q = S.q.trim().toLowerCase();
  if (q && !(r.domain.includes(q) || (r.owner || '').toLowerCase().includes(q) || (r.bu || '').toLowerCase().includes(q)
      || (r.tags || []).some(t => t.toLowerCase().includes(q)))) return false;
  for (const c of CHECKS) if (S.f[c] && r._st(c) !== S.f[c]) return false;
  const sc = r.overall_score;
  if (S.score && !({hi: sc >= 80, mid: sc >= 50 && sc < 80, lo: sc < 50})[S.score]) return false;
  if (S.smin !== '' && sc < +S.smin) return false;
  if (S.smax !== '' && sc > +S.smax) return false;
  if (S.tier && r.tier !== S.tier) return false;
  if (S.owner && r.owner !== S.owner) return false;
  if (S.bu && r.bu !== S.bu) return false;
  if (S.tag && !(r.tags || []).includes(S.tag)) return false;
  if (S.finding && !r._codes.has(S.finding)) return false;
  if (S.changed && !(r.change && r.change.changed)) return false;
  if (S.profile && r.profile !== S.profile) return false;
  if (S.comp) { const [k, v] = S.comp.split(':'); if ((r.compliance || {})[k] !== v) return false; }
  return true;
}
const SORTERS = {
  domain: r => r.domain, score: r => r.overall_score, priority: r => r.priority, tier: r => tierW(r.tier),
  findings: r => r._crit * 1000 + r._warn, delta: r => (r.change && r.change.score_delta) || 0
};
let _cache = {key: null, list: null};
function chips() {
  const out = [];
  if (S.q) out.push(['q', `Search "${S.q}"`]);
  CHECKS.forEach(c => { if (S.f[c]) out.push(['c.' + c, `${L[c]}: ${st(S.f[c])[2]}`]); });
  if (S.score) out.push(['score', {hi: 'Score 80 and above', mid: 'Score 50 to 79', lo: 'Score under 50'}[S.score]]);
  if (S.smin !== '' || S.smax !== '') out.push(['range', `Score ${S.smin || 0} to ${S.smax || 100}`]);
  if (S.tier) out.push(['tier', `Tier ${S.tier}`]);
  if (S.owner) out.push(['owner', `Owner ${S.owner}`]);
  if (S.bu) out.push(['bu', `Unit ${S.bu}`]);
  if (S.tag) out.push(['tag', `Tag ${S.tag}`]);
  if (S.finding) out.push(['finding', findingTitle(S.finding)]);
  if (S.changed) out.push(['changed', 'Changed since baseline']);
  if (S.profile) out.push(['profile', {'non-mail': 'Does not handle mail', unreachable: 'DNS unreachable', nonexistent: 'Does not exist', mail: 'Handles mail'}[S.profile] || S.profile]);
  if (S.comp) { const [k, v] = S.comp.split(':'); out.push(['comp', `${(COMP[k] || [k])[0]}: ${v}`]); }
  return out;
}
/* ================= sidebar & top bar ================= */
function side() {
  const live = R.filter(r => r.profile !== 'nonexistent');
  const avg = weighted(live, r => r.overall_score), g = gradeOf(avg);
  const visible = ROUTES.filter(x => x.show());
  return `<div class="brand"><div class="brand-mark">${icon('shield', 18)}</div><div><b>${esc(TOOL)}</b><small>${esc(TITLE)}</small></div></div>
    <button class="posture" data-route="overview" title="Portfolio grade"><span class="letter g-${g}">${g}</span>
      <span><b class="num">${avg.toFixed(0)}/100</b><br>${R.length} domains</span></button>
    <nav class="nav" aria-label="Sections">${visible.map((x, k) => {
      const c = x.count ? x.count() : null;
      return `<button class="nav-item" data-route="${x.id}"${S.route === x.id ? ' aria-current="page"' : ''} title="${esc(x.label)} (${k + 1})">
        ${icon(x.icon)}<span>${esc(x.label)}</span>${c !== null ? `<span class="count">${c}</span>` : ''}</button>`; }).join('')}</nav>
    <div class="side-foot">
      <button class="nav-item" data-action="about">${icon('info')}<span>About this scan</span></button>
      <button class="nav-item" data-action="keys">${icon('key')}<span>Keyboard shortcuts</span><span class="count"><span class="kbd">?</span></span></button>
      ${themeControl()}
    </div>`;
}
function topbar() {
  const r = ROUTES.find(x => x.id === S.route) || ROUTES[0];
  let sub = '';
  if (S.route === 'domains') { const n = list().length; sub = n === R.length ? `${R.length} domains` : `${n} of ${R.length} domains`; }
  else if (S.route === 'overview') sub = `Scanned ${esc(M.generated || '')}`;
  return `<h1>${esc(r.label)}</h1><span class="sub">${sub}</span><span class="spacer"></span>
    <button class="cmdk" data-action="palette" aria-label="Search domains, findings and actions">${icon('search')}<span class="lbl">Search domains, findings, actions</span><span class="kbd">Ctrl K</span></button>
    <button class="btn" data-action="print-exec" title="Executive summary as PDF">${icon('print')}<span>Executive PDF</span></button>`;
}

/* ================= overview ================= */
function overview() {
  const live = R.filter(r => r.profile !== 'nonexistent');
  const avg = weighted(live, r => r.overall_score), g = gradeOf(avg);
  let delta = null;
  if (diff) {
    const same = live.filter(r => r.change && !r.change.new && r.change.previous_score !== null && r.change.previous_score !== undefined);
    if (same.length) delta = weighted(same, r => r.overall_score) - weighted(same, r => +r.change.previous_score);
  }
  const n = R.length;
  const hi = R.filter(r => r.overall_score >= 80).length, mid = R.filter(r => r.overall_score >= 50 && r.overall_score < 80).length;
  const nonmail = R.filter(r => r.profile === 'non-mail').length, unreach = R.filter(r => r.profile === 'unreachable').length;
  const kpi = (val, label, cls, attrs) => `<button class="kpi ${cls || ''}" ${attrs}><b>${val}</b><span>${esc(label)}</span></button>`;
  let h = `<div class="print-head"><h1>${esc(TITLE)}</h1><p class="muted">${R.length} domains, scanned ${esc(M.generated || '')}</p></div>
  <div class="ov-top">
    <section class="card grade-card" aria-label="Portfolio grade">
      <div class="letter g-${g}">${g}</div><div class="lbl">Portfolio grade</div>
      <div class="avg">${avg.toFixed(0)}<small>/100</small></div>
      <div class="lbl">${hasMeta ? 'Average weighted by tier' : 'Average score'}${delta !== null ? `, <span class="${delta >= 0 ? 'delta-up' : 'delta-down'}">${delta >= 0 ? '+' : ''}${delta.toFixed(1)} since baseline</span>` : ''}</div>
    </section>
    <section class="card kpi-card">
      ${kpi(n, 'domains analyzed', '', 'data-route="domains"')}
      ${kpi(hi, 'fully protected, 80+', 'k-pass', 'data-filter="score" data-value="hi"')}
      ${kpi(mid, 'need attention, 50 to 79', 'k-warn', 'data-filter="score" data-value="mid"')}
      ${kpi(n - hi - mid, 'critical risk, under 50', 'k-fail', 'data-filter="score" data-value="lo"')}
      ${nonmail && VIEW !== 'dns' ? kpi(nonmail, 'do not handle mail', '', 'data-filter="profile" data-value="non-mail"') : ''}
      ${unreach ? kpi(unreach, 'DNS unreachable', '', 'data-filter="profile" data-value="unreachable"') : ''}
    </section>
  </div><div class="ov-grid">`;
  // control coverage
  const present = new Set();
  const rows = CHECKS.map(c => {
    const counts = {};
    R.forEach(r => { const s = r._st(c); counts[s] = (counts[s] || 0) + 1; });
    const segs = ST_ORDER.filter(s => counts[s]).map(s => { present.add(st(s)[0]); const lbl = `${L[c]}: ${st(s)[2]}, ${counts[s]} domain${counts[s] === 1 ? '' : 's'}`;
      return `<button class="c-${st(s)[0]}" style="flex:${counts[s]}" data-check="${c}" data-status="${s}" title="${esc(lbl)}" aria-label="${esc(lbl)}"></button>`; }).join('');
    return `<div class="cov-row"><span>${esc(L[c])}</span><div class="cov-bar">${segs}</div><span class="cov-num">${pct(counts.valid || 0, n)}%</span></div>`;
  }).join('');
  const LEG = {pass: 'Pass', warn: 'Warning or partial', fail: 'Fail', none: 'Missing', null: 'Null MX', na: 'Not applicable', dns: 'DNS error'};
  h += `<section class="card span2"><header><h2>Control coverage</h2><p>Share of domains passing each control. Select a segment to list those domains.</p></header>
    <div class="body"><div class="cov">${rows}</div><div class="legend">${Object.keys(LEG).filter(k => present.has(k)).map(k => `<span><i class="dot c-${k}"></i>${LEG[k]}</span>`).join('')}</div></div></section>`;
  // distribution
  const bins = Array(10).fill(0);
  live.forEach(r => { bins[Math.min(9, Math.floor(r.overall_score / 10))]++; });
  const max = Math.max(1, ...bins);
  const bars = bins.map((v, i) => { const hh = Math.max(v ? 3 : 0, Math.round(104 * v / max)), x = 14 + i * 37, y = 118 - hh;
    const col = i >= 8 ? 'var(--pass)' : i >= 5 ? 'var(--warn)' : 'var(--fail)';
    const lo = i * 10, hiB = i === 9 ? 100 : i * 10 + 9;
    return `<rect class="hbar" x="${x}" y="${y}" width="31" height="${hh}" rx="3" fill="${col}" data-smin="${lo}" data-smax="${hiB}" tabindex="0" role="button" aria-label="${v} domains scoring ${lo} to ${hiB}"><title>${v} domains, score ${lo}-${hiB}</title></rect>
      ${v ? `<text class="v" x="${x + 15.5}" y="${y - 4}" text-anchor="middle">${v}</text>` : ''}<text x="${x + 15.5}" y="134" text-anchor="middle">${lo}</text>`; }).join('');
  h += `<section class="card"><header><h2>Score distribution</h2></header><div class="body"><svg class="hist" viewBox="0 0 390 140" role="group" aria-label="Score distribution"><line x1="10" y1="118.5" x2="384" y2="118.5"/>${bars}</svg><p class="sub" style="margin-top:6px">Select a bar to list the domains in that range.</p></div></section>`;
  // fix first
  const risks = [...R].filter(r => r.priority > 0).sort((a, b) => b.priority - a.priority).slice(0, 6);
  h += `<section class="card"><header><h2>Fix first</h2><p>Highest priority</p></header><div class="body"><ul class="rows">${risks.map(r => {
    const top = r.issues.find(x => x.severity === 'critical') || r.issues[0];
    return `<li><button class="r-btn" data-open="${r._i}"><span class="r-main">${esc(r.domain)}</span><span class="r-val">${scoreHtml(r.overall_score)}</span>
      <span class="r-sub">${hasMeta ? esc(r.tier) + ' tier, ' : ''}${top ? esc(top.message) : ''}</span></button></li>`; }).join('') || '<li class="muted">Nothing urgent.</li>'}</ul></div></section>`;
  // top critical findings
  const crit = findingCounts().filter(([c]) => FIND[c] && FIND[c][0] === 'critical').slice(0, 6);
  h += `<section class="card"><header><h2>Most frequent critical findings</h2></header><div class="body"><ul class="rows">${crit.map(([c, k]) =>
    `<li><button class="r-btn" data-finding="${esc(c)}"><span class="r-main">${esc(findingTitle(c))}</span><span class="r-val num">${k}</span>
      <span class="r-sub">${esc(FIND[c][1])}, ${pct(k, n)}% of domains</span></button></li>`).join('') || '<li class="muted">No critical findings.</li>'}</ul></div></section>`;
  // risk by tier
  const tiers = TIER_ORDER.filter(t => R.some(r => r.tier === t));
  if (tiers.length > 1) {
    const bands = [['lo', 'Under 50', 'var(--fail)'], ['mid', '50 to 79', 'var(--warn)'], ['hi', '80+', 'var(--pass)']];
    const cnt = (t, b) => R.filter(r => r.tier === t && scoreCls(r.overall_score) === b).length;
    const mx = Math.max(1, ...tiers.flatMap(t => bands.map(b => cnt(t, b[0]))));
    h += `<section class="card"><header><h2>Risk by tier</h2><p>Domains by tier and score</p></header><div class="body"><div class="rm">
      <div class="rm-row"><span></span>${bands.map(b => `<span class="rm-head">${b[1]}</span>`).join('')}</div>
      ${tiers.map(t => `<div class="rm-row"><span class="tag tier-${t}" style="justify-self:start">${t}</span>${bands.map(b => { const v = cnt(t, b[0]);
        return `<button class="rm-cell${v ? '' : ' zero'}" style="background:color-mix(in srgb, ${b[2]} ${v ? 12 + Math.round(48 * v / mx) : 4}%, transparent)" data-tier="${t}" data-band="${b[0]}" aria-label="${v} ${t} tier domains scoring ${b[1]}">${v}</button>`; }).join('')}</div>`).join('')}
    </div></div></section>`;
  }
  // requirements
  const comp = Object.entries(COMP).map(([k, v]) => {
    const vals = R.map(r => (r.compliance || {})[k]).filter(x => x && x !== 'n/a');
    return {k, label: v[0], desc: v[1], pass: vals.filter(x => x === 'pass').length, fail: vals.filter(x => x === 'fail').length, total: vals.length};
  }).filter(c => c.total);
  if (comp.length) h += `<section class="card"><header><h2>Requirements met</h2><p>Select to list failing domains</p></header><div class="body">${comp.map(c =>
    `<button class="bar-row" data-comp="${c.k}:fail" title="${esc(c.desc)}"><span>${esc(c.label)}</span><span class="bar"><i class="b-pass" style="width:${pct(c.pass, c.total)}%"></i></span><span>${c.pass}/${c.total}</span></button>`).join('')}</div></section>`;
  // changes
  if (diff) h += `<section class="card${tiers.length > 1 ? '' : ' span2'}"><header><h2>Since the baseline</h2><p>${esc(diff.baseline_date || diff.baseline)}</p></header><div class="body"><div class="stat-strip">
      <button class="stat" data-route="changes"><b class="delta-up">${diff.improved}</b><span>improved</span></button>
      <button class="stat" data-route="changes"><b class="delta-down">${diff.worsened}</b><span>worsened</span></button>
      <button class="stat" data-route="changes"><b>${diff.new_critical}</b><span>new critical findings</span></button>
      <button class="stat" data-route="changes"><b>${diff.new_domains.length}/${diff.removed_domains.length}</b><span>domains added/removed</span></button></div></div></section>`;
  return h + '</div>';
}
/* ================= domains ================= */
const PRESETS = () => [
  ['all', 'All domains', {}],
  ['crit', 'Critical risk', {score: 'lo'}],
  ...(hasMeta && R.some(r => r.tier === 'critical') ? [['tier1', 'Critical tier', {tier: 'critical'}]] : []),
  ...(CHECKS.includes('takeover') ? [['tko', 'Takeover exposure', {f: {takeover: 'error'}}]] : []),
  ...(hasAuth ? [['bulk', 'Fails Gmail/Yahoo rules', {comp: 'gmail_yahoo:fail'}]] : []),
  ...(diff ? [['chg', 'Changed', {changed: '1'}]] : [])
];
function domains() {
  const all = list();
  const pages = Math.max(1, Math.ceil(all.length / P.size));
  if (S.page > pages) S.page = pages;
  const items = all.slice((S.page - 1) * P.size, S.page * P.size);
  const active = chips();
  const presetCounts = PRESETS().map(p => { const saved = {}; FKEYS.forEach(k => saved[k] = S[k]); const sf = S.f;
    Object.assign(S, blank(), p[2]); const c = R.filter(matches).length; Object.assign(S, saved); S.f = sf; return c; });
  let h = `<div class="presets" role="group" aria-label="Saved views">${PRESETS().map((p, k) =>
    `<button class="preset" data-preset="${k}" aria-pressed="${presetActive(p)}">${esc(p[1])}<span class="n">${presetCounts[k]}</span></button>`).join('')}</div>
  <div class="toolbar">
    <div class="search-box">${icon('search')}<input type="search" id="q" placeholder="Filter by domain, owner, unit or tag" value="${esc(S.q)}" aria-label="Filter domains"></div>
    <button class="btn" data-action="filters" aria-expanded="${S.filtersOpen}">${icon('filter')}Filters${active.length ? `<span class="badge-n">${active.length}</span>` : ''}</button>
    <span class="spacer"></span>
    <div class="seg" role="group" aria-label="Layout"><button data-view="table" aria-pressed="${P.view === 'table'}">Table</button><button data-view="heatmap" aria-pressed="${P.view === 'heatmap'}">Heatmap</button></div>
    ${P.view === 'table' ? `<div class="seg" role="group" aria-label="Density"><button data-density="comfortable" aria-pressed="${P.density === 'comfortable'}">Comfortable</button><button data-density="compact" aria-pressed="${P.density === 'compact'}">Compact</button></div>
    <div class="menu"><button class="btn" data-menu="cols" aria-expanded="${S.menu === 'cols'}">${icon('columns')}Columns</button>${S.menu === 'cols' ? `<div class="menu-pop">${COLS().map(c =>
      `<label class="check"><input type="checkbox" data-col="${c.id}"${P.hidden.includes(c.id) ? '' : ' checked'}> ${esc(c.label)}</label>`).join('')}<div class="sep"></div><button class="mi" data-action="cols-reset">Show all columns</button></div>` : ''}</div>` : ''}
    <div class="menu"><button class="btn" data-menu="export" aria-expanded="${S.menu === 'export'}">${icon('download')}Export</button>${S.menu === 'export' ? `<div class="menu-pop">
      <button class="mi" data-action="csv">Filtered domains as CSV<small>${all.length}</small></button>
      <button class="mi" data-action="json">Filtered domains as JSON<small>${all.length}</small></button>
      ${S.sel.size ? `<div class="sep"></div><button class="mi" data-action="csv-sel">Selected domains as CSV<small>${S.sel.size}</small></button>` : ''}
      <div class="sep"></div><button class="mi" data-action="copy-list">Copy domain list</button><button class="mi" data-action="copy-link">Copy link to this view</button></div>` : ''}</div>
  </div>`;
  if (S.filtersOpen) h += filterPanel();
  h += `<div class="chips">${active.length ? active.map(([k, lbl]) => `<span class="chip">${esc(lbl)}<button data-chip="${esc(k)}" aria-label="Remove filter ${esc(lbl)}">${icon('x', 12)}</button></span>`).join('') + '<button class="link" data-action="clear">Clear all</button>' : `<span>${all.length} domains</span>`}</div>`;
  if (S.sel.size) h += `<div class="selbar"><b>${S.sel.size} selected</b><button class="btn small" data-action="csv-sel">Export CSV</button><button class="btn small" data-action="copy-sel">Copy domains</button><span class="spacer"></span><button class="link" data-action="sel-clear">Clear selection</button></div>`;
  if (!all.length) h += `<div class="grid-wrap"><div class="empty"><b>No domain matches these filters</b><button class="btn" data-action="clear">Clear filters</button></div></div>`;
  else h += `<div class="grid-wrap" id="grid">${P.view === 'heatmap' ? heatmap(items) : table(items)}</div>`;
  return h + pager(all.length, pages);
}
function table(items) {
  const cols = visibleCols();
  const allSel = items.length && items.every(r => S.sel.has(r._i));
  const cur = S.sort.k === 'domain' ? (S.sort.d > 0 ? 'ascending' : 'descending') : 'none';
  return `<table class="grid${P.density === 'compact' ? ' compact' : ''}"><thead><tr>
    <th class="sticky" aria-sort="${cur}"><div class="cell-domain"><input type="checkbox" data-selall aria-label="Select all on this page"${allSel ? ' checked' : ''}><button class="sort" data-sort="domain">Domain</button></div></th>
    ${cols.map(th).join('')}</tr></thead><tbody>${items.map((r, k) => `<tr data-row="${r._i}" class="${k === S.cursor ? 'cursor ' : ''}${S.open === r._i ? 'active' : ''}">
      <td class="sticky"><div class="cell-domain"><input type="checkbox" data-sel="${r._i}" aria-label="Select ${esc(r.domain)}"${S.sel.has(r._i) ? ' checked' : ''}>
        <div><button class="dom" data-open="${r._i}">${esc(r.domain)}</button>${(r.owner || r.bu) && P.density !== 'compact' ? `<div class="dom-sub">${esc([r.owner, r.bu].filter(Boolean).join(', '))}</div>` : ''}</div></div></td>
      ${cols.map(c => `<td class="${c.cls || ''}">${c.cell(r)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}
function heatmap(items) {
  return `<div class="heat" style="--cols:${CHECKS.length}" role="table" aria-label="Security heatmap">
    <div class="heat-row heat-head" role="row"><div role="columnheader">Domain</div>${CHECKS.map(c => `<div role="columnheader" title="${esc(L[c])}">${esc(SHORT[c] || L[c])}</div>`).join('')}<div role="columnheader" style="text-align:right">Score</div></div>
    ${items.map(r => `<div class="heat-row" role="row"><button class="dom" role="rowheader" data-open="${r._i}" title="${esc(r.domain)}">${esc(r.domain)}</button>
      ${CHECKS.map(c => { const s = r._st(c), m = st(s), det = DETAIL[c] ? DETAIL[c](r) : '';
        const lbl = `${r.domain}, ${L[c]}: ${m[2]}${det ? ', ' + det : ''}`;
        return `<button class="cell c-${m[0]}" role="cell" data-open="${r._i}" data-dtab="${tabFor(c)}" title="${esc(lbl)}" aria-label="${esc(lbl)}">${m[1]}</button>`; }).join('')}
      <span class="score ${scoreCls(r.overall_score)}" role="cell">${r.overall_score}</span></div>`).join('')}</div>`;
}
/* ================= findings ================= */
/* ================= changes, groups, lookalikes, reports ================= */
function groups() {
  const keyFn = {owner: r => [r.owner || '(no owner)'], bu: r => [r.bu || '(no unit)'], tier: r => [r.tier], tag: r => (r.tags && r.tags.length ? r.tags : ['(no tag)'])}[S.groupBy];
  const g = {};
  R.forEach(r => keyFn(r).forEach(k => (g[k] = g[k] || []).push(r)));
  const rows = Object.entries(g).map(([k, rs]) => ({k, rs, avg: rs.reduce((a, r) => a + r.overall_score, 0) / rs.length,
    crit: rs.reduce((a, r) => a + r._crit, 0), worst: rs.reduce((w, r) => r.overall_score < w.overall_score ? r : w, rs[0])})).sort((a, b) => a.avg - b.avg);
  return `<div class="toolbar"><div class="seg" role="group" aria-label="Group by">${[['owner', 'Owner'], ['bu', 'Business unit'], ['tier', 'Tier'], ['tag', 'Tag']].map(([v, l]) =>
      `<button data-groupby="${v}" aria-pressed="${S.groupBy === v}">${l}</button>`).join('')}</div></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Group</th><th class="r">Domains</th><th>Average score</th><th class="r">Critical findings</th><th>Weakest domain</th></tr></thead><tbody>
    ${rows.map(x => `<tr><td class="sticky"><button class="dom" data-group="${S.groupBy}" data-value="${esc(x.k.startsWith('(') ? '' : x.k)}">${esc(x.k)}</button></td><td class="r num">${x.rs.length}</td>
      <td><div class="scorecell" style="justify-content:flex-start">${scoreHtml(Math.round(x.avg))}<span class="mini" style="width:120px"><i class="${scoreCls(x.avg)}" style="width:${x.avg}%"></i></span></div></td>
      <td class="r num">${x.crit}</td><td><button class="link" data-open="${x.worst._i}">${esc(x.worst.domain)}</button> ${scoreHtml(x.worst.overall_score)}</td></tr>`).join('')}</tbody></table></div>`;
}
function lookRows() {
  const seen = new Set(), rows = [];
  R.forEach(r => (r.lookalikes.registered || []).forEach(e => { const k = r.lookalikes.base + '|' + e.domain; if (!seen.has(k)) { seen.add(k); rows.push({r, e}); } }));
  return rows.sort((a, b) => (b.e.mx - a.e.mx) || String(b.e.created || '').localeCompare(String(a.e.created || '')));
}
function lookalikes() {
  const rows = lookRows().filter(x => !S.lmx || x.e.mx);
  return `<div class="toolbar"><label class="check"><input type="checkbox" data-lmx${S.lmx ? ' checked' : ''}> Only domains with mail servers</label></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Lookalike</th><th>Imitates</th><th>Technique</th><th>Mail servers</th><th>Website</th><th>Registered</th></tr></thead><tbody>
    ${rows.map(({r, e}) => `<tr data-row="${r._i}"><td class="sticky mono">${esc(e.domain)}</td><td><button class="link" data-open="${r._i}" data-dtab="exposure">${esc(r.lookalikes.base)}</button></td>
      <td>${esc(e.kind)}</td><td>${e.mx ? pill('error', 'MX') : '<span class="faint">No</span>'}</td><td>${e.a ? 'Yes' : '<span class="faint">No</span>'}</td>
      <td class="nowrap">${esc((e.created || '').slice(0, 10)) || '<span class="faint">unknown</span>'}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No registered lookalikes found.</td></tr>'}</tbody></table></div>`;
}
function reports() {
  const rows = R.filter(r => r.dmarc_reports.status !== 'missing').sort((a, b) => a.dmarc_reports.pass_rate - b.dmarc_reports.pass_rate);
  const un = D.unscanned_report_domains || [];
  return `<div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Domain</th><th class="r">Messages</th><th>Pass rate</th><th class="r">Not aligned</th><th class="r">Unauthenticated</th><th>Verdict</th></tr></thead><tbody>
    ${rows.map(r => { const x = r.dmarc_reports;
      return `<tr data-row="${r._i}"><td class="sticky"><button class="dom" data-open="${r._i}" data-dtab="reports">${esc(r.domain)}</button><div class="dom-sub">${esc(x.period.filter(Boolean).join(' to '))}</div></td>
        <td class="r num">${x.messages}</td><td><div class="scorecell" style="justify-content:flex-start"><span class="num">${x.pass_rate}%</span><span class="mini" style="width:80px"><i class="${x.pass_rate >= 98 ? 'hi' : x.pass_rate >= 90 ? 'mid' : 'lo'}" style="width:${x.pass_rate}%"></i></span></div></td>
        <td class="r num">${x.unaligned}</td><td class="r num">${x.spoofed}</td><td>${esc(x.verdict)}</td></tr>`; }).join('') || '<tr><td colspan="6" class="empty">No report matches the scanned domains.</td></tr>'}</tbody></table></div>
    ${un.length ? `<p class="muted" style="margin-top:12px">Seen in reports but not scanned: <span class="mono">${un.map(esc).join(', ')}</span></p>` : ''}`;
}

/* ================= domain drawer ================= */
const EVIDENCE = ['mx', 'spf', 'dkim', 'dmarc', 'mta-sts', 'tls-rpt', 'bimi', 'dnssec', 'caa'], EXPOSURE = ['takeover', 'axfr', 'consistency', 'lookalikes'];
const tabFor = c => EXPOSURE.includes(c) ? 'exposure' : 'evidence';
const DTABS = [
  {id: 'overview', label: 'Summary', show: () => true},
  {id: 'findings', label: 'Findings', show: () => true, n: r => r.issues.length},
  {id: 'fixes', label: 'Fixes', show: r => (r.remediation || []).length > 0, n: r => r.remediation.length},
  {id: 'evidence', label: 'DNS evidence', show: r => EVIDENCE.some(c => vis(r, c))},
  {id: 'exposure', label: 'Exposure', show: r => EXPOSURE.some(c => vis(r, c))},
  {id: 'reports', label: 'DMARC reports', show: r => r.dmarc_reports.status !== 'missing'}
];
function tabOverview(r) {
  const b = r.score_breakdown || {}, comps = Object.entries(b.components || {});
  const comp = Object.entries(r.compliance || {}).filter(([, v]) => v !== 'n/a');
  let h = `<div class="dr-cols">${sec('score', 'How the score is built', `${comps.map(([c, v]) => `<div class="bar-row"><span>${esc(L[c])}</span>
      <span class="bar"><i class="b-${v.got >= v.max ? 'pass' : v.got > 0 ? 'warn' : 'fail'}" style="width:${pct(v.got, v.max)}%"></i></span><span>${v.got}/${v.max}</span></div>`).join('')}
      ${b.normalized ? `<p class="sub" style="margin-top:8px">Normalized to 100 over the selected checks (${b.max} points available).</p>` : ''}
      ${b.cap ? `<p class="note-box" style="margin-top:10px">${esc(b.cap)}</p>` : ''}${b.note ? `<p class="sub">${esc(b.note)}</p>` : ''}`)}
    ${sec('compliance', 'Requirements', comp.length ? comp.map(([k, v]) => `<div class="bar-row" style="grid-template-columns:1fr auto" title="${esc(COMP[k][1])}"><span>${esc(COMP[k][0])}</span>${pill({pass: 'valid', fail: 'error', unknown: 'unknown'}[v] || 'na', v === 'unknown' ? '' : '')}</div>`).join('')
      + '<p class="sub" style="margin-top:8px">Only what DNS can show. Alignment, PTR, spam rate and unsubscribe headers need message-level checks.</p>' : '<p class="muted">Not applicable to the selected checks.</p>')}</div>`;
  h += sec('controls', 'Controls', `<div class="ctl-grid">${CHECKS.filter(c => vis(r, c)).map(c => `<button class="ctl" data-dtab="${tabFor(c)}" data-anchor="${c}"><span>${esc(L[c])}</span>${pill(r._st(c), DETAIL[c] ? DETAIL[c](r) : '')}</button>`).join('')}</div>`);
  if (r.change && r.change.changed) {
    const c = r.change;
    h += sec('changes', 'Since the baseline', c.new ? '<p>New domain in this scan.</p>' : `${c.previous_score === null || c.previous_score === undefined ? '' : `<p>Score <span class="num">${esc(c.previous_score)}</span> to ${scoreHtml(r.overall_score)} ${deltaHtml(r)}</p>`}
      ${c.status_changes.map(s => `<div style="margin-top:6px">${esc(L[s.check] || s.check)} ${pill(s.from)} ${pill(s.to)}</div>`).join('')}
      ${c.new_issues.length ? `<p style="margin-top:10px"><b>New:</b> ${c.new_issues.map(x => esc(findingTitle(x))).join(', ')}</p>` : ''}
      ${c.resolved_issues.length ? `<p style="margin-top:6px"><b>Resolved:</b> ${c.resolved_issues.map(x => esc(findingTitle(x))).join(', ')}</p>` : ''}`);
  }
  const top = r.issues.filter(i => i.severity !== 'info').slice(0, 4);
  h += sec('top', 'Most important findings', top.length ? issueList(top) : '<p class="muted">No critical or warning findings.</p>',
    r.issues.length > top.length ? `<button class="link" data-dtab="findings">All ${r.issues.length} findings</button>` : '');
  return h;
}
function tabFindings(r) {
  if (!r.issues.length) return sec('issues', 'Findings', '<p class="muted">No findings. The configuration matches every selected check.</p>');
  return ['critical', 'warning', 'info'].map(s => { const xs = r.issues.filter(i => i.severity === s);
    return xs.length ? sec('issues-' + s, `${s[0].toUpperCase() + s.slice(1)} (${xs.length})`, issueList(xs)) : ''; }).join('');
}
function tabFixes(r) {
  return sec('fixes', 'Suggested fixes', `<p class="sub" style="margin-bottom:12px">Review every value before publishing: these records are generated from the current configuration.</p>` +
    r.remediation.map((x, k) => `<div class="fix"><h4>${esc(x.title)}</h4>${x.name ? `<div class="where">${esc(x.type)} record at <span class="mono">${esc(x.name)}</span></div>` : ''}
      ${x.value ? `<div class="rowx"><pre class="record" id="fix-${r._i}-${k}">${esc(x.value)}</pre><button class="btn small copy" data-copy="fix-${r._i}-${k}">${icon('copy', 14)}Copy</button></div>` : ''}
      ${x.note ? `<p class="note">${esc(x.note)}</p>` : ''}</div>`).join(''));
}
function tabEvidence(r) {
  let h = '';
  if (vis(r, 'mx')) h += sec('mx', 'Mail servers (MX)', r.mx.records.length ? `<table><thead><tr><th>Priority</th><th>Host</th><th>Protection</th></tr></thead><tbody>
      ${r.mx.records.map(m => `<tr><td class="num">${m.priority}</td><td class="mono">${esc(m.host || '.')}${m.resolves === false ? ' ' + pill('error', 'does not resolve') : ''}${m.is_cname ? ' ' + pill('warning', 'CNAME') : ''}</td>
        <td>${r.mx.null_mx ? pill('null') : m.is_protected ? `<span class="pill s-pass">${esc(m.provider)}</span>` : '<span class="faint">Unprotected</span>'}</td></tr>`).join('')}</tbody></table>`
    : `<p class="muted">${r.mx.implicit ? 'No MX records: mail falls back to the A/AAAA record.' : 'No MX records.'}</p>`, pill(r._st('mx')));
  if (vis(r, 'spf')) h += sec('spf', 'SPF', `${r.spf.record ? `<pre class="record">${esc(r.spf.record)}</pre>` : '<p class="muted" style="margin-bottom:10px">No SPF record.</p>'}
      <div class="kv">${kv('DNS lookups', `${r.spf.lookups}/10`, r.spf.lookups > 10 ? 'score lo' : '')}${kv('Void lookups', `${r.spf.void_lookups}/2`)}${kv('Ends with', r.spf.mechanism)}${kv('PermError', r.spf.permerror ? 'Yes' : 'No', r.spf.permerror ? 'score lo' : '')}</div>
      ${r.spf.include_tree.length ? `<details class="more"><summary>Include tree (${r.spf.include_tree.length})</summary><div class="tree">${r.spf.include_tree.map(nd =>
        `<div style="padding-left:${nd.depth * 16}px">${esc(nd.domain)} <span class="faint">${nd.lookups} nested${nd.status !== 'ok' ? ', ' + esc(nd.status) : ''}</span></div>`).join('')}</div></details>` : ''}`, pill(r._st('spf')));
  if (vis(r, 'dkim')) h += sec('dkim', 'DKIM', r.dkim.selectors.length ? `<table><thead><tr><th>Selector</th><th>Key</th><th>Status</th></tr></thead><tbody>
      ${r.dkim.selectors.map(s => `<tr><td class="mono">${esc(s.name)}${s.source === 'report' ? ' <span class="tag">from reports</span>' : s.source === 'declared' ? ' <span class="tag">from dkim.csv</span>' : ''}${s.cname ? `<div class="sub">CNAME ${esc(s.cname)}</div>` : ''}</td>
        <td class="nowrap">${esc(s.algorithm || '')} ${s.key_size ? s.key_size + ' bit' : ''}${s.testing ? ' <span class="tag">t=y</span>' : ''}${s.hash_algorithms ? ` <span class="tag">h=${esc(s.hash_algorithms)}</span>` : ''}</td>
        <td>${pill({valid: 'valid', weak: 'warning', revoked: 'missing', invalid: 'error'}[s.status] || 'missing', s.status)}</td></tr>`).join('')}
      ${(r.dkim.declared || []).filter(n => !r.dkim.selectors.some(s => s.name === n)).map(n => `<tr><td class="mono">${esc(n)} <span class="tag">from dkim.csv</span></td><td class="faint">not published</td><td>${pill('missing')}</td></tr>`).join('')}</tbody></table>
      ${r.dkim.stopped_early ? `<p class="sub" style="margin-top:8px">Search stopped after ${r.dkim.probed} selectors: a valid key was found. Run with --full-dkim to probe every known selector.</p>` : ''}`
    : `<p class="muted">${r.dkim.status === 'na' ? 'Not needed: the domain does not handle mail.' : `${r.dkim.mode === 'dkim.csv' ? ((r.dkim.declared || []).length ? `The records listed in dkim.csv (${esc(r.dkim.declared.join(', '))}) are not published in DNS.` : 'No DKIM record listed in dkim.csv for this domain: DKIM is not verified and not counted in the score.') : `No key found on ${r.dkim.probed} probed selectors. List the DKIM records each domain uses in dkim.csv, next to the domain list, or load DMARC reports to discover them.`}`}</p>`, pill(r._st('dkim')));
  if (vis(r, 'dmarc')) h += sec('dmarc', 'DMARC', `${r.dmarc.record ? `<pre class="record">${esc(r.dmarc.record)}</pre>` : '<p class="muted" style="margin-bottom:10px">No DMARC record.</p>'}
      ${r.dmarc.inherited_from ? `<p class="sub" style="margin-bottom:10px">Inherited from ${esc(r.dmarc.inherited_from)}</p>` : ''}
      <div class="kv">${kv('Policy', r.dmarc.policy)}${kv('Subdomains', r.dmarc.subdomain_policy)}${kv('Applied to', r.dmarc.pct + '%')}${kv('Alignment', `SPF ${r.dmarc.aspf}, DKIM ${r.dmarc.adkim}`)}
      ${kv('Aggregate reports', r.dmarc.rua_destinations.join(', '))}${kv('Failure reports', r.dmarc.ruf)}</div>`, pill(r._st('dmarc')));
  const tr = [];
  if (vis(r, 'mta-sts')) tr.push(kv('MTA-STS', r.mta_sts.mode ? `${st(r.mta_sts.status)[2]}, mode ${r.mta_sts.mode}` : st(r.mta_sts.status)[2]),
    kv('Policy MX', r.mta_sts.mx_patterns.join(', ')), kv('Policy max_age', r.mta_sts.max_age), kv('Policy problem', r.mta_sts.policy_error));
  if (vis(r, 'tls-rpt')) tr.push(kv('TLS-RPT', r.tls_rpt.rua || st(r.tls_rpt.status)[2]));
  if (vis(r, 'bimi')) tr.push(kv('BIMI logo', r.bimi.logo_url || st(r.bimi.status)[2]));
  if (vis(r, 'dnssec')) tr.push(kv('DNSSEC', st(r.dnssec.status)[2]));
  if (tr.length) h += sec('mta-sts', 'Transport and DNS security', `<div class="kv">${tr.join('')}</div>`);
  if (vis(r, 'caa')) { const c = r.caa;
    h += sec('caa', 'Certificate authorities (CAA)', c.records.length ? `<table><thead><tr><th>Flags</th><th>Tag</th><th>Value</th></tr></thead><tbody>
      ${c.records.map(x => `<tr><td class="num">${esc(x.flags)}</td><td class="mono">${esc(x.tag)}</td><td class="mono">${esc(x.value)}</td></tr>`).join('')}</tbody></table>
      <div class="kv" style="margin-top:12px">${kv('May issue', c.issuers[0] === ';' ? 'No CA (issuance forbidden)' : c.issuers.join(', '))}${kv('Wildcards', c.wildcard_issuers ? (c.wildcard_issuers[0] === ';' ? 'Forbidden' : c.wildcard_issuers.join(', ')) : 'Same as above')}
      ${kv('Violations reported to', c.iodef.join(', '))}${c.inherited_from ? kv('Inherited from', c.inherited_from) : ''}</div>`
      : `<p class="muted">${c.status === 'dns_error' ? 'The CAA lookup failed: certificate authorities may refuse to issue.' : 'No CAA record: every public certificate authority may issue certificates for this domain.'}</p>`, pill(r._st('caa'))); }
  return h;
}
function tabExposure(r) {
  let h = '';
  if (vis(r, 'takeover')) { const t = r.takeover;
    h += sec('takeover', 'External dependencies', `<p class="sub" style="margin-bottom:12px">Domains this one relies on. If one lapses, whoever registers it can pass SPF, receive mail or reports, or take over the zone.${t.rdap ? '' : ' Registration dates unavailable: RDAP was off.'}</p>
      ${t.dependencies.length ? `<table><thead><tr><th>Domain</th><th>Used by</th><th>State</th><th>Expires</th></tr></thead><tbody>${t.dependencies.map(e => `<tr><td class="mono">${esc(e.domain)}</td><td class="sub">${esc(e.used_by.join(', '))}</td>
        <td>${pill({ok: 'valid', unregistered: 'error', expired: 'error', expiring: 'warning', 'no-dns': 'warning', unknown: 'unknown'}[e.state] || 'unknown', e.state === 'ok' ? '' : e.state)}</td><td class="nowrap num">${esc((e.expires || '').slice(0, 10))}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No external dependencies found.</p>'}
      ${t.dangling.length ? `<p style="margin-top:14px"><b>Dangling CNAMEs</b></p>${t.dangling.map(d => `<div class="mono" style="margin-top:4px">${esc(d.name)} \u2192 ${esc(d.target)}</div>`).join('')}` : ''}
      <div class="kv" style="margin-top:14px">${kv('Name servers', t.ns_hosts.join(', '))}${kv('Domain expires', (t.domain_expires || '').slice(0, 10))}</div>`, pill(r._st('takeover'))); }
  if (vis(r, 'axfr')) { const x = r.axfr;
    h += sec('axfr', 'Zone transfer (AXFR)', `<p class="sub" style="margin-bottom:12px">Each authoritative name server was asked for a full copy of the zone. Only the first answer is read: the zone is not downloaded.</p>
      ${x.servers.length ? `<table><thead><tr><th>Name server</th><th>Address</th><th>Result</th></tr></thead><tbody>${x.servers.map(s => `<tr><td class="mono">${esc(s.ns)}</td><td class="mono">${esc(s.ip || '')}</td>
        <td>${pill({refused: 'valid', open: 'error', unreachable: 'unknown'}[s.result] || 'unknown', s.result === 'open' ? `open, ${s.records} records in the first message` : s.result)}</td></tr>`).join('')}</tbody></table>`
      : '<p class="muted">No name server could be tested.</p>'}`, pill(r._st('axfr'))); }
  if (vis(r, 'consistency')) { const c = r.consistency;
    h += sec('consistency', 'Resolver and authoritative consistency', c.differences.length ? c.differences.map(d => `<p><b>${esc(d.type)} ${esc(d.name)}</b> <span class="sub">${d.kind === 'authoritative' ? 'authoritative servers disagree' : 'resolvers differ from the authoritative answer'}</span></p>
      <table style="margin:6px 0 14px"><tbody>${Object.entries(d.answers).map(([s, v]) => `<tr><td class="nowrap sub">${esc(s)}</td><td class="mono">${v.length ? v.map(esc).join('<br>') : '<span class="faint">no data</span>'}</td></tr>`).join('')}</tbody></table>`).join('')
      : `<p class="muted">${c.status === 'unknown' ? 'Authoritative servers could not be queried.' : 'All sources return the same data.'}</p><p class="sub" style="margin-top:6px">Sources: ${esc(c.sources.join(', '))}</p>`, pill(r._st('consistency'))); }
  if (vis(r, 'lookalikes')) { const lk = r.lookalikes;
    h += sec('lookalikes', 'Lookalike domains', lk.status === 'na' ? '<p class="muted">Not checked for this tier.</p>' : `<p class="sub" style="margin-bottom:10px">${lk.generated} variants of ${esc(lk.base)} checked, ${lk.registered.length} registered.</p>
      ${lk.registered.length ? `<table><thead><tr><th>Domain</th><th>Technique</th><th>MX</th><th>Registered</th></tr></thead><tbody>${lk.registered.map(e => `<tr><td class="mono">${esc(e.domain)}</td><td>${esc(e.kind)}</td><td>${e.mx ? pill('error', 'yes') : '<span class="faint">No</span>'}</td><td class="num">${esc((e.created || '').slice(0, 10))}</td></tr>`).join('')}</tbody></table>` : ''}`, pill(r._st('lookalikes'))); }
  return h;
}
function tabReports(r) {
  const x = r.dmarc_reports;
  return sec('reports', 'DMARC aggregate reports', `<p class="note-box" style="margin-bottom:14px">${esc(x.verdict)}</p>
    <div class="kv">${kv('Period', x.period.filter(Boolean).join(' to '))}${kv('Reports', x.reports)}${kv('Messages', x.messages)}${kv('Pass rate', x.pass_rate + '%')}${kv('Not aligned', x.unaligned)}${kv('Unauthenticated', x.spoofed)}${kv('Selectors seen', x.selectors.join(', '))}${kv('Reporters', x.reporters.join(', '))}</div>
    ${x.sources.length ? `<table style="margin-top:16px"><thead><tr><th>Source</th><th class="r">Messages</th><th>Result</th><th>Envelope or DKIM domains</th></tr></thead><tbody>${x.sources.slice(0, 30).map(s => `<tr>
      <td class="mono">${esc(s.ip)}${s.ptr ? `<div class="sub">${esc(s.ptr)}</div>` : ''}</td><td class="r num">${s.count}</td>
      <td>${pill({aligned: 'valid', unaligned: 'warning', spoof: 'error'}[s.category], {aligned: 'passes', unaligned: 'not aligned', spoof: 'unauthenticated'}[s.category])}</td>
      <td class="sub">${esc([...s.envelope_from, ...s.dkim_domains].join(', '))}</td></tr>`).join('')}</tbody></table>` : ''}`);
}
const TAB_RENDER = {overview: tabOverview, findings: tabFindings, fixes: tabFixes, evidence: tabEvidence, exposure: tabExposure, reports: tabReports};
let lastOpen = null, lastAnchor = null;
function drawer() {
  const root = $('#drawer-root');
  if (S.open === null) {
    if (lastOpen !== null) { root.innerHTML = ''; document.body.classList.remove('locked');
      const back = document.querySelector(`[data-open="${lastOpen}"]`); if (back) back.focus({preventScroll: true}); }
    lastOpen = null; return;
  }
  const r = R[S.open], lst = list(), pos = lst.findIndex(x => x._i === r._i);
  const prev = pos > 0 ? lst[pos - 1]._i : null, next = pos >= 0 && pos < lst.length - 1 ? lst[pos + 1]._i : null;
  const tabs = DTABS.filter(t => t.show(r));
  if (S.dtab !== 'all' && !tabs.some(t => t.id === S.dtab)) S.dtab = 'overview';
  const badges = [r.profile !== 'mail' ? {'non-mail': 'Does not handle mail', nonexistent: 'Domain does not exist', unreachable: 'DNS unreachable'}[r.profile] : ''].filter(Boolean);
  const body = S.dtab === 'all' ? tabs.map(t => `<h2 class="dr-print-title">${esc(t.label)}</h2>` + TAB_RENDER[t.id](r)).join('') : TAB_RENDER[S.dtab](r);
  const fresh = lastOpen === null;
  root.innerHTML = `<div class="scrim${fresh ? ' enter' : ''}" data-action="close"></div>
    <aside class="drawer${fresh ? ' enter' : ''}" role="dialog" aria-modal="true" aria-labelledby="dr-title">
      <header class="dr-head">
        <div class="dr-nav"><button class="btn icon ghost" data-open="${prev}" ${prev === null ? 'disabled' : ''} aria-label="Previous domain" title="Previous (k)">${icon('left')}</button>
          <button class="btn icon ghost" data-open="${next}" ${next === null ? 'disabled' : ''} aria-label="Next domain" title="Next (j)">${icon('right')}</button>
          <span>${pos >= 0 ? `${pos + 1} of ${lst.length}` : ''}</span><span class="spacer"></span>
          <button class="btn ghost small" data-action="copy-link">${icon('link', 14)}Copy link</button>
          <button class="btn ghost small" data-action="print-domain">${icon('print', 14)}Print</button>
          <button class="btn icon ghost" data-action="close" id="dr-close" aria-label="Close" title="Close (Esc)">${icon('x')}</button></div>
        <div class="dr-id">${ring(r.overall_score)}<div style="min-width:0"><h2 id="dr-title">${esc(r.domain)}</h2>
          <div class="meta">${hasMeta ? tierTag(r.tier) : ''}${badges.map(b => `<span class="tag">${esc(b)}</span>`).join('')}${r.owner ? `<span class="tag">Owner ${esc(r.owner)}</span>` : ''}${r.bu ? `<span class="tag">${esc(r.bu)}</span>` : ''}
            ${(r.tags || []).map(t => `<span class="tag">#${esc(t)}</span>`).join('')}<span class="t">Grade ${gradeOf(r.overall_score)}, priority ${r.priority}, scanned ${esc(r.scan_date)}</span></div>
          ${r.error ? `<p class="note-box" style="margin-top:8px">Analysis error: ${esc(r.error)}</p>` : ''}</div></div>
        <nav class="dr-tabs" role="tablist">${tabs.map(t => `<button role="tab" data-dtab="${t.id}" aria-selected="${S.dtab === t.id}">${esc(t.label)}${t.n ? `<span class="n">${t.n(r)}</span>` : ''}</button>`).join('')}</nav>
      </header>
      <div class="dr-body" id="dr-body">${body}</div></aside>`;
  document.body.classList.add('locked');
  if (fresh) { const c = $('#dr-close'); if (c) c.focus({preventScroll: true}); }
  if (lastAnchor) { const el = document.getElementById('sec-' + lastAnchor); if (el) el.scrollIntoView({block: 'start'}); lastAnchor = null; }
  lastOpen = S.open;
}

/* ================= overlays: command palette, dialogs ================= */
let pal = null;
function paletteItems(q) {
  q = q.trim().toLowerCase();
  const items = [];
  ROUTES.filter(x => x.show()).forEach(x => { if (!q || x.label.toLowerCase().includes(q)) items.push({g: 'Go to', t: x.label, h: '', run: () => go({route: x.id, open: null})}); });
  const doms = (q ? R.filter(r => r.domain.includes(q) || (r.owner || '').toLowerCase().includes(q)) : [...R].sort((a, b) => b.priority - a.priority)).slice(0, q ? 8 : 5);
  doms.forEach(r => items.push({g: 'Domains', t: r.domain, h: `score ${r.overall_score}`, run: () => go({open: r._i, dtab: 'overview'})}));
  findingCounts().filter(([c]) => q && findingTitle(c).toLowerCase().includes(q)).slice(0, 6).forEach(([c, k]) =>
    items.push({g: 'Findings', t: findingTitle(c), h: `${k} domains`, run: () => filterTo({finding: c})}));
  [...themeActions(), ['Executive summary as PDF', printExec], ['Export filtered domains as CSV', () => exportCsv(list())],
   ['Clear all filters', () => filterTo({})], ['Copy link to this view', copyLink], ['Keyboard shortcuts', showKeys], ['About this scan', showAbout]]
    .forEach(([t, fn]) => { if (!q || t.toLowerCase().includes(q)) items.push({g: 'Actions', t, h: '', run: fn}); });
  return items;
}
function openPalette() {
  pal = {q: '', idx: 0, items: paletteItems('')};
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-label="Command palette">
    <div class="pal-input">${icon('search', 18)}<input id="pal-q" placeholder="Search domains, findings and actions" autocomplete="off" role="combobox" aria-expanded="true" aria-controls="pal-list"><span class="kbd">Esc</span></div>
    <ul class="pal-list" id="pal-list" role="listbox"></ul>
    <div class="pal-foot"><span><span class="kbd">\u2191</span> <span class="kbd">\u2193</span> move</span><span><span class="kbd">Enter</span> open</span><span><span class="kbd">Esc</span> close</span></div></div></div>`;
  renderPalette();
  $('#pal-q').focus();
}
function showKeys() {
  const k = [['Ctrl K or /', 'Search domains, findings and actions'], ['1 to 7', 'Switch section'], ['j / k', 'Next or previous domain (list and detail)'],
    ['Enter', 'Open the highlighted domain'], ['x', 'Select the highlighted domain'], ['f', 'Show or hide filters'], ['Esc', 'Close the detail or dialog'], ['?', 'This help']];
  dialog('Keyboard shortcuts', `<table class="keys">${k.map(([a, b]) => `<tr><td><span class="kbd">${esc(a)}</span></td><td>${esc(b)}</td></tr>`).join('')}</table>`);
}
function showAbout() {
  const w = D.weights || {};
  dialog('About this scan', `<div class="kv" style="margin-bottom:16px">${kv('Generated', M.generated)}${kv('Tool', TOOL + ' ' + (M.version || ''))}${kv('Domains', R.length)}${kv('Resolvers', M.resolver)}</div>
    <p style="margin-bottom:6px"><b>Checks</b></p><p class="muted" style="margin-bottom:14px">${CHECKS.map(c => esc(L[c]) + (w[c] ? ` (${w[c]} pts)` : '')).join(', ')}</p>
    <p style="margin-bottom:6px"><b>Notes</b></p><ul style="margin:0;padding-left:18px;color:var(--muted)">${(M.notes || []).map(n => `<li style="margin-bottom:4px">${esc(n)}</li>`).join('')}</ul>`);
}

/* ================= actions ================= */
const csvCell = v => { let s = String(v === null || v === undefined ? '' : v); if (/^[=+\-@\t\r|%]/.test(s)) s = "'" + s; return /[";\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
function exportCsv(rows, name) {
  const head = ['domain', 'score', 'priority', 'tier', 'owner', 'bu', 'tags', ...CHECKS.map(c => L[c]), 'critical', 'warning', 'issue_codes'];
  const body = rows.map(r => [r.domain, r.overall_score, r.priority, r.tier, r.owner, r.bu, (r.tags || []).join('|'), ...CHECKS.map(c => r._st(c)), r._crit, r._warn, [...r._codes].join('|')]);
  download(name || 'mailguard-domains.csv', 'text/csv;charset=utf-8', '\ufeff' + [head, ...body].map(x => x.map(csvCell).join(';')).join('\r\n'));
}
function exportJson(rows) {
  download('mailguard-domains.json', 'application/json', JSON.stringify(rows.map(r => { const o = {}; Object.keys(r).forEach(k => { if (k[0] !== '_') o[k] = r[k]; }); return o; }), null, 2));
}
window.addEventListener('afterprint', () => {
  document.body.classList.remove('print-exec', 'print-drawer');
  if (window.__restoreTab) { S.dtab = window.__restoreTab; window.__restoreTab = null; drawer(); }
});

/* ================= render ================= */
const VIEWS = {overview, domains, findings, changes, groups, lookalikes, reports};
function render() {
  applyTheme();
  $('#side').innerHTML = side();
  $('#topbar').innerHTML = topbar();
  const view = VIEWS[S.route] || overview;
  $('#view').innerHTML = view();
  drawer();
  const rt = ROUTES.find(x => x.id === S.route);
  document.title = (S.open !== null ? R[S.open].domain + ' - ' : '') + (rt ? rt.label + ' - ' : '') + TOOL;
}
/* ================= events ================= */
document.addEventListener('click', e => {
  const t = e.target.closest('button, [data-open], [data-smin], tr[data-row], [data-pal], [data-overlay], .scrim');
  if (S.menu && !e.target.closest('.menu')) { S.menu = null; if (!t) { render(); return; } }
  if (!t) return;
  const ds = t.dataset;
  if (ds.overlay !== undefined && e.target === t) { closeOverlay(); return; }
  if (ds.pal !== undefined) { runPalette(+ds.pal); return; }
  if (ds.open !== undefined && ds.open !== 'null') { if (ds.dtab) lastAnchor = null; go({open: +ds.open, dtab: ds.dtab || (S.open === +ds.open ? S.dtab : 'overview')}); return; }
  if (ds.smin !== undefined) { filterTo({smin: ds.smin, smax: ds.smax}); return; }
  if (ds.route) { go({route: ds.route, open: null, page: 1, cursor: -1}); $('#view').focus({preventScroll: true}); window.scrollTo(0, 0); return; }
  if (ds.check) { filterTo({f: {[ds.check]: ds.status}}); return; }
  if (ds.filter) { if (ds.filter.startsWith('c.')) filterTo({f: {[ds.filter.slice(2)]: ds.value}}); else filterTo({[ds.filter]: ds.value}); return; }
  if (ds.tier) { filterTo({tier: ds.tier, score: ds.band}); return; }
  if (ds.finding) { filterTo({finding: ds.finding}); return; }
  if (ds.comp) { filterTo({comp: ds.comp}); return; }
  if (ds.group) { filterTo({[ds.group]: ds.value}); return; }
  if (ds.preset !== undefined) { const p = PRESETS()[+ds.preset]; filterTo(JSON.parse(JSON.stringify(p[2]))); return; }
  if (ds.chip) { clearChip(ds.chip); go({page: 1, cursor: -1}, false); return; }
  if (ds.sort) { const k = ds.sort; go({sort: {k, d: S.sort.k === k ? -S.sort.d : (k === 'domain' ? 1 : -1)}, page: 1}, false); return; }
  if (ds.page) { go({page: +ds.page, cursor: -1}, false); const g = $('#grid'); if (g) g.scrollTop = 0; return; }
  if (ds.view) { P.view = ds.view; savePrefs(); render(); return; }
  if (ds.density) { P.density = ds.density; savePrefs(); render(); return; }
  if (ds.menu) { S.menu = S.menu === ds.menu ? null : ds.menu; render(); return; }
  if (ds.dtab) { if (ds.anchor) lastAnchor = ds.anchor; go({dtab: ds.dtab}, false); const b = $('#dr-body'); if (b && !lastAnchor) b.scrollTop = 0; return; }
  if (ds.fsev !== undefined) { S.fsev = ds.fsev; render(); return; }
  if (ds.groupby) { S.groupBy = ds.groupby; render(); return; }
  if (ds.copy) { const el = document.getElementById(ds.copy); if (el) copyText(el.textContent, 'Record copied'); return; }
  if (t.tagName === 'TR' && ds.row !== undefined && !e.target.closest('input, button, a')) { go({open: +ds.row, dtab: 'overview'}); return; }
  const a = ds.action;
  const acts = {
    close: () => go({open: null}), palette: openPalette, about: showAbout, keys: showKeys, theme: toggleTheme,
    'overlay-close': closeOverlay, 'print-exec': printExec, 'print-domain': printDomain, 'copy-link': () => { S.menu = null; copyLink(); render(); },
    filters: () => { S.filtersOpen = !S.filtersOpen; render(); }, clear: () => filterTo({}),
    csv: () => { S.menu = null; exportCsv(list()); render(); }, json: () => { S.menu = null; exportJson(list()); render(); },
    'csv-sel': () => { S.menu = null; exportCsv(R.filter(r => S.sel.has(r._i)), 'mailguard-selected.csv'); render(); },
    'copy-list': () => { S.menu = null; copyText(list().map(r => r.domain).join('\n'), `${list().length} domains copied`); render(); },
    'copy-sel': () => copyText(R.filter(r => S.sel.has(r._i)).map(r => r.domain).join('\n'), `${S.sel.size} domains copied`),
    'sel-clear': () => { S.sel.clear(); render(); }, 'cols-reset': () => { P.hidden = []; savePrefs(); render(); }
  };
  if (acts[a]) acts[a]();
});
document.addEventListener('change', e => {
  const t = e.target, ds = t.dataset;
  if (ds.f) { S.f[ds.f] = t.value; if (!t.value) delete S.f[ds.f]; go({page: 1, cursor: -1}, false); }
  else if (ds.sel !== undefined) { const i = +ds.sel; S.sel.has(i) ? S.sel.delete(i) : S.sel.add(i); render(); }
  else if (ds.selall !== undefined) { const items = list().slice((S.page - 1) * P.size, S.page * P.size); items.forEach(r => t.checked ? S.sel.add(r._i) : S.sel.delete(r._i)); render(); }
  else if (ds.col) { P.hidden = t.checked ? P.hidden.filter(x => x !== ds.col) : [...P.hidden, ds.col]; savePrefs(); render(); }
  else if (ds.lmx !== undefined) { S.lmx = t.checked; render(); }
  else if (ds.k === 'size') { P.size = +t.value; savePrefs(); go({page: 1}, false); }
  else if (ds.k === 'changed') { go({changed: t.checked ? '1' : '', page: 1}, false); }
  else if (ds.k === 'smin' || ds.k === 'smax') { const v = t.value === '' ? '' : String(Math.max(0, Math.min(100, +t.value))); go({[ds.k]: v, page: 1}, false); }
  else if (ds.k) { go({[ds.k]: t.value, page: 1, cursor: -1}, false); }
});
let qTimer = null;
document.addEventListener('input', e => {
  const id = e.target.id;
  if (id === 'pal-q') { pal.q = e.target.value; pal.items = paletteItems(pal.q); pal.idx = 0; renderPalette(); return; }
  if (id !== 'q' && id !== 'fq') return;
  clearTimeout(qTimer);
  const v = e.target.value;
  qTimer = setTimeout(() => {
    if (id === 'q') { Object.assign(S, {q: v, page: 1, cursor: -1}); history.replaceState(null, '', toHash()); }
    else S.fq = v;
    rerenderKeepFocus(id);
  }, 160);
});
document.addEventListener('keydown', e => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName);
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal ? closeOverlay() : openPalette(); return; }
  if (pal) {
    if (e.key === 'ArrowDown') { e.preventDefault(); pal.idx = Math.min(pal.items.length - 1, pal.idx + 1); renderPalette(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); pal.idx = Math.max(0, pal.idx - 1); renderPalette(); }
    else if (e.key === 'Enter') { e.preventDefault(); runPalette(pal.idx); }
    else if (e.key === 'Escape') { e.preventDefault(); closeOverlay(); }
    return;
  }
  if (e.key === 'Escape') {
    if ($('#overlay-root').innerHTML) closeOverlay();
    else if (S.menu) { S.menu = null; render(); }
    else if (S.open !== null) go({open: null});
    else if (typing) e.target.blur();
    return;
  }
  if ($('#overlay-root').innerHTML) {  // keep focus inside dialogs
    if (e.key === 'Tab') { const f = [...$('#overlay-root').querySelectorAll('button, input')]; if (f.length) { e.preventDefault(); const i = f.indexOf(document.activeElement); f[(i + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus(); } }
    return;
  }
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === '/') { e.preventDefault(); openPalette(); return; }
  if (e.key === '?') { showKeys(); return; }
  if (S.open !== null) {
    const lst = list(), pos = lst.findIndex(x => x._i === S.open);
    if ((e.key === 'j' || e.key === ']') && pos < lst.length - 1) go({open: lst[pos + 1]._i}, false);
    else if ((e.key === 'k' || e.key === '[') && pos > 0) go({open: lst[pos - 1]._i}, false);
    return;
  }
  const n = parseInt(e.key, 10), visible = ROUTES.filter(x => x.show());
  if (n >= 1 && n <= visible.length) { go({route: visible[n - 1].id, open: null, page: 1, cursor: -1}); return; }
  if (S.route === 'domains') {
    const items = list().slice((S.page - 1) * P.size, S.page * P.size);
    if (e.key === 'f') { S.filtersOpen = !S.filtersOpen; render(); return; }
    if (!items.length) return;
    if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); S.cursor = Math.min(items.length - 1, S.cursor + 1); render(); scrollCursor(); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); S.cursor = Math.max(0, S.cursor - 1); render(); scrollCursor(); }
    else if (e.key === 'Enter' && S.cursor >= 0) { e.preventDefault(); go({open: items[S.cursor]._i, dtab: 'overview'}); }
    else if (e.key === 'x' && S.cursor >= 0) { const i = items[S.cursor]._i; S.sel.has(i) ? S.sel.delete(i) : S.sel.add(i); render(); }
  }
});
/* ================= start ================= */
applyTheme();
fromHash();
history.replaceState(null, '', toHash());
render();
})();
