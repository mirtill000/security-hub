/* Asset noun of the report: an app sets window.ASSET_NOUN (default: domain / domains). */
function noun(n) { const w = window.ASSET_NOUN || ['domain', 'domains']; return w[n === 1 ? 0 : 1]; }
const st = s => ST[s] || ST.missing;
const scoreCls = n => n >= 80 ? 'hi' : n >= 50 ? 'mid' : 'lo';
const gradeOf = n => n >= 90 ? 'A' : n >= 75 ? 'B' : n >= 65 ? 'C' : n >= 50 ? 'D' : 'F';
const tierW = t => D.tiers[t] || 2;
const vis = (r, c) => CHECKS.includes(c) && r._st(c) !== 'skipped';
const icon = (n, s) => `<svg class="ico" width="${s || 16}" height="${s || 16}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;
const tierTag = t => `<span class="tag tier-${esc(t)}">${esc(t)}</span>`;
const scoreHtml = n => `<span class="score ${scoreCls(n)}">${n}</span>`;
function deltaHtml(r) {
  if (!r.change) return '<span class="faint">\u2013</span>';
  if (r.change.new) return '<span class="tag">new</span>';
  const d = r.change.score_delta;
  return d > 0 ? `<span class="delta-up num">+${d}</span>` : d < 0 ? `<span class="delta-down num">${d}</span>` : '<span class="faint num">0</span>';
}
function ring(score, size) {
  const rad = 26, c = 2 * Math.PI * rad, off = c * (1 - score / 100);
  return `<svg class="ring ${scoreCls(score)}" width="${size || 64}" height="${size || 64}" viewBox="0 0 64 64" aria-label="Score ${score}"><circle cx="32" cy="32" r="${rad}" class="ring-bg"/><circle cx="32" cy="32" r="${rad}" class="ring-fg" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 32 32)"/><text x="32" y="38" text-anchor="middle">${score}</text></svg>`;
}
function weighted(rows, fn) {
  const w = rows.reduce((a, r) => a + tierW(r.tier), 0);
  return w ? rows.reduce((a, r) => a + fn(r) * tierW(r.tier), 0) / w : 0;
}
const findingTitle = c => (FIND[c] || [0, 0, c])[2];
function toHash() {
  const p = new URLSearchParams();
  FKEYS.forEach(k => { if (S[k]) p.set(k, S[k]); });
  Object.keys(S.f).forEach(c => { if (S.f[c]) p.set('c.' + c, S.f[c]); });
  if (S.sort.k !== 'priority' || S.sort.d !== -1) p.set('sort', (S.sort.d < 0 ? '-' : '') + S.sort.k);
  if (S.page > 1) p.set('page', S.page);
  if (S.open !== null) { p.set('d', R[S.open].domain); if (S.dtab !== 'overview') p.set('t', S.dtab); }
  const qs = p.toString();
  return '#/' + S.route + (qs ? '?' + qs : '');
}
function fromHash() {
  const raw = decodeURIComponent(location.hash.replace(/^#\/?/, ''));
  if (raw.startsWith('domain=')) {  // links from v3.0 reports
    const r0 = R.find(x => x.domain === raw.slice(7));
    Object.assign(S, blank(), {route: 'domains', open: r0 ? r0._i : null, dtab: 'overview'});
    return;
  }
  const qi = location.hash.indexOf('?');
  const route = location.hash.replace(/^#\/?/, '').split('?')[0];
  const p = new URLSearchParams(qi >= 0 ? location.hash.slice(qi + 1) : '');
  Object.assign(S, blank());
  S.route = ROUTES.some(x => x.id === route && x.show()) ? route : 'overview';
  FKEYS.forEach(k => { if (p.has(k)) S[k] = p.get(k); });
  p.forEach((v, k) => { if (k.startsWith('c.') && CHECKS.includes(k.slice(2))) S.f[k.slice(2)] = v; });
  const so = p.get('sort');
  S.sort = so ? {k: so.replace(/^-/, ''), d: so.startsWith('-') ? -1 : 1} : {k: 'priority', d: -1};
  S.page = Math.max(1, +p.get('page') || 1);
  const d = p.get('d'), r = d ? R.find(x => x.domain === d) : null;
  S.open = r ? r._i : null;
  S.dtab = p.get('t') || 'overview';
}
function go(changes, push) {
  Object.assign(S, changes);
  const h = toHash();
  if (location.hash !== h) history[push === false ? 'replaceState' : 'pushState'](null, '', h);
  render();
}
function list() {
  const key = toHash().replace(/[?&](d|t|page)=[^&]*/g, '');
  if (_cache.key === key) return _cache.list;
  const a = R.filter(matches);
  const fn = SORTERS[S.sort.k] || SORTERS.priority, d = S.sort.d;
  a.sort((x, y) => { const p = fn(x), q = fn(y); return (p < q ? -1 : p > q ? 1 : 0) * d || x.domain.localeCompare(y.domain); });
  _cache = {key, list: a};
  return a;
}
function clearChip(key) {
  if (key.startsWith('c.')) delete S.f[key.slice(2)];
  else if (key === 'range') { S.smin = ''; S.smax = ''; }
  else S[key] = '';
}
const filterTo = extra => go(Object.assign(blank(), {route: 'domains', open: null, page: 1, cursor: -1}, extra));
function findingCounts() {
  const counts = {};
  R.forEach(r => r._codes.forEach(c => { if (FIND[c]) counts[c] = (counts[c] || 0) + 1; }));
  return Object.entries(counts).sort((a, b) => SEV[FIND[a[0]][0]] - SEV[FIND[b[0]][0]] || b[1] - a[1]);
}
const COLS = () => [
  {id: 'tier', label: 'Tier', show: hasMeta, sort: 'tier', cell: r => tierTag(r.tier)},
  {id: 'score', label: 'Score', sort: 'score', cls: 'r', cell: r => `<div class="scorecell">${scoreHtml(r.overall_score)}<span class="mini"><i class="${scoreCls(r.overall_score)}" style="width:${r.overall_score}%"></i></span></div>`},
  {id: 'delta', label: 'Change', show: !!diff, sort: 'delta', cls: 'r', cell: deltaHtml},
  ...CHECKS.map(c => ({id: 'c.' + c, label: L[c], short: SHORT[c] || L[c], check: c, cls: P.density === 'compact' ? 'c' : '',
    cell: r => P.density === 'compact' ? sq(r._st(c), L[c]) : pill(r._st(c), DETAIL[c] ? DETAIL[c](r) : '')})),
  {id: 'findings', label: 'Findings', sort: 'findings', cell: r => r._crit || r._warn ? `<span class="counts">${r._crit ? `<span class="cnt crit" title="critical">${r._crit}</span>` : ''}${r._warn ? `<span class="cnt warn" title="warning">${r._warn}</span>` : ''}</span>` : '<span class="faint">None</span>'},
  {id: 'priority', label: 'Priority', sort: 'priority', cls: 'r', cell: r => `<span class="num">${r.priority}</span>`}
].filter(c => c.show !== false);
const visibleCols = () => COLS().filter(c => !P.hidden.includes(c.id));
function presetActive(p) {
  const target = Object.assign(blank(), p[2]);
  return FKEYS.every(k => (S[k] || '') === (target[k] || '')) && JSON.stringify(S.f) === JSON.stringify(target.f || {});
}
function filterPanel() {
  const sel = (key, label, opts, cur, fmt) => `<label class="field">${esc(label)}<select data-k="${key}"><option value="">All</option>${opts.map(o => `<option value="${esc(o)}"${o === cur ? ' selected' : ''}>${esc(fmt ? fmt(o) : o)}</option>`).join('')}</select></label>`;
  const owners = uniq(R.map(r => r.owner)), bus = uniq(R.map(r => r.bu)), tags = uniq(R.flatMap(r => r.tags || []));
  const tiers = TIER_ORDER.filter(t => R.some(r => r.tier === t));
  const compOpts = Object.keys(COMP).flatMap(k => ['fail', 'pass'].map(v => `${k}:${v}`)).filter(o => { const [k, v] = o.split(':'); return R.some(r => (r.compliance || {})[k] === v); });
  return `<div class="filter-panel">
    ${CHECKS.map(c => `<label class="field">${esc(L[c])}<select data-f="${c}"><option value="">All</option>${uniq(R.map(r => r._st(c))).map(v => `<option value="${esc(v)}"${S.f[c] === v ? ' selected' : ''}>${esc(st(v)[2])}</option>`).join('')}</select></label>`).join('')}
    ${sel('score', 'Score band', ['hi', 'mid', 'lo'], S.score, v => ({hi: '80 and above', mid: '50 to 79', lo: 'Under 50'})[v])}
    <label class="field">Score range<span class="range"><input type="number" min="0" max="100" data-k="smin" value="${esc(S.smin)}" placeholder="0" aria-label="Minimum score"><span>to</span><input type="number" min="0" max="100" data-k="smax" value="${esc(S.smax)}" placeholder="100" aria-label="Maximum score"></span></label>
    ${tiers.length > 1 ? sel('tier', 'Tier', tiers, S.tier) : ''}${owners.length ? sel('owner', 'Owner', owners, S.owner) : ''}
    ${bus.length ? sel('bu', 'Business unit', bus, S.bu) : ''}${tags.length ? sel('tag', 'Tag', tags, S.tag) : ''}
    ${sel('finding', 'Finding', findingCounts().map(x => x[0]), S.finding, findingTitle)}
    ${compOpts.length ? sel('comp', 'Requirement', compOpts, S.comp, o => { const [k, v] = o.split(':'); return `${COMP[k][0]}: ${v}`; }) : ''}
    ${diff ? `<label class="check" style="align-self:end"><input type="checkbox" data-k="changed"${S.changed ? ' checked' : ''}> Changed since baseline</label>` : ''}
  </div>`;
}
function th(c) {
  if (!c.sort) return `<th class="${c.cls || ''}" title="${esc(c.label)}">${esc(P.density === 'compact' && c.short ? c.short : c.label)}</th>`;
  const cur = S.sort.k === c.sort ? (S.sort.d > 0 ? 'ascending' : 'descending') : 'none';
  return `<th class="${c.cls || ''}" aria-sort="${cur}"><button class="sort" data-sort="${c.sort}">${esc(c.label)}</button></th>`;
}
function pager(total, pages) {
  const cur = S.page, nums = [];
  for (let p = 1; p <= pages; p++) if (p === 1 || p === pages || Math.abs(p - cur) <= 2) nums.push(p);
  let prev = 0, out = '';
  nums.forEach(p => { if (p - prev > 1) out += '<span class="faint">\u2026</span>'; out += `<button class="btn small" data-page="${p}"${p === cur ? ' aria-current="page"' : ''}>${p}</button>`; prev = p; });
  const from = total ? (cur - 1) * P.size + 1 : 0, to = Math.min(cur * P.size, total);
  return `<nav class="pager" aria-label="Pagination"><span>Rows ${from} to ${to} of ${total}
      <select data-k="size" aria-label="Rows per page" style="margin-left:8px">${[25, 50, 100, 250, 500].map(s => `<option value="${s}"${s === P.size ? ' selected' : ''}>${s} per page</option>`).join('')}</select></span>
    ${pages > 1 ? `<div class="pages"><button class="btn small" data-page="${cur - 1}"${cur <= 1 ? ' disabled' : ''}>${icon('left', 14)}Previous</button>${out}<button class="btn small" data-page="${cur + 1}"${cur >= pages ? ' disabled' : ''}>Next${icon('right', 14)}</button></div>` : ''}
    <span class="faint">Keys: <span class="kbd">j</span> <span class="kbd">k</span> move, <span class="kbd">Enter</span> open</span></nav>`;
}
function findings() {
  const fq = S.fq.trim().toLowerCase();
  const rows = findingCounts().filter(([c]) => (!S.fsev || FIND[c][0] === S.fsev) && (!fq || findingTitle(c).toLowerCase().includes(fq) || FIND[c][1].toLowerCase().includes(fq)));
  const sevCount = s => findingCounts().filter(([c]) => FIND[c][0] === s).length;
  return `<div class="toolbar"><div class="search-box">${icon('search')}<input type="search" id="fq" placeholder="Filter findings" value="${esc(S.fq)}" aria-label="Filter findings"></div>
    <div class="seg" role="group" aria-label="Severity">${[['', 'All'], ['critical', 'Critical'], ['warning', 'Warning'], ['info', 'Info']].map(([v, l]) =>
      `<button data-fsev="${v}" aria-pressed="${S.fsev === v}">${l}${v ? ` <span class="faint">${sevCount(v)}</span>` : ''}</button>`).join('')}</div></div>
    <div class="flist">${rows.map(([c, k]) => { const f = FIND[c];
      const doms = R.filter(r => r._codes.has(c)).sort((a, b) => b.priority - a.priority);
      return `<details class="finding"><summary><span class="sev sev-${f[0]}" title="${f[0]}"></span>
        <span class="ttl"><b>${esc(f[2])}</b><span>${esc(f[1])}, ${esc(f[0])}</span></span>
        <span class="bar fbar" title="${pct(k, R.length)}% of ${noun(2)}"><i class="b-${f[0] === 'critical' ? 'fail' : f[0] === 'warning' ? 'warn' : 'acc'}" style="width:${pct(k, R.length)}%"></i></span>
        <span class="num" style="text-align:right">${k}</span><span class="chev">${icon('chev')}</span></summary>
        <div class="fbody"><p>${esc(f[3])}</p>${(FW[f[1]] || []).length ? `<div class="fw">${FW[f[1]].map(x => `<span class="tag">${esc(x)}</span>`).join('')}</div>` : ''}
          <div class="dlist">${doms.slice(0, 40).map(r => `<button data-open="${r._i}">${esc(r.domain)}</button>`).join('')}${doms.length > 40 ? `<span class="faint">and ${doms.length - 40} more</span>` : ''}</div>
          <div><button class="btn small" data-finding="${esc(c)}">Show the ${k} ${noun(k)} in the list${icon('arrow', 14)}</button></div></div></details>`; }).join('') || '<div class="card empty"><b>No findings</b>Nothing matches this filter.</div>'}</div>`;
}
function changes() {
  const changed = R.filter(r => r.change && r.change.changed).sort((a, b) => (a.change.score_delta || 0) - (b.change.score_delta || 0));
  return `<div class="stat-strip" style="margin-bottom:16px">
      <div class="stat"><b class="delta-up">${diff.improved}</b><span>improved</span></div><div class="stat"><b class="delta-down">${diff.worsened}</b><span>worsened</span></div>
      <div class="stat"><b>${diff.unchanged}</b><span>unchanged</span></div><div class="stat"><b>${diff.new_critical}</b><span>new critical findings</span></div></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Domain</th><th class="r">Score</th><th>Control changes</th><th>New findings</th><th>Resolved</th></tr></thead><tbody>
    ${changed.map(r => { const c = r.change;
      return `<tr data-row="${r._i}"><td class="sticky"><button class="dom" data-open="${r._i}">${esc(r.domain)}</button>${c.new ? '<div class="dom-sub">new domain</div>' : ''}</td>
        <td class="r nowrap">${c.new ? scoreHtml(r.overall_score) : `<span class="faint num">${esc(c.previous_score)}</span> ${icon('arrow', 12).replace('class="ico"', 'class="ico" style="display:inline;vertical-align:-1px"')} ${scoreHtml(r.overall_score)} ${deltaHtml(r)}`}</td>
        <td>${c.status_changes.map(s => `<div class="nowrap" style="margin:2px 0">${esc(L[s.check] || s.check)} ${pill(s.from)} ${pill(s.to)}</div>`).join('')}</td>
        <td class="sub">${c.new_issues.map(x => esc(findingTitle(x))).join('<br>')}</td><td class="sub">${c.resolved_issues.map(x => esc(findingTitle(x))).join('<br>')}</td></tr>`; }).join('')
      || '<tr><td colspan="5" class="empty">No changes since the baseline.</td></tr>'}</tbody></table></div>
    ${diff.removed_domains.length ? `<p class="muted" style="margin-top:12px">No longer scanned: ${diff.removed_domains.map(esc).join(', ')}</p>` : ''}`;
}
const kv = (label, value, cls) => `<div><span>${esc(label)}</span><b class="${cls || ''}">${value === null || value === undefined || value === '' ? '<span class="faint">none</span>' : esc(value)}</b></div>`;
const sec = (id, title, body, act) => `<section class="dr-sec" id="sec-${id}"><h3>${esc(title)}${act ? `<span class="act">${act}</span>` : ''}</h3>${body}</section>`;
function issueList(issues) {
  return issues.map(i => `<div class="issue"><span class="sev sev-${esc(i.severity)}" title="${esc(i.severity)}"></span>
    <div><div class="msg">${esc(i.message)}</div><div class="proto">${esc(i.protocol)}, ${esc(i.severity)}</div></div>
    <div class="rec">${esc(i.recommendation)}</div>${(FW[i.protocol] || []).length ? `<div class="fw">${FW[i.protocol].map(x => `<span class="tag">${esc(x)}</span>`).join('')}</div>` : ''}</div>`).join('');
}
function renderPalette() {
  let g = '', html = '';
  pal.items.forEach((it, k) => { if (it.g !== g) { g = it.g; html += `<li class="pal-group" role="presentation">${esc(g)}</li>`; }
    html += `<li class="pal-item" role="option" id="pal-${k}" data-pal="${k}" aria-selected="${k === pal.idx}"><span class="ptitle">${esc(it.t)}</span><span class="phint">${esc(it.h)}</span></li>`; });
  $('#pal-list').innerHTML = html || '<li class="pal-group">No results</li>';
  const q = $('#pal-q'); if (q) q.setAttribute('aria-activedescendant', 'pal-' + pal.idx);
  const cur = $('#pal-' + pal.idx); if (cur) cur.scrollIntoView({block: 'nearest'});
}
function dialog(title, body) {
  $('#overlay-root').innerHTML = `<div class="overlay" data-overlay><div class="dialog" role="dialog" aria-modal="true" aria-labelledby="dlg-t">
    <header><h2 id="dlg-t">${esc(title)}</h2><button class="btn icon ghost" data-action="overlay-close" aria-label="Close">${icon('x')}</button></header><div class="dbody">${body}</div></div></div>`;
  const b = $('#overlay-root [data-action="overlay-close"]'); if (b) b.focus();
}
function toast(msg) { const t = document.createElement('div'); t.className = 'toast'; t.textContent = msg; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 2600); }
function copyText(text, okMsg) {
  const done = () => toast(okMsg || 'Copied');
  const fallback = () => { const t = document.createElement('textarea'); t.value = text; t.style.position = 'fixed'; t.style.opacity = '0'; document.body.appendChild(t); t.select();
    try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed: select the text manually'); } t.remove(); };
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
}
function copyLink() { copyText(location.href, 'Link copied'); }
function download(name, mime, text) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], {type: mime})); a.download = name;
  document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  toast(`Downloaded ${name}`);
}
function printExec() {
  if (S.route !== 'overview' || S.open !== null) go({route: 'overview', open: null});
  document.body.classList.add('print-exec');
  setTimeout(() => window.print(), 60);
}
function printDomain() {
  const prev = S.dtab; S.dtab = 'all'; drawer();
  document.body.classList.add('print-drawer');
  setTimeout(() => { window.print(); }, 60);
  window.__restoreTab = prev;
}
function rerenderKeepFocus(id) {
  const el = document.getElementById(id), pos = el ? el.selectionStart : null;
  render();
  const n = document.getElementById(id); if (n) { n.focus(); if (pos !== null) try { n.setSelectionRange(pos, pos); } catch (e) { /* number inputs */ } }
}
function scrollCursor() { const row = document.querySelector('tr.cursor'); if (row) row.scrollIntoView({block: 'nearest'}); }
