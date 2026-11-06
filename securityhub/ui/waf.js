
(function () {
'use strict';
/* @include core.js */
/* @include report-core.js */
/* @include asset-report.js */
window.ASSET_NOUN = ['website', 'websites'];
/* @include asset-data.js */
/* ================= WAFGuard: Imperva Cloud WAF ================= */
const ACC = D.account_issues || [], POL = D.policies || [];
const BLOCKING = ['BLOCK', 'BLOCK_REQUEST', 'BLOCK_USER', 'BLOCK_IP', 'QUARANTINE'];
const SHORT = {onboarding: 'Onboard', allowlist: 'Allow'};
const DETAIL = {
  onboarding: r => r.active === 'bypass' ? 'bypass' : '',
  waf: r => { const rs = cd(r, 'waf').rules || []; return rs.length ? `${rs.filter(x => BLOCKING.includes(x.action)).length}/4 blocking` : ''; },
  allowlist: r => { const n = cd(r, 'allowlist').allowed_ip_count; return n ? `${n} IPs` : ''; },
  ddos: r => { const d = cd(r, 'ddos'); if (d.adaptive) return d.adaptive_threshold ? `adaptive ${d.adaptive_threshold} rps` : 'adaptive threshold'; return d.recommended && d.threshold && d.recommended !== d.threshold ? `${d.threshold} \u2192 ${d.recommended} rps` : d.threshold ? `${d.mode || ''} ${d.threshold} rps`.trim() : (d.mode || ''); },
  tls: r => { const d = cd(r, 'tls'); return d.days_left !== undefined && d.days_left !== null ? `${d.days_left} days` : ''; }
};
const actionPill = a => BLOCKING.includes(a) ? pill('valid', ({BLOCK: 'Block request', BLOCK_REQUEST: 'Block request', BLOCK_USER: 'Block user', BLOCK_IP: 'Block IP', QUARANTINE: 'Quarantine'})[a])
  : a === 'ALERT' ? pill('warning', 'Alert only') : a ? pill('error', a === 'IGNORE' ? 'Ignore' : a) : pill('missing', 'not set');
function ddosChart(d) {
  const t = d.traffic, pts = (t && t.chart) || [];
  if (pts.length < 2) return '';
  const W = 640, H = 190, L = 46, Rr = 10, T = 14, B = 26;
  const top = Math.max(d.threshold || 0, d.recommended || 0, ...pts.map(p => p[1] + p[2])) * 1.1 || 1;
  const x = i => L + i * (W - L - Rr) / (pts.length - 1), y = v => H - B - (v / top) * (H - T - B);
  const path = pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[1]).toFixed(1)}`).join('');
  const blocked = pts.some(p => p[2] > 0) ? pts.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[1] + p[2]).toFixed(1)}`).join('') : '';
  const hl = (v, cls, lbl) => v ? `<line x1="${L}" x2="${W - Rr}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}" class="${cls}"/><text x="${W - Rr}" y="${(y(v) - 5).toFixed(1)}" text-anchor="end" class="${cls}-t">${lbl} ${v}</text>` : '';
  const day = ts => new Date(ts).toISOString().slice(0, 10);
  const ticks = [0, 0.5, 1].map(f => `<text x="${L - 6}" y="${(y(top * f) + 3).toFixed(1)}" text-anchor="end" class="ax">${Math.round(top * f)}</text><line x1="${L}" x2="${W - Rr}" y1="${y(top * f).toFixed(1)}" y2="${y(top * f).toFixed(1)}" class="grid"/>`).join('');
  return `<svg class="ddos-chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Legitimate requests per second against the DDoS threshold">${ticks}
    <path d="${path}L${x(pts.length - 1).toFixed(1)},${y(0)}L${L},${y(0)}Z" class="area"/>${blocked ? `<path d="${blocked}" class="blk"/>` : ''}<path d="${path}" class="ln"/>
    ${hl(d.threshold, 'thr', 'Current')}${d.recommended !== d.threshold ? hl(d.recommended, 'rec', 'Recommended') : ''}
    <text x="${L}" y="${H - 6}" class="ax">${day(pts[0][0])}</text><text x="${W - Rr}" y="${H - 6}" text-anchor="end" class="ax">${day(pts[pts.length - 1][0])}</text></svg>
    <div class="legend"><span><i class="dot" style="background:var(--accent)"></i>Legitimate req/s (peak per bucket)</span>${blocked ? '<span><i class="dot" style="background:var(--dns)"></i>Including blocked</span>' : ''}<span><i class="dot" style="background:var(--fail)"></i>Current threshold</span><span><i class="dot" style="background:var(--pass)"></i>Recommended</span></div>`;
}
const APP = {
  tool: 'WAFGuard', subtitle: 'Imperva WAF posture', title: 'Imperva WAF posture',
  hasAuth: CHECKS.includes('waf'),
  domSub: r => esc([`#${r.site_id}`, r._acc, r.owner, r.bu].filter(Boolean).join(', ')),
  profiles: {bypass: 'Bypass mode', onboarding: 'Onboarding incomplete', error: 'Partially read', protected: 'Protected'},
  badges: {bypass: 'Bypass mode', onboarding: 'Onboarding incomplete', error: 'Partially read'},
  accountLabel: 'Account',
  kpis: kpi => {
    const bypass = R.filter(r => r.profile === 'bypass').length, onb = R.filter(r => r.profile === 'onboarding').length;
    return (bypass ? kpi(bypass, 'in bypass mode', 'k-fail', 'data-filter="profile" data-value="bypass"') : '')
      + (onb ? kpi(onb, 'onboarding incomplete', '', 'data-filter="profile" data-value="onboarding"') : '');
  },
  overviewExtra: () => {
    let h = '';
  const DD = [['DDOS_THRESHOLD_LOW', 'Too low for real peaks'], ['DDOS_THRESHOLD_HIGH', 'Too high to trigger'],
    ['DDOS_ABOVE_ORIGIN', 'Above origin capacity'], ['DDOS_DEFAULT_THRESHOLD', 'Left at default 1000'], ['DDOS_OFF', 'Protection off']];
  const withData = R.filter(r => cd(r, 'ddos').recommended);
  if (CHECKS.includes('ddos') && withData.length) {
    const aligned = withData.filter(r => !DD.some(([c]) => r._codes.has(c))).length;
    h += `<section class="card"><header><h2>DDoS thresholds</h2><p>Compared with ${withData.length} sites' real traffic</p></header><div class="body"><ul class="rows">
      <li><div class="r-btn" style="cursor:default"><span class="r-main">Aligned with traffic</span><span class="r-val num score hi">${aligned}</span></div></li>
      ${DD.map(([c, l]) => { const k = R.filter(r => r._codes.has(c)).length; return k ? `<li><button class="r-btn" data-finding="${c}"><span class="r-main">${esc(l)}</span><span class="r-val num">${k}</span></button></li>` : ''; }).join('')}</ul></div></section>`;
  }
    return h;
  },
  accTitle: 'Account findings', accSub: 'affecting every website',
  presets: () => [
  ...(hasMeta && R.some(r => r.tier === 'critical') ? [['tier1', 'Critical tier', {tier: 'critical'}]] : []),
  ...(R.some(r => r.profile === 'bypass') ? [['byp', 'Bypass mode', {profile: 'bypass'}]] : []),
  ...(CHECKS.includes('origin') && R.some(r => r.probed) ? [['org', 'Origin exposed', {f: {origin: 'error'}}]] : []),
  ...(hasAuth ? [['pci', 'Fails PCI DSS 6.4.2', {comp: 'pci_642:fail'}], ['alert', 'WAF rules not blocking', {comp: 'owasp_block:fail'}]] : []),
  ],
  searchHint: 'Filter by website, site ID, account, owner or tag',
  groupKeys: {account: r => [r._acc || '(account)']},
  groupLabels: [['account', 'Account']],
  policies: {
    label: 'Policies', show: () => POL.length > 0, count: () => POL.length,
    render: () => {
  const typeOrder = {WAF_RULES: 0, WHITELIST: 1, ACL: 2, FILE_UPLOAD: 3};
  const rows = [...POL].sort((a, b) => (typeOrder[a.type] ?? 9) - (typeOrder[b.type] ?? 9) || String(a.name).localeCompare(String(b.name)));
  const accHtml = ACC.length ? `<section class="card" style="margin-bottom:16px"><header><h2>Account findings</h2><p>Configuration that affects every website</p></header><div class="body">${issueList(ACC)}</div></section>` : '';
  return accHtml + `<div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky" style="min-width:200px">Policy</th><th>Type</th><th>State</th><th class="r">Assets</th><th class="r">In this scan</th><th>Settings</th><th class="r">Exceptions</th><th>Last change</th></tr></thead><tbody>
    ${rows.map(p => `<tr><td class="sticky" style="min-width:200px"><button class="dom" style="word-break:normal" data-policy="${esc(p.id)}">${esc(p.name)}</button><div class="dom-sub">#${esc(p.id)}${p.account ? ', account ' + esc(p.account) : ''}</div></td>
      <td><span class="tag">${esc(p.type)}</span>${p.default ? ' <span class="tag tier-high">default</span>' : ''}</td>
      <td>${p.enabled ? '<span class="pill s-pass">Enabled</span>' : '<span class="pill s-fail">Disabled</span>'}</td><td class="r num">${esc(p.assets)}</td><td class="r num">${esc(p.in_scan)}</td>
      <td class="sub">${esc(p.settings)}</td><td class="r num">${esc(p.exceptions)}</td><td class="sub nowrap">${esc(p.modified)}${p.modified_by ? '<br>' + esc(p.modified_by) : ''}</td></tr>`).join('')
      || '<tr><td colspan="8" class="empty">No policies returned by the API.</td></tr>'}</tbody></table></div>`;
    }
  },
  config: {
    checks: ['onboarding', 'waf', 'allowlist', 'bots', 'ddos', 'tls'], label: 'Configuration',
    render: r => {
  let h = '';
  if (vis(r, 'onboarding')) { const d = cd(r, 'onboarding');
    h += sec('onboarding', 'Website', `<div class="kv">${kv('Site ID', r.site_id)}${kv('Account', r._acc)}${kv('Status', d.status)}${kv('Mode', d.active)}${kv('Display name', d.display_name)}
      ${kv('Policies applied', (r.policies || []).map(p => `${p.name} (${p.type}${p.enabled ? '' : ', disabled'})`).join(', '))}</div>
      ${(d.dns || []).length ? `<table style="margin-top:14px"><thead><tr><th>DNS record</th><th>Type</th><th>Point to</th></tr></thead><tbody>${d.dns.map(x => `<tr><td class="mono">${esc(x.name)}</td><td>${esc(x.type)}</td><td class="mono">${esc([].concat(x.value || []).join(', '))}</td></tr>`).join('')}</tbody></table>` : ''}`, pill(r._st('onboarding'))); }
  if (vis(r, 'waf')) { const d = cd(r, 'waf');
    h += sec('waf', 'WAF rules', `<p class="sub" style="margin-bottom:10px">${d.policy ? `Policy <b>${esc(d.policy.name)}</b> #${esc(d.policy.id)}${d.policy.enabled ? '' : ' (disabled)'}` : d.legacy ? 'Legacy per-site rules (no WAF Rules policy applied)' : 'No WAF rules found'}</p>
      <table><thead><tr><th>Rule</th><th>Action</th><th>Source</th><th class="r">Exceptions</th></tr></thead><tbody>${(d.rules || []).map(x => `<tr><td>${esc(x.rule)}</td><td>${actionPill(x.action)}</td><td class="sub">${esc(x.source)}</td><td class="r num">${esc(x.exceptions)}</td></tr>`).join('')}</tbody></table>
      <div class="kv" style="margin-top:14px">${kv('Backdoor protection', d.backdoor)}${kv('Data leakage protection', d.data_leak)}${kv('Exceptions', d.exception_count)}</div>
      ${(d.exceptions || []).length ? `<details class="more"${d.exceptions.some(e => e.broad) ? ' open' : ''}><summary>Exceptions (${d.exception_count})</summary><table style="margin-top:8px"><thead><tr><th>Rule</th><th>Conditions (all must match)</th><th>Applies to</th><th>Comment</th></tr></thead><tbody>
        ${d.exceptions.map(e => `<tr><td>${esc(e.rule)}${e.broad ? ' ' + pill('warning', 'broad') : ''}${e.why ? `<br><span class="sub">${esc(e.why)}</span>` : ''}</td><td class="mono">${(e.values || []).map(esc).join('<br>') || '<span class="faint">any request</span>'}</td><td class="sub">${esc(e.scope || '')}</td><td class="sub">${esc(e.comment) || '<span class="faint">none</span>'}</td></tr>`).join('')}</tbody></table></details>` : ''}`, pill(r._st('waf'))); }
  if (vis(r, 'allowlist')) { const d = cd(r, 'allowlist');
    h += sec('allowlist', 'Allow-lists and access control', `<div class="kv">${kv('Allow-listed IPs', d.allowed_ip_count)}${kv('Blocked countries', (d.blocked_countries || []).join(', '))}${kv('Blocked continents', (d.blocked_continents || []).join(', '))}${kv('Blocked IPs', d.blocked_ips)}${kv('Blocked URLs', d.blocked_urls)}</div>
      ${(d.allowed_ips || []).length ? `<details class="more"><summary>Allow-listed IPs (${d.allowed_ip_count})</summary><div class="tree">${d.allowed_ips.map(esc).join('<br>')}</div></details>` : ''}
      ${(d.allowed_urls || []).length ? `<details class="more"><summary>Allow-listed URLs</summary><div class="tree">${d.allowed_urls.map(esc).join('<br>')}</div></details>` : ''}`, pill(r._st('allowlist'))); }
  const bd = [];
  if (vis(r, 'bots')) { const d = cd(r, 'bots'); bd.push(kv('Block bad bots', yesNo(d.block_bad_bots)), kv('Challenge suspected bots', yesNo(d.challenge_suspected_bots))); }
  if (bd.length) h += sec('bots', 'Bot access control', `<div class="kv">${bd.join('')}</div>`, pill(r._st('bots')));
  if (vis(r, 'ddos')) { const d = cd(r, 'ddos'), t = d.traffic;
    h += sec('ddos', 'DDoS protection', `<div class="kv">${kv('Activation mode', d.mode)}${kv('Current threshold', d.adaptive ? 'Adaptive (set by Imperva from the site traffic)' + (d.adaptive_threshold ? ` \u2014 currently ${d.adaptive_threshold} req/s` : '') : d.threshold ? d.threshold + ' req/s' : '')}
      ${t && !d.adaptive ? kv('Recommended threshold', d.recommended + ' req/s', d.recommended === d.threshold ? 'score hi' : '') + kv('Peak legitimate traffic', `${t.peak} req/s`) + kv('Peak at', t.peak_at + ' UTC')
        + kv('Peak vs threshold', d.peak_ratio !== undefined ? d.peak_ratio + '%' : '', d.peak_ratio >= 90 ? 'score lo' : '') + kv('95th percentile', `${t.p95} req/s`) + kv('Average', `${t.avg} req/s`)
        + kv('Blocked peak', `${t.blocked_peak} req/s`) + kv('DDoS incidents', t.ddos_incidents) : ''}${kv('Origin capacity', d.origin_max_rps ? d.origin_max_rps + ' req/s' : 'not provided')}</div>
      ${d.adaptive ? '<p class="sub" style="margin-top:10px">Adaptive protection: Imperva derives the activation threshold from the site\'s own traffic, so it is not compared with a fixed value.</p>' : t ? ddosChart(d) + `<p class="sub" style="margin-top:8px">Last ${esc(t.days)} days, ${t.granularity_s ? (t.granularity_s >= 86400 ? Math.round(t.granularity_s / 86400) + '-day' : Math.round(t.granularity_s / 3600) + '-hour') : 'default'} buckets (${t.points} points)${d.coarse ? ': coarse data, the API did not accept hourly granularity, so peaks are strongly smoothed' : ''}. Values are averages per bucket: short bursts are higher. Recommended: ${esc(d.recommended_why)}.</p>`
        : '<p class="sub" style="margin-top:10px">Traffic statistics not available: the threshold could not be compared with real traffic.</p>'}`, pill(r._st('ddos'))); }
  if (vis(r, 'tls')) { const d = cd(r, 'tls');
    h += sec('tls', 'TLS', `<div class="kv">${kv('Certificate', d.certificate)}${kv('Expires', d.expires)}${kv('Days left', d.days_left)}${kv('Validation', d.validation)}${kv('TLS to origin', yesNo(d.origin_tls))}
      ${r.probed ? kv('HSTS', (() => { const h = d.hsts_check || {}; return h.state === 'present' ? `${h.header}${h.path && h.path !== '/' ? ' (on ' + h.path + ')' : ''}` : h.state === 'unknown' ? `not verifiable: ${h.reason || 'no answer'}` : h.state === 'disabled' ? `disabled: ${h.header}` : (d.hsts || 'not served') + (h.reason ? ` (${h.reason})` : ''); })()) + kv('HTTP to HTTPS redirect', yesNo(d.redirects_https)) + kv('TLS 1.0 accepted', yesNo(d.tls10)) + kv('TLS 1.1 accepted', yesNo(d.tls11)) + kv('Negotiated', d.served_tls) : ''}</div>
      ${r.probed ? '' : '<p class="sub" style="margin-top:10px">HSTS, redirect and legacy TLS are tested with --probe.</p>'}`, pill(r._st('tls'))); }
  return h;
    }
  },
  exposure: {
    checks: ['origin'], label: 'Internet exposure', show: r => vis(r, 'origin') || r.probed,
    render: r => {
  const o = cd(r, 'origin'), p = cd(r, 'onboarding').probe;
  let h = '';
  if (p) h += sec('dns', 'DNS routing', `<div class="kv">${kv('Routed through Imperva', yesNo(p.routed))}${kv('CNAME chain', (p.cnames || []).join(' > '))}${kv('Resolves to', (p.addresses || []).join(', '))}${kv('Expected', (p.expected || []).join(', '))}${kv('Imperva edge headers', yesNo(p.imperva_edge))}</div>`);
  if (vis(r, 'origin')) h += sec('origin', 'Origin servers', o.results ? `<p class="sub" style="margin-bottom:10px">One GET / per origin address on 443 and 80, with the website host name. An origin that answers lets attackers bypass the WAF.</p>
      <table><thead><tr><th>Origin</th><th>Address</th><th>Result</th><th>Port</th><th>HTTP</th></tr></thead><tbody>${o.results.map(x => `<tr><td class="mono">${esc(x.origin)}</td><td class="mono">${esc(x.ip)}</td>
        <td>${x.result === 'serves' ? pill('error', 'answers directly') : x.result === 'reachable' ? pill('warning', 'port open') : x.result === 'private' ? pill('na', 'private address') : pill('valid', 'closed')}</td><td class="num">${esc(x.port || '')}</td><td class="num">${esc(x.status || '')}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">No origin addresses in the configuration.</td></tr>'}</tbody></table>`
    : `<p class="muted">${esc(o.note || 'Not tested.')}</p><div class="kv" style="margin-top:10px">${kv('Configured origins', (o.origins || []).join(', '))}</div>`, pill(r._st('origin')));
  return h || '<p class="muted">Run with --probe to test DNS routing, origin exposure, HSTS and TLS versions from the Internet.</p>';
    }
  },
  indicative: 'based on the configuration read from the API and, with --probe, on tests from the Internet.',
  fixesIntro: 'Terraform snippets for the Imperva (incapsula) provider. Check attribute names against your provider version and plan before applying.',
  metaTags: r => `<span class="tag">#${esc(r.site_id)}</span>${r._acc ? `<span class="tag">${esc(r._acc)}</span>` : ''}`,
  metaNote: r => r.probed ? ', tested from the Internet' : '',
  csv: {head: ['website', 'site_id', 'account'], row: r => [r.domain, r.site_id, r._acc], file: 'wafguard-websites', selected: 'wafguard-selected.csv'},
  copyNoun: 'websites'
};
/* @include asset-app.js */
})();
