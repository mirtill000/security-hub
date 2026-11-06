(function () {
'use strict';
/* @include core.js */
/* @include report-core.js */
/* @include asset-report.js */
window.ST_LABELS = {null: ['null', '∅', 'Null MX'], na: ['na', '·', 'Not applicable'], dns_error: ['dns', '?', 'DNS error']};
/* @include asset-data.js */
/* ================= MailGuard: DNS and e-mail authentication ================= */
const ATTR = D.attrs, ACC = [], POL = [];
const VIEW = M.view || 'combined', TITLE = M.title || 'Email security posture';
const TOOL = {email: 'MailGuard Email', dns: 'MailGuard DNS'}[VIEW] || 'MailGuard DNS';
const SHORT = {'mta-sts': 'STS', 'tls-rpt': 'TLS', takeover: 'Deps', axfr: 'XFR', consistency: 'Sync', lookalikes: 'Look'};
const DETAIL = {
  mx: r => r.mx.total_count ? `${r.mx.protected_count}/${r.mx.total_count} protected` : '',
  spf: r => r.spf.record ? `${r.spf.lookups}/10 lookups` : '',
  dkim: r => r.dkim.total_selectors ? `${r.dkim.valid_selectors} key${r.dkim.valid_selectors === 1 ? '' : 's'}`
    : r.dkim.status === 'unknown' && r.dkim.mode === 'dkim.csv' && !(r.dkim.declared || []).length ? 'domain not in dkim.csv' : '',
  dmarc: r => r.dmarc.policy ? `p=${r.dmarc.policy}` : '',
  'mta-sts': r => r.mta_sts.mode ? `mode ${r.mta_sts.mode}` : '',
  caa: r => r.caa.issuers.length ? (r.caa.issuers[0] === ';' ? 'no CA allowed' : `${r.caa.issuers.length} CA${r.caa.issuers.length === 1 ? '' : 's'}`) : '',
  axfr: r => r.axfr.servers.length ? `${r.axfr.servers.filter(s => s.result === 'open').length}/${r.axfr.servers.length} open` : '',
  takeover: r => r.takeover.dependencies.length ? `${r.takeover.dependencies.length} deps` : '',
  lookalikes: r => r.lookalikes.registered.length ? `${r.lookalikes.registered.length} found` : ''
};
const EVID = ['mx', 'spf', 'dkim', 'dmarc', 'mta-sts', 'tls-rpt', 'bimi', 'dnssec', 'caa'], EXPO = ['takeover', 'axfr', 'consistency', 'lookalikes'];
function lookRows() {
  const seen = new Set(), rows = [];
  R.forEach(r => (r.lookalikes.registered || []).forEach(e => { const k = r.lookalikes.base + '|' + e.domain; if (!seen.has(k)) { seen.add(k); rows.push({r, e}); } }));
  return rows.sort((a, b) => (b.e.mx - a.e.mx) || String(b.e.created || '').localeCompare(String(a.e.created || '')));
}
function lookView() {
  const rows = lookRows().filter(x => !S.lmx || x.e.mx);
  return `<div class="toolbar"><label class="check"><input type="checkbox" data-lmx${S.lmx ? ' checked' : ''}> Only domains with mail servers</label></div>
    <div class="grid-wrap"><table class="grid"><thead><tr><th class="sticky">Lookalike</th><th>Imitates</th><th>Technique</th><th>Mail servers</th><th>Website</th><th>Registered</th></tr></thead><tbody>
    ${rows.map(({r, e}) => `<tr data-row="${r._i}"><td class="sticky mono">${esc(e.domain)}</td><td><button class="link" data-open="${r._i}" data-dtab="exposure">${esc(r.lookalikes.base)}</button></td>
      <td>${esc(e.kind)}</td><td>${e.mx ? pill('error', 'MX') : '<span class="faint">No</span>'}</td><td>${e.a ? 'Yes' : '<span class="faint">No</span>'}</td>
      <td class="nowrap">${esc((e.created || '').slice(0, 10)) || '<span class="faint">unknown</span>'}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No registered lookalikes found.</td></tr>'}</tbody></table></div>`;
}
function reportsView() {
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
function dnsEvidence(r) {
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
function dnsExposure(r) {
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
function dnsReports(r) {
  const x = r.dmarc_reports;
  return sec('reports', 'DMARC aggregate reports', `<p class="note-box" style="margin-bottom:14px">${esc(x.verdict)}</p>
    <div class="kv">${kv('Period', x.period.filter(Boolean).join(' to '))}${kv('Reports', x.reports)}${kv('Messages', x.messages)}${kv('Pass rate', x.pass_rate + '%')}${kv('Not aligned', x.unaligned)}${kv('Unauthenticated', x.spoofed)}${kv('Selectors seen', x.selectors.join(', '))}${kv('Reporters', x.reporters.join(', '))}</div>
    ${x.sources.length ? `<table style="margin-top:16px"><thead><tr><th>Source</th><th class="r">Messages</th><th>Result</th><th>Envelope or DKIM domains</th></tr></thead><tbody>${x.sources.slice(0, 30).map(s => `<tr>
      <td class="mono">${esc(s.ip)}${s.ptr ? `<div class="sub">${esc(s.ptr)}</div>` : ''}</td><td class="r num">${s.count}</td>
      <td>${pill({aligned: 'valid', unaligned: 'warning', spoof: 'error'}[s.category], {aligned: 'passes', unaligned: 'not aligned', spoof: 'unauthenticated'}[s.category])}</td>
      <td class="sub">${esc([...s.envelope_from, ...s.dkim_domains].join(', '))}</td></tr>`).join('')}</tbody></table>` : ''}`);
}
const PROFILES = {'non-mail': 'Does not handle mail', unreachable: 'DNS unreachable', nonexistent: 'Does not exist', mail: 'Handles mail'};
const APP = {
  tool: TOOL, subtitle: TITLE, title: TITLE,
  rowStatus: (r, c) => (r[ATTR[c]] || {}).status || 'missing',
  hasMeta: () => R.some(r => r.owner || r.bu || (r.tags && r.tags.length)) || new Set(R.map(r => r.tier)).size > 1,
  hasReports: R.some(r => r.dmarc_reports && r.dmarc_reports.status !== 'missing') || (D.unscanned_report_domains || []).length > 0,
  hasLook: CHECKS.includes('lookalikes'),
  hasAuth: ['spf', 'dkim', 'dmarc'].every(c => CHECKS.includes(c)),
  routes: [
    {id: 'lookalikes', label: 'Lookalikes', icon: 'copy', show: () => hasLook, count: () => lookRows().length},
    {id: 'reports', label: 'DMARC reports', icon: 'mail', show: () => hasReports}
  ],
  views: {lookalikes: () => lookView(), reports: () => reportsView()},
  search: (r, q) => r.domain.includes(q) || (r.owner || '').toLowerCase().includes(q) || (r.bu || '').toLowerCase().includes(q) || (r.tags || []).some(t => t.toLowerCase().includes(q)),
  legend: {null: 'Null MX', na: 'Not applicable', dns: 'DNS error or not verified'},
  domSub: r => esc([r.owner, r.bu].filter(Boolean).join(', ')),
  profiles: PROFILES,
  badges: {'non-mail': 'Does not handle mail', nonexistent: 'Domain does not exist', unreachable: 'DNS unreachable'},
  badgeNeutral: true,
  accountLabel: 'Account',
  kpiFirst: (kpi, n) => kpi(n, 'domains analyzed', '', 'data-route="domains"'),
  kpis: kpi => {
    const nonmail = R.filter(r => r.profile === 'non-mail').length, unreach = R.filter(r => r.profile === 'unreachable').length;
    return (nonmail && VIEW !== 'dns' ? kpi(nonmail, 'do not handle mail', '', 'data-filter="profile" data-value="non-mail"') : '')
      + (unreach ? kpi(unreach, 'DNS unreachable', '', 'data-filter="profile" data-value="unreachable"') : '');
  },
  accTitle: '', accSub: '',
  presets: () => [
    ...(hasMeta && R.some(r => r.tier === 'critical') ? [['tier1', 'Critical tier', {tier: 'critical'}]] : []),
    ...(CHECKS.includes('takeover') ? [['tko', 'Takeover exposure', {f: {takeover: 'error'}}]] : []),
    ...(hasAuth ? [['bulk', 'Fails Gmail/Yahoo rules', {comp: 'gmail_yahoo:fail'}]] : [])
  ],
  searchHint: 'Filter by domain, owner, unit or tag',
  groupKeys: {}, groupLabels: [],
  policies: {label: 'Policies', show: () => false, count: () => 0, render: () => ''},
  config: {checks: EVID, label: 'DNS evidence', render: r => dnsEvidence(r)},
  exposure: {checks: EXPO, label: 'Exposure', render: r => dnsExposure(r)},
  tabs: [{id: 'reports', label: 'DMARC reports', show: r => r.dmarc_reports.status !== 'missing', render: r => dnsReports(r)}],
  complianceNote: 'Only what DNS can show. Alignment, PTR, spam rate and unsubscribe headers need message-level checks.',
  fixes: r => sec('fixes', 'Suggested fixes', `<p class="sub" style="margin-bottom:12px">Review every value before publishing: these records are generated from the current configuration.</p>` +
    r.remediation.map((x, k) => `<div class="fix"><h4>${esc(x.title)}</h4>${x.name ? `<div class="where">${esc(x.type)} record at <span class="mono">${esc(x.name)}</span></div>` : ''}
      ${x.value ? `<div class="rowx"><pre class="record" id="fix-${r._i}-${k}">${esc(x.value)}</pre><button class="btn small copy" data-copy="fix-${r._i}-${k}">${icon('copy', 14)}Copy</button></div>` : ''}
      ${x.note ? `<p class="note">${esc(x.note)}</p>` : ''}</div>`).join('')),
  metaTags: r => r.bu ? `<span class="tag">${esc(r.bu)}</span>` : '',
  metaNote: r => r.scan_date ? `, scanned ${esc(r.scan_date)}` : '',
  aboutCount: 'Domains',
  csv: {head: ['domain'], row: r => [r.domain], file: 'mailguard-domains', selected: 'mailguard-selected.csv'},
  copyNoun: 'domains'
};
/* @include asset-app.js */
})();
