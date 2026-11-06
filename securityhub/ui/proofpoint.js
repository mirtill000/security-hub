
(function () {
'use strict';
/* @include core.js */
/* @include report-core.js */
/* @include asset-report.js */
window.ASSET_NOUN = ['domain', 'domains'];
/* @include asset-data.js */
/* ================= PPGuard: Proofpoint email protection ================= */
const ACC = D.account_issues || [], POL = [], PEOPLE = D.people || {}, THREATS = D.threats || [], TOT = D.totals || {}, WIN = D.window || {}, NOMAIL = D.no_mail || [], TAP = !!D.tap;
const SHORT = {routing: 'Routing', direct: 'Direct', spf: 'SPF', threats: 'Threats', clicks: 'Clicks', rewrite: 'URL Def.', people: 'People'};
const DETAIL = {
  routing: r => { const mx = cd(r, 'routing').mx || []; const pp = mx.filter(m => m.proofpoint).length; return mx.length ? `${pp}/${mx.length} MX via Proofpoint` : ''; },
  direct: r => cd(r, 'direct').m365_resolves ? 'Microsoft 365 reachable' : '',
  spf: r => { const d = cd(r, 'spf'); return d.record === undefined ? '' : d.proofpoint ? 'includes Proofpoint' : d.record ? '' : 'missing'; },
  threats: r => { const d = cd(r, 'threats'); return d.malicious ? `${d.malicious} delivered` : d.impostor ? `${d.impostor} impostor` : ''; },
  clicks: r => { const d = cd(r, 'clicks'); return d.malicious ? `${d.malicious} by ${(d.users || []).length} users` : ''; },
  rewrite: r => { const d = cd(r, 'rewrite'); return d.not_rewritten ? `${d.not_rewritten} not rewritten` : ''; },
  people: r => { const d = cd(r, 'people'); return d.vap_count ? `${d.vap_count} VAP` : ''; }
};
const tagc = (cls, text) => `<span class="pill s-${cls}">${esc(text)}</span>`;
const TP = D.tp || {}, POD = D.pod || {};
const pctTxt = v => v === null || v === undefined ? '-' : `${v}%`;
const pairs = (rows, head) => (rows || []).length ? `<table style="margin-top:10px"><thead><tr><th>${esc(head)}</th><th class="r">Messages</th></tr></thead><tbody>${rows.map(([k, n]) => `<tr><td class="mono">${esc(k)}</td><td class="r num">${esc(n)}</td></tr>`).join('')}</tbody></table>` : '';
function tpHtml() {
  if (!Object.keys(TP).length) return '';
  const q = TP.quarantines, u = TP.url_rewrite, ind = TP.industry, mb = TP.mail_bomb, vips = TP.bec_vips || [], per = TP.period || {};
  return `<section class="card" style="margin-bottom:16px"><header><h2>Threat Protection reports</h2><p>Last ${esc(per.days || '')} days, read-only</p></header><div class="body">
    <div class="kv">${q ? kv('Condemned copies pulled before being read', q.pulled_unread) + kv('Pulled after being read', q.pulled_read, q.pulled_read ? 'score lo' : '') + kv('Not pulled (skiplist / external)', q.skipped) : kv('Threat Response', 'not available')}
      ${u ? kv('URLs rewritten by URL Defense', pctTxt(u.coverage), u.coverage !== null && u.coverage < 95 ? 'score lo' : '') : ''}
      ${ind ? kv('Attack index (quarter from ' + ind.start_month + ')', ind.customer) + (ind.verticals || []).map(v => kv(v.name + ' average', v.attack_index)).join('') : ''}
      ${mb ? kv('Users targeted by email bombing', (mb.users || []).length || mb.total || 0, (mb.users || []).length ? 'score lo' : '') : ''}</div>
    ${u && (u.reasons || []).length ? `<table style="margin-top:12px"><thead><tr><th>Why URLs were not rewritten</th><th class="r">URLs</th></tr></thead><tbody>${u.reasons.map(r => `<tr><td>${esc(r.reason)}</td><td class="r num">${esc(r.urls)}</td></tr>`).join('')}</tbody></table>` : ''}
    ${vips.length ? `<table style="margin-top:12px"><thead><tr><th>VIP targeted by BEC</th><th>Risk</th><th class="r">BEC threats</th><th>Privileged</th><th>Takeover risk</th></tr></thead><tbody>${vips.slice(0, 50).map(v => `<tr><td>${esc(v.person || '?')}<div class="dom-sub">${esc([v.title, v.department].filter(Boolean).join(', '))}</div></td><td>${esc(v.riskExposure || '')}</td><td class="r num">${esc(v.becEmailThreats)}</td><td>${yesNo(v.isPrivileged)}</td><td>${v.ato ? tagc('fail', 'yes') : 'No'}</td></tr>`).join('')}</tbody></table>` : ''}
    ${mb && (mb.users || []).length ? `<table style="margin-top:12px"><thead><tr><th>Targeted by email bombing</th><th class="r">Events</th></tr></thead><tbody>${mb.users.map(x => `<tr><td>${esc(x.email || x.name || '?')}</td><td class="r num">${esc(x.events ?? '')}</td></tr>`).join('')}</tbody></table>` : ''}
    </div></section>`;
}
function podHtml() {
  if (!Object.keys(POD).length) return '';
  const m = POD.message, a = POD.audit, w = POD.window || {};
  let h = '';
  if (m) h += `<section class="card" style="margin-bottom:16px"><header><h2>Gateway: PoD message log</h2><p>Last ${esc(w.hours || '')} hours, ${esc(m.inbound)} inbound messages${m.truncated ? ' (sample)' : ''}</p></header><div class="body">
    <div class="kv">${kv('Failing SPF/DMARC and delivered', `${m.auth_failed_delivered} (${pctTxt(m.auth_failed_delivered_pct)})`, m.auth_failed_delivered_pct > 1 ? 'score lo' : '')}
      ${kv('Spoofing your domains (failed DMARC)', `${m.spoof}, delivered ${m.spoof_delivered}`, m.spoof_delivered ? 'score lo' : '')}
      ${kv('Received with TLS 1.2+', pctTxt(m.tls_pct), m.no_tls_pct > 5 ? 'score lo' : '')}${kv('URLs rewritten', pctTxt(m.url_coverage))}
      ${kv('Attachments not analyzed (sandbox errors)', m.sandbox_errors, m.sandbox_errors ? 'score lo' : '')}${kv('Messages with a virus', m.virus)}</div>
    ${pairs(m.auth_fail_senders, 'Delivered despite failing authentication: sender domain')}${pairs(m.spoofed_domains, 'Your domains used as sender (failed DMARC)')}
    ${pairs(m.no_tls_senders, 'Received without TLS 1.2+: sender')}
    ${Object.keys(m.no_rewrite_reasons || {}).length ? pairs(Object.entries(m.no_rewrite_reasons), 'URLs not rewritten: reason') : ''}
    ${Object.keys(m.dispositions || {}).length ? pairs(Object.entries(m.dispositions), 'Disposition') : ''}</div></section>`;
  if (a) h += `<section class="card" style="margin-bottom:16px"><header><h2>PoD console audit</h2><p>${esc((a.admins || []).length)} administrator(s) signed in, ${esc((a.counts || {}).events || 0)} events</p></header><div class="body">
    ${Object.keys(a.login_ips || {}).length ? `<table><thead><tr><th>Administrator</th><th>Sign-in IP addresses</th></tr></thead><tbody>${Object.entries(a.login_ips).map(([u, ips]) => `<tr><td>${esc(u)}</td><td class="mono sub">${esc(ips.join(', '))}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No sign-in in the window.</p>'}
    ${pairs(a.changes, 'Configuration change')}${(a.api_keys || []).length ? `<table style="margin-top:10px"><thead><tr><th>API key</th><th>Action</th><th>By</th><th>When</th></tr></thead><tbody>${a.api_keys.map(k => `<tr><td>${esc(k.name || '')}</td><td>${esc(k.action)}</td><td>${esc(k.by)}</td><td class="sub nowrap">${esc(String(k.time || '').slice(0, 16))}</td></tr>`).join('')}</tbody></table>` : ''}</div></section>`;
  return h;
}
const APP = {
  tool: 'PPGuard', subtitle: 'Proofpoint email protection', title: 'Proofpoint email protection posture',
  domSub: r => esc([r.gateway ? 'Gateway: ' + r.gateway : '', r._acc, r.source === 'tap' ? 'seen by TAP only' : '', r.owner, r.bu].filter(Boolean).join(', ')),
  profiles: {unprotected: 'Not routed via Proofpoint', bypass: 'MX bypass', clicked: 'Malicious click permitted', delivered: 'Threat delivered', protected: 'Protected'},
  badges: {unprotected: 'Not routed via Proofpoint', bypass: 'MX bypass', clicked: 'Malicious click permitted', delivered: 'Threat delivered'},
  accountLabel: 'Mailbox',
  kpiFirst: (kpi, n) => kpi(n, 'mail domains assessed', '', 'data-route="domains"'),
  kpis: kpi => {
    const bypass = R.filter(r => r.profile === 'unprotected' || r.profile === 'bypass').length;
    return (bypass ? kpi(bypass, 'domains bypassing Proofpoint', 'k-fail', 'data-filter="finding" data-value="' + (R.some(r => r.profile === 'unprotected') ? 'MX_NOT_PROOFPOINT' : 'MX_BYPASS') + '"') : '')
      + (TAP ? kpi(TOT.malicious || 0, `malicious delivered, ${WIN.hours || ''}h`, (TOT.malicious ? 'k-fail' : 'k-pass'), 'data-route="policies"') : '')
      + (TAP ? kpi(TOT.clicks_permitted || 0, 'malicious clicks permitted', (TOT.clicks_permitted ? 'k-fail' : 'k-pass'), 'data-filter="finding" data-value="CLICK_PERMITTED"') : '');
  },
  accTitle: 'Organization findings', accSub: 'across the organization',
  presets: () => [
  ...(hasMeta && R.some(r => r.tier === 'critical') ? [['tier1', 'Critical tier', {tier: 'critical'}]] : []),
  ...(R.some(r => r.profile === 'unprotected') ? [['unp', 'Not via Proofpoint', {profile: 'unprotected'}]] : []),
  ...(R.some(r => r.profile === 'bypass') ? [['byp', 'MX bypass', {profile: 'bypass'}]] : []),
  ...(R.some(r => r._codes.has('DIRECT_DELIVERY')) ? [['dir', 'Direct delivery to verify', {finding: 'DIRECT_DELIVERY'}]] : []),
  ...(R.some(r => r._codes.has('CLICK_PERMITTED')) ? [['clk', 'Clicks permitted', {finding: 'CLICK_PERMITTED'}]] : []),
  ],
  searchHint: 'Filter by domain, mailbox platform, owner or tag',
  groupKeys: {account: r => [r._acc || '(not identified)'], group: r => [r.gateway || '(unknown)'], os: r => [r.source || '(list)']},
  groupLabels: [['account', 'Mailbox platform'], ['group', 'Gateway'], ['os', 'Source']],
  policies: {
    label: 'People and threats', show: () => TAP || ACC.length > 0 || NOMAIL.length > 0 || Object.keys(TP).length > 0 || Object.keys(POD).length > 0, count: () => (PEOPLE.vap || []).length + THREATS.length,
    render: () => {
  const who = p => esc(p.name || (p.emails || [''])[0]) + (p.vip ? ' ' + tagc('warn', 'VIP') : '') + `<div class="dom-sub">${esc([(p.emails || [])[0], p.department, p.title].filter(Boolean).join(', '))}</div>`;
  const accHtml = ACC.length ? `<section class="card" style="margin-bottom:16px"><header><h2>Organization findings</h2><p>Across every domain</p></header><div class="body">${issueList(ACC)}</div></section>` : '';
  if (!TAP) return accHtml + tpHtml() + podHtml() + `<section class="card"><header><h2>TAP not available</h2></header><div class="body"><p class="muted">Delivered threats, clicks and people need the TAP API (PROOFPOINT_PRINCIPAL / PROOFPOINT_SECRET). Only the DNS routing checks were evaluated.</p>${NOMAIL.length ? `<p class="sub" style="margin-top:10px">Domains without MX, not assessed (${NOMAIL.length}): ${NOMAIL.slice(0, 50).map(esc).join(', ')}</p>` : ''}</div></section>`;
  const totals = `<section class="card" style="margin-bottom:16px"><header><h2>TAP in the last ${esc(WIN.hours)} hours</h2><p>${esc(String(WIN.start || '').slice(0, 16).replace('T', ' '))} to ${esc(String(WIN.end || '').slice(0, 16).replace('T', ' '))} UTC</p></header>
    <div class="body"><div class="kv">${kv('Messages blocked', TOT.blocked_messages)}${kv('Threat messages delivered', TOT.delivered)}${kv('of which malicious (active)', TOT.malicious)}${kv('Malicious clicks permitted', TOT.clicks_permitted)}${kv('Clicks blocked', TOT.blocked_clicks)}
      ${kv('Malicious clicks blocked by URL Defense', TOT.click_block_rate === null || TOT.click_block_rate === undefined ? '-' : TOT.click_block_rate + '%', TOT.click_block_rate !== null && TOT.click_block_rate < 90 ? 'score lo' : '')}
      ${kv('Users with repeated permitted clicks', TOT.repeat_clickers || 0, TOT.repeat_clickers ? 'score lo' : '')}
      ${TOT.exposure_hours ? kv('Time in the mailbox before the verdict (median / max)', `${TOT.exposure_hours.median} h / ${TOT.exposure_hours.max} h`, TOT.exposure_hours.median >= 1 ? 'score lo' : '') : ''}</div></div></section>`;
  const thr = `<section class="card" style="margin-bottom:16px"><header><h2>Threats that reached users</h2><p>${THREATS.length} threat${THREATS.length === 1 ? '' : 's'}, most clicked first</p></header><div class="body">
    ${THREATS.length ? `<table><thead><tr><th>Classification</th><th>Type</th><th class="r">Messages</th><th class="r">Recipients</th><th class="r">Clicks</th><th>Campaign</th><th>TAP</th></tr></thead><tbody>${THREATS.map(t => `<tr>
      <td>${tagc(t.classification === 'impostor' ? 'warn' : 'fail', t.classification)}</td><td class="sub">${esc(t.type)}</td><td class="r num">${esc(t.messages)}</td><td class="r num">${esc(t.recipients)}</td>
      <td class="r num">${t.clicks ? `<b class="tx-bad">${esc(t.clicks)}</b>` : '0'}</td><td class="sub mono">${esc(t.campaign || '')}</td>
      <td>${/^https:\/\/threatinsight\.proofpoint\.com\//.test(String(t.url || '')) ? `<a href="${esc(t.url)}" target="_blank" rel="noopener noreferrer">Open</a>` : ''}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No malicious or impostor message delivered in the window.</p>'}</div></section>`;
  const vap = PEOPLE.vap || [], top = PEOPLE.top_clickers || [];
  const vapHtml = `<section class="card" style="margin-bottom:16px"><header><h2>Very Attacked People</h2><p>${vap.length} user${vap.length === 1 ? '' : 's'} over ${esc(PEOPLE.window_days)} days${PEOPLE.threshold ? `, attack index threshold ${esc(PEOPLE.threshold)}` : ''}</p></header><div class="body">
    ${PEOPLE.vap === null ? '<p class="muted">The People API could not be read.</p>' : vap.length ? `<table><thead><tr><th>User</th><th class="r">Attack index</th><th>Threat families</th></tr></thead><tbody>${vap.slice(0, 200).map(p => `<tr><td>${who(p)}</td><td class="r num">${esc(p.attack_index)}</td><td class="sub">${esc((p.families || []).join(', '))}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No Very Attacked People in the window.</p>'}</div></section>`;
  const topHtml = `<section class="card" style="margin-bottom:16px"><header><h2>Top clickers</h2><p>Users who clicked on threats (permitted or blocked) over ${esc(PEOPLE.window_days)} days</p></header><div class="body">
    ${PEOPLE.top_clickers === null ? '<p class="muted">The People API could not be read.</p>' : top.length ? `<table><thead><tr><th>User</th><th class="r">Clicks</th><th>Threat families</th></tr></thead><tbody>${top.slice(0, 200).map(p => `<tr><td>${who(p)}</td><td class="r num">${esc(p.clicks)}</td><td class="sub">${esc((p.families || []).join(', '))}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No top clickers in the window.</p>'}</div></section>`;
  const nomail = NOMAIL.length ? `<section class="card"><header><h2>Domains without MX</h2><p>${NOMAIL.length} domain${NOMAIL.length === 1 ? '' : 's'} that receive no mail: not assessed</p></header><div class="body"><div class="tree mono">${NOMAIL.slice(0, 500).map(esc).join('<br>')}</div></div></section>` : '';
  return accHtml + totals + tpHtml() + podHtml() + thr + vapHtml + topHtml + nomail;
    }
  },
  config: {
    checks: ['routing', 'direct', 'spf'], label: 'Mail routing',
    render: r => {
  let h = '';
  if (vis(r, 'routing')) { const d = cd(r, 'routing'), mx = d.mx || [];
    h += sec('routing', 'MX records', mx.length ? `<table><thead><tr><th class="r">Pref.</th><th>Host</th><th>Gateway</th><th>How recognized</th></tr></thead><tbody>${mx.map(m => `<tr><td class="r num">${esc(m.preference)}</td><td class="mono">${esc(m.host)}</td>
      <td>${m.proofpoint ? tagc('pass', 'Proofpoint') : tagc('fail', m.platform || 'not Proofpoint')}</td><td class="sub">${esc(m.how || (m.resolves === false ? 'host does not resolve' : ''))}</td></tr>`).join('')}</tbody></table>
      <p class="sub" style="margin-top:10px">Mail is delivered to the lowest preference first, but senders may use any MX: every MX must be Proofpoint.</p>`
      : `<p class="muted">${d.mx_status === 'error' ? 'MX records could not be read.' : 'No MX record.'}</p>`, pill(r._st('routing'))); }
  if (vis(r, 'direct')) { const d = cd(r, 'direct');
    h += sec('direct', 'Direct delivery', d.m365_host ? `<div class="kv">${kv('Microsoft 365 endpoint', d.m365_host)}${kv('Resolves', yesNo(d.m365_resolves))}${kv('Domain verified in a Microsoft 365 tenant (MS= record)', yesNo(d.m365_verified))}</div>
      <p class="sub" style="margin-top:10px">If the endpoint resolves, attackers can send to it directly and skip Proofpoint unless Exchange Online rejects mail that does not arrive through the Proofpoint connector. This cannot be seen from outside: verify the connector and the rule.</p>`
      : '<p class="muted">Not applicable: the domain is not routed through Proofpoint.</p>', pill(r._st('direct'))); }
  if (vis(r, 'spf')) { const d = cd(r, 'spf');
    h += sec('spf', 'SPF', d.record !== undefined ? `<pre class="record">${esc(d.record || '(no SPF record)')}</pre><div class="kv" style="margin-top:10px">${kv('Authorizes Proofpoint', yesNo(d.proofpoint))}</div>` : '<p class="muted">Not read.</p>', pill(r._st('spf'))); }
  return h || '<p class="muted">DNS routing was not assessed.</p>';
    }
  },
  exposure: {
    checks: ['threats', 'clicks', 'rewrite', 'people'], label: 'Threats and clicks',
    render: r => {
  let h = '';
  const tapLink = u => /^https:\/\/threatinsight\.proofpoint\.com\//.test(String(u || '')) ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">TAP</a>` : '';
  if (vis(r, 'threats')) { const d = cd(r, 'threats'), ms = d.messages || [];
    h += sec('threats', 'Delivered threats', r._st('threats') === 'na' ? '<p class="muted">Not applicable: mail is not routed through Proofpoint, TAP does not see it.</p>' : ms.length ? `<div class="kv" style="margin-bottom:10px">${kv('Malicious messages delivered', d.malicious)}${kv('Recipients', d.recipients)}${kv('Impostor', d.impostor)}${kv('Through safelist routes', d.safelisted)}</div>
      <table><thead><tr><th>When</th><th>Threat</th><th>Recipients</th><th>From domain</th><th>Policy routes</th><th></th></tr></thead><tbody>${ms.map(m => `<tr><td class="nowrap sub">${esc(String(m.time || '').slice(0, 16).replace('T', ' '))}</td>
        <td>${(m.threats || []).map(t => tagc(t.classification === 'impostor' ? 'warn' : 'fail', `${t.classification} ${t.type || ''}`)).join(' ')}</td><td class="sub">${esc((m.recipients || []).join(', '))}</td>
        <td class="mono sub">${esc(m.from_domain || '')}</td><td class="sub">${esc((m.routes || []).join(', '))}</td><td>${tapLink(((m.threats || [])[0] || {}).url)}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No malicious message delivered in the window.</p>', pill(r._st('threats'))); }
  if (vis(r, 'clicks')) { const d = cd(r, 'clicks'), cs = d.clicks || [];
    h += sec('clicks', 'Permitted clicks', r._st('clicks') === 'na' ? '<p class="muted">Not applicable.</p>' : cs.length ? `<table><thead><tr><th>When</th><th>User</th><th>Threat</th><th>Campaign</th><th></th></tr></thead><tbody>${cs.map(c => `<tr><td class="nowrap sub">${esc(String(c.time || '').slice(0, 16).replace('T', ' '))}</td>
        <td>${esc(c.recipient)}</td><td>${tagc('fail', c.classification)}</td><td class="sub mono">${esc(c.campaign || '')}</td><td>${tapLink(c.url)}</td></tr>`).join('')}</tbody></table>
      <p class="sub" style="margin-top:10px">The URL was malicious and the click was allowed: treat the user as potentially compromised.</p>` : '<p class="muted">No malicious click permitted in the window.</p>', pill(r._st('clicks'))); }
  if (vis(r, 'rewrite')) { const d = cd(r, 'rewrite');
    h += sec('rewrite', 'URL Defense', d.url_messages ? `<div class="kv">${kv('Delivered messages with URL threats', d.url_messages)}${kv('Not completely rewritten', d.not_rewritten)}</div>` : '<p class="muted">No delivered message with URL threats: nothing to measure.</p>', pill(r._st('rewrite'))); }
  if (vis(r, 'people')) { const d = cd(r, 'people'), ps = d.vap || [];
    h += sec('people', 'Very Attacked People', ps.length ? `<table><thead><tr><th>User</th><th class="r">Attack index</th><th>Families</th></tr></thead><tbody>${ps.map(p => `<tr><td>${esc(p.name || (p.emails || [''])[0])}${p.vip ? ' ' + tagc('warn', 'VIP') : ''}<div class="dom-sub">${esc([(p.emails || [])[0], p.department, p.title].filter(Boolean).join(', '))}</div></td>
      <td class="r num">${esc(p.attack_index)}</td><td class="sub">${esc((p.families || []).join(', '))}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No Very Attacked People in this domain.</p>', pill(r._st('people'))); }
  return h || '<p class="muted">TAP data was not available for this domain.</p>';
    }
  },
  indicative: 'based on public DNS and on the TAP events of the window.',
  fixesIntro: 'Where to act: DNS, the Proofpoint admin portal, the TAP dashboard or the mailbox service. Fix routing first: it decides whether the other controls apply at all.',
  metaTags: r => `${r.gateway ? `<span class="tag">Gateway ${esc(r.gateway)}</span>` : ''}${r._acc ? `<span class="tag">${esc(r._acc)}</span>` : ''}`,
  csv: {head: ['domain', 'gateway', 'mailbox_platform'], row: r => [r.domain, r.gateway, r._acc], file: 'ppguard-domains'},
  copyNoun: 'domains'
};
/* @include asset-app.js */
})();
