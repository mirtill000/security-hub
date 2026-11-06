
(function () {
'use strict';
/* @include core.js */
/* @include report-core.js */
/* @include asset-report.js */
window.ASSET_NOUN = ['endpoint', 'endpoints'];
/* @include asset-data.js */
/* ================= EDRGuard: SentinelOne EDR ================= */
const ACC = D.account_issues || [], POL = D.policies || [], EXC = D.exclusions || [], COV = D.coverage || null;
const SHORT = {health: 'Health', protection: 'Mode', policy: 'Policy', version: 'Version', threats: 'Threats', vulnerabilities: 'Vulns', scan: 'Scan'};
const DETAIL = {
  health: r => { const d = cd(r, 'health'); return d.last_seen_days === null || d.last_seen_days === undefined ? '' : d.last_seen_days === 0 ? 'seen today' : `seen ${d.last_seen_days}d ago`; },
  protection: r => cd(r, 'protection').mode || '',
  policy: r => { const d = cd(r, 'policy'); return d.anti_tamper === false ? 'anti-tamper off' : (d.engines_off || []).length ? `${d.engines_off.length} engines off` : (d.scope || ''); },
  version: r => cd(r, 'version').agent_version || '',
  threats: r => { const d = cd(r, 'threats'); return d.open ? `${d.active || 0} active, ${d.open} open` : ''; },
  vulnerabilities: r => cd(r, 'vulnerabilities').status || ''
};
const APP = {
  tool: 'EDRGuard', subtitle: 'SentinelOne EDR posture', title: 'SentinelOne EDR posture',
  domSub: r => esc([r.os, r._acc, r.group_name, r.owner, r.bu].filter(Boolean).join(', ')),
  profiles: {threat: 'Active threat', detect: 'Detect mode only', stale: 'Not seen recently', disabled: 'Agent disabled', protected: 'Protected'},
  badges: {threat: 'Active threat', detect: 'Detect mode only', stale: 'Not seen recently', disabled: 'Agent disabled'},
  accountLabel: 'Account',
  kpis: kpi => {
    const detect = R.filter(r => r.profile === 'detect').length, stale = R.filter(r => r.profile === 'stale' || r.profile === 'disabled').length;
    return (detect ? kpi(detect, 'in detect mode only', 'k-fail', 'data-filter="profile" data-value="detect"') : '')
      + (stale ? kpi(stale, 'stale or disabled agents', 'k-warn', 'data-filter="profile" data-value="stale"') : '');
  },
  accTitle: 'Console findings', accSub: 'affecting every endpoint',
  presets: () => [
    ...(hasMeta && R.some(r => r.tier === 'critical') ? [['tier1', 'Critical tier', {tier: 'critical'}]] : []),
    ...(R.some(r => r.profile === 'detect') ? [['det', 'Detect mode', {profile: 'detect'}]] : []),
    ...(R.some(r => r.profile === 'stale') ? [['stl', 'Not seen recently', {profile: 'stale'}]] : []),
    ...(CHECKS.includes('threats') && R.some(r => r._st('threats') === 'error') ? [['thr', 'Active threats', {f: {threats: 'error'}}]] : [])
  ],
  searchHint: 'Filter by hostname, site, group, owner or tag',
  groupKeys: {account: r => [r._acc || '(site)'], group: r => [r.group_name || '(group)'], os: r => [r.os_type || '(os)']},
  groupLabels: [['account', 'Site'], ['group', 'Group'], ['os', 'Operating system']],
  policies: {
    label: 'Policies and exclusions', show: () => POL.length > 0 || EXC.length > 0 || ACC.length > 0 || !!COV, count: () => POL.length + EXC.length,
    render: () => {
  const onoff = v => v === true ? pill('valid', 'on') : v === false ? pill('error', 'off') : '<span class="faint">-</span>';
  const mode = v => v ? (String(v).toLowerCase() === 'protect' ? pill('valid', 'Protect') : pill('error', 'Detect')) : '<span class="faint">-</span>';
  const accHtml = ACC.length ? `<section class="card" style="margin-bottom:16px"><header><h2>Console findings</h2><p>Configuration that affects many endpoints</p></header><div class="body">${issueList(ACC)}</div></section>` : '';
  const covHtml = COV ? `<section class="card" style="margin-bottom:16px"><header><h2>Coverage against the inventory</h2><p>${COV.covered} of ${COV.inventory} expected hosts have an agent</p></header>
    <div class="body">${COV.missing.length ? `<p class="sub" style="margin-bottom:8px">Hosts without a SentinelOne agent (${COV.missing.length}):</p><div class="tree mono">${COV.missing.slice(0, 500).map(esc).join('<br>')}</div>` : '<p class="muted">Every host in the inventory has an agent.</p>'}</div></section>` : '';
  const pol = `<div class="grid-wrap" style="margin-bottom:16px"><table class="grid"><thead><tr><th class="sticky" style="min-width:200px">Policy</th><th>Malicious</th><th>Suspicious</th><th>Anti-tamper</th><th>Snapshots</th><th>Engines off</th><th>Auto mitigation</th><th class="r">Endpoints</th></tr></thead><tbody>
    ${POL.map(p => `<tr><td class="sticky" style="min-width:200px"><button class="dom" style="word-break:normal" data-policy="${esc(p.id)}">${esc(p.name)}</button><div class="dom-sub">${esc(p.type)} policy</div></td>
      <td>${mode(p.mode)}</td><td>${mode(p.suspicious_mode)}</td><td>${onoff(p.anti_tamper)}</td><td>${onoff(p.snapshots)}</td>
      <td class="sub">${(p.engines_off || []).length ? esc(p.engines_off.join(', ')) : '<span class="faint">none</span>'}</td><td class="sub">${esc(String(p.auto_mitigation || '').replace('mitigation.', ''))}</td><td class="r num">${esc(p.in_scan)}</td></tr>`).join('')
      || '<tr><td colspan="8" class="empty">No policy could be read.</td></tr>'}</tbody></table></div>`;
  const risky = EXC.filter(x => x.risk), shown = [...risky, ...EXC.filter(x => !x.risk)].slice(0, 500);
  const exc = `<section class="card"><header><h2>Exclusions</h2><p>${EXC.length} exclusion${EXC.length === 1 ? '' : 's'}, ${risky.length} risky</p></header><div class="body">
    ${EXC.length ? `<table><thead><tr><th>Type</th><th>Value</th><th>Mode</th><th>Scope</th><th>Risk</th><th>Description</th></tr></thead><tbody>${shown.map(x => `<tr><td>${esc(x.type)}</td><td class="mono">${esc(x.value)}</td>
      <td class="sub">${esc(x.mode || x.pathExclusionType || '')}</td><td class="sub">${esc(x.scopeName || x.scope || '')}</td>
      <td>${x.risk ? pill(x.risk === 'critical' ? 'error' : 'warning', x.reason) : '<span class="faint">-</span>'}</td><td class="sub">${esc(x.description) || '<span class="faint">none</span>'}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No exclusions returned by the console.</p>'}</div></section>`;
  return accHtml + covHtml + pol + exc;
    }
  },
  config: {
    checks: ['health', 'protection', 'policy', 'version'], label: 'Agent and policy',
    render: r => {
  let h = '';
  if (vis(r, 'health')) { const d = cd(r, 'health');
    h += sec('health', 'Agent', `<div class="kv">${kv('Host name', r.domain)}${kv('Operating system', r.os)}${kv('Machine type', r.machine_type)}${kv('Site', r._acc)}${kv('Group', r.group_name)}
      ${kv('Last seen', d.last_seen ? `${String(d.last_seen).slice(0, 16).replace('T', ' ')} (${d.last_seen_days} days ago)` : '')}${kv('Network status', d.network)}${kv('Operational state', d.operational_state)}
      ${kv('Actions needed', (d.actions_needed || []).join(', ') || 'none')}${kv('Missing permissions', (d.missing_permissions || []).join(', ') || 'none')}${kv('Registered', String(d.registered || '').slice(0, 10))}</div>`, pill(r._st('health'))); }
  if (vis(r, 'protection')) { const d = cd(r, 'protection');
    h += sec('protection', 'Protection mode', `<div class="kv">${kv('Malicious threats', d.mode)}${kv('Suspicious threats', d.suspicious_mode)}</div>
      <p class="sub" style="margin-top:10px">Detect only raises alerts: the threat keeps running until an analyst acts.</p>`, pill(r._st('protection'))); }
  if (vis(r, 'policy')) { const d = cd(r, 'policy'), eng = Object.entries(d.engines || {});
    h += sec('policy', 'Policy', d.scope === null || d.scope === undefined ? '<p class="muted">The policy of this endpoint could not be read: it is not counted as failed.</p>' :
      `<p class="sub" style="margin-bottom:10px">Effective policy: <b>${esc(d.scope)}</b></p><div class="kv">${kv('Anti-tamper', yesNo(d.anti_tamper))}${kv('Snapshots (rollback)', yesNo(d.snapshots))}${kv('Auto mitigation', String(d.auto_mitigation || '').replace('mitigation.', ''))}</div>
      ${eng.length ? `<table style="margin-top:12px"><thead><tr><th>Engine</th><th>State</th></tr></thead><tbody>${eng.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${String(v).toLowerCase() === 'on' ? pill('valid', 'on') : pill('error', String(v))}</td></tr>`).join('')}</tbody></table>` : ''}`, pill(r._st('policy'))); }
  if (vis(r, 'version')) { const d = cd(r, 'version');
    h += sec('version', 'Agent version', `<div class="kv">${kv('Installed', d.agent_version)}${kv('Latest GA for the platform', d.latest_ga || 'not available')}${kv('Up to date (console)', yesNo(d.up_to_date))}</div>`, pill(r._st('version'))); }
  return h;
    }
  },
  exposure: {
    checks: ['threats', 'vulnerabilities', 'scan'], label: 'Threats and vulnerabilities',
    render: r => {
  let h = '';
  if (vis(r, 'threats')) { const d = cd(r, 'threats'), ts = d.threats || [];
    h += sec('threats', 'Open threats', ts.length ? `<table><thead><tr><th>Threat</th><th>Classification</th><th>Confidence</th><th>Mitigation</th><th>Incident</th><th>Created</th></tr></thead><tbody>
      ${ts.map(t => `<tr><td class="mono">${esc(t.name)}</td><td class="sub">${esc(t.classification)}</td><td>${esc(t.confidence)}</td><td>${['mitigated', 'blocked', 'marked_as_benign'].includes(String(t.mitigation)) ? pill('valid', t.mitigation) : pill('error', t.mitigation || 'not mitigated')}</td>
        <td class="sub">${esc(t.incident)}${t.verdict && t.verdict !== 'undefined' ? ', ' + esc(t.verdict) : ''}</td><td class="nowrap sub">${esc(String(t.created || '').slice(0, 10))}</td></tr>`).join('')}</tbody></table>`
      : `<p class="muted">${d.agent_active_threats ? esc(d.agent_active_threats) + ' active threats reported by the agent (details not available).' : 'No open threats.'}</p>`, pill(r._st('threats'))); }
  if (vis(r, 'vulnerabilities')) { const d = cd(r, 'vulnerabilities');
    h += sec('vulnerabilities', 'Vulnerable applications', `<div class="kv">${kv('Status', d.status || 'not available')}</div>`, pill(r._st('vulnerabilities'))); }
  if (vis(r, 'scan')) { const d = cd(r, 'scan');
    h += sec('scan', 'Full disk scan', `<div class="kv">${kv('Status', d.status || 'not available')}${kv('Finished', String(d.finished || '').slice(0, 10))}</div>`, pill(r._st('scan'))); }
  return h || '<p class="muted">No threat or vulnerability data for this endpoint.</p>';
    }
  },
  indicative: 'based on the agent state and the policies read from the SentinelOne console.',
  fixesIntro: 'Where to act in the SentinelOne management console. Prefer changing the site or group policy: it fixes every endpoint that uses it.',
  metaTags: r => `${r.os ? `<span class="tag">${esc(r.os)}</span>` : ''}${r._acc ? `<span class="tag">Site ${esc(r._acc)}</span>` : ''}${r.group_name ? `<span class="tag">Group ${esc(r.group_name)}</span>` : ''}`,
  metaNote: r => r.agent_version ? ', agent ' + esc(r.agent_version) : '',
  csv: {head: ['hostname', 'agent_id', 'site'], row: r => [r.domain, r.site_id, r._acc], file: 'edrguard-endpoints'},
  copyNoun: 'hostnames'
};
/* @include asset-app.js */
})();
