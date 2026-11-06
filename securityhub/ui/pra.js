
(function () {
'use strict';
/* @include core.js */
/* @include report-core.js */
/* @include asset-report.js */
window.ASSET_NOUN = ['object', 'objects'];
/* @include asset-data.js */
/* ================= PRAGuard: BeyondTrust Privileged Remote Access ================= */
const ACC = D.account_issues || [], POL = [], TOT = D.totals || {}, SITE = D.site || '';
const SHORT = {authentication: 'Auth', privileges: 'Privileges', lifecycle: 'Lifecycle', access_policy: 'Policy', exposure: 'Exposure'};
const DETAIL = {
  authentication: r => { const d = cd(r, 'authentication'); return d.provider ? d.provider : d.allow_list !== undefined ? (d.allow_list ? 'IP allow list' : 'no allow list') : ''; },
  privileges: r => { const d = cd(r, 'privileges'); return d.admin ? 'admin' : (d.sensitive || []).length ? `${d.sensitive.length} sensitive` : (d.checkout_groups || []).length ? 'checkout' : ''; },
  lifecycle: r => { const d = cd(r, 'lifecycle'); return d.days !== undefined && d.days !== null ? `${d.days}d ago` : d.policy || ''; },
  access_policy: r => cd(r, 'access_policy').policy || (r.kind === 'asset' ? 'no policy' : ''),
  exposure: r => cd(r, 'exposure').type || ''
};
const PRA_LABELS = {provider: 'Security provider', provider_type: 'Provider type', mfa: 'MFA', two_factor_type: 'MFA requirement', admin: 'Administrator',
  vault_admin: 'Vault administrator', last_sign_in: 'Last sign-in', days: 'Days since sign-in', created: 'Created', expires: 'Account expiration', vendor: 'Vendor group',
  vendor_admin: 'Vendor administrator', allow_list: 'Network allow list', command: 'Command API', configuration: 'Configuration API', sensitive: 'Sensitive permissions',
  checkout_groups: 'Group policies with checkout', policy: 'Policy', recording: 'Sessions recorded', approval: 'Approval required', schedule: 'Schedule',
  mfa_challenge: 'MFA challenge', group_type: 'Asset group', type: 'Type', host: 'Host', protocol: 'Protocol', tag: 'Tag', connected: 'Connected',
  clustered: 'Clustered', proxy: 'Proxy enabled'};
const fmtV = v => v === true ? 'Yes' : v === false ? 'No' : Array.isArray(v) ? (v.length ? v.join(', ') : 'none') : v === null || v === undefined || v === '' ? '-'
  : /^\d{4}-\d\d-\d\dT\d\d:\d\d/.test(String(v)) ? String(v).slice(0, 16).replace('T', ' ') : String(v);  // dates only
function checkSec(r, c) {
  const d = cd(r, c), keys = Object.keys(d);
  return sec(c, L[c], keys.length ? `<div class="kv">${keys.map(k => kv(PRA_LABELS[k] || k, fmtV(d[k]))).join('')}</div>` : '<p class="muted">No data.</p>', pill(r._st(c)));
}
const APP = {
  tool: 'PRAGuard', subtitle: 'BeyondTrust PRA', title: 'BeyondTrust PRA posture',
  domSub: r => esc([r._acc, r.detail].filter(Boolean).join(' \u00b7 ')),
  profiles: {critical: 'Critical findings', attention: 'Needs attention', ok: 'No findings'},
  badges: {critical: 'Critical findings'},
  accountLabel: 'User type',
  kpiFirst: (kpi, n) => kpi(n, TOT.limited ? `objects listed (only those needing action)` : 'objects assessed', '', 'data-route="domains"'),
  kpis: kpi => {
    const kindN = k => R.filter(r => r.kind === k).length, nomfa = R.filter(r => r._codes.has('ADMIN_NO_MFA') || r._codes.has('VENDOR_NO_MFA') || r._codes.has('USER_NO_MFA')).length, unrec = R.filter(r => r._codes.has('ASSET_RECORDING_OFF') || r._codes.has('ASSET_NO_POLICY')).length;
    return (nomfa ? kpi(nomfa, 'people without MFA', 'k-fail', 'data-filter="finding" data-value="' + (R.some(r => r._codes.has('ADMIN_NO_MFA')) ? 'ADMIN_NO_MFA' : R.some(r => r._codes.has('VENDOR_NO_MFA')) ? 'VENDOR_NO_MFA' : 'USER_NO_MFA') + '"') : '')
      + (unrec ? kpi(unrec, 'assets without recording or policy', 'k-fail', 'data-filter="profile" data-value="critical"') : '')
      + kpi(kindN('vendor_user'), 'vendor users', '', 'data-filter="account" data-value="Vendor user"');
  },
  accTitle: 'Organization findings', accSub: 'across the organization',
  critPreset: [['crit', 'Critical findings', {profile: 'critical'}]],
  presets: () => [
  ...[['user', 'Users'], ['vendor_user', 'Vendor users'], ['asset', 'Assets'], ['gateway', 'Gateways'], ['api_account', 'API accounts'], ['vault_account', 'Vault accounts']]
    .filter(([k]) => R.some(r => r.kind === k)).map(([k, l]) => [k, l, {account: R.find(r => r.kind === k)._acc}]),
  ],
  searchHint: 'Filter by name, kind, host or finding',
  groupKeys: {account: r => [r._acc || '(kind)'], group: r => [r.profile], os: r => [(cd(r, 'access_policy').policy) || '(no policy)']},
  groupLabels: [['account', 'Kind'], ['group', 'Status'], ['os', 'Asset policy']],
  policies: {
    label: 'Site', show: () => true, count: () => null,
    render: () => {
  const accHtml = ACC.length ? `<section class="card" style="margin-bottom:16px"><header><h2>Site findings</h2><p>Security providers, group policies, vendor groups, sessions</p></header><div class="body">${issueList(ACC)}</div></section>` : '';
  const kinds = Object.entries(TOT.objects || {});
  const names = {user: 'Users', vendor_user: 'Vendor users', asset: 'Assets', gateway: 'Gateways', api_account: 'API accounts', vault_account: 'Vault accounts'};
  const objHtml = `<section class="card" style="margin-bottom:16px"><header><h2>Objects</h2><p>${esc(SITE)}</p></header><div class="body"><div class="kv">${kinds.map(([k, n]) => kv(names[k] || k, n)).join('')}${kv('Disabled users (not assessed)', TOT.users_disabled)}</div>
    ${TOT.limited ? `<p class="sub" style="margin-top:10px">Large site: only the ${esc(TOT.listed)} objects that need action are listed.</p>` : ''}</div></section>`;
  const s = TOT.sessions;
  const sessHtml = s ? `<section class="card"><header><h2>Sessions in the last ${esc(s.days)} days</h2></header><div class="body"><div class="kv">${kv('Sessions', s.total)}${kv('Not recorded', s.unrecorded)}${kv('By vendor users', s.by_vendors)}${kv('With file transfers', s.file_transfers)}</div>
    ${(s.top_users || []).length ? `<table style="margin-top:12px"><thead><tr><th>Most active users</th><th class="r">Sessions</th></tr></thead><tbody>${s.top_users.map(([u, n]) => `<tr><td>${esc(u)}</td><td class="r num">${esc(n)}</td></tr>`).join('')}</tbody></table>` : ''}
    ${(s.top_endpoints || []).length ? `<table style="margin-top:12px"><thead><tr><th>Most accessed endpoints</th><th class="r">Sessions</th></tr></thead><tbody>${s.top_endpoints.map(([u, n]) => `<tr><td>${esc(u)}</td><td class="r num">${esc(n)}</td></tr>`).join('')}</tbody></table>` : ''}</div></section>`
    : '<section class="card"><header><h2>Sessions</h2></header><div class="body"><p class="muted">The session report could not be read (Reporting API permission).</p></div></section>';
  return accHtml + objHtml + sessHtml;
    }
  },
  config: {
    checks: ['authentication', 'privileges', 'lifecycle'], label: 'Identity and access',
    render: r => APP.config.checks.filter(c => vis(r, c)).map(c => checkSec(r, c)).join('') || '<p class="muted">Not applicable to this object.</p>'
  },
  exposure: {
    checks: ['access_policy', 'exposure'], label: 'Policy and exposure',
    render: r => APP.exposure.checks.filter(c => vis(r, c)).map(c => checkSec(r, c)).join('') || '<p class="muted">Not applicable to this object.</p>'
  },
  indicative: 'based on the PRA configuration read through the API.',
  fixesIntro: 'Where to act: the /login administrative interface or the Access Console. Fixing a group policy or an asset policy fixes every user or asset that uses it.',
  metaTags: r => `${r._acc ? `<span class="tag">${esc(r._acc)}</span>` : ''}${r.detail ? `<span class="tag">${esc(r.detail)}</span>` : ''}`,
  aboutCount: 'Objects listed',
  csv: {head: ['name', 'kind', 'detail'], row: r => [r.domain, r._acc, r.detail], file: 'praguard-objects'},
  copyNoun: 'names'
};
/* @include asset-app.js */
})();
