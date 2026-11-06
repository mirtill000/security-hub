
(function () {
'use strict';
/* @include core.js */
/* @include report-core.js */
/* @include asset-report.js */
window.ASSET_NOUN = ['user', 'users'];
/* @include asset-data.js */
/* ================= IASGuard: SAP Cloud Identity Services ================= */
const ACC = D.account_issues || [], POL = [], TOT = D.totals || {}, TENANT = D.tenant || '';
const SHORT = {signin: 'Sign-in', mfa: 'MFA', password: 'Password', activity: 'Activity', lifecycle: 'Validity', email: 'E-mail'};
const DETAIL = {
  signin: r => { const d = cd(r, 'signin'); return d.password_status === 'disabled' ? 'corporate IdP' : d.password_status ? 'IAS password' + (d.expected ? ' (expected)' : '') : ''; },
  mfa: r => { const d = cd(r, 'mfa'); return d.mfa === true ? 'enrolled' : d.mfa === false ? 'none' : ''; },
  password: r => { const d = cd(r, 'password'); return d.age_days !== undefined && d.age_days !== null ? `${d.age_days}d old` : ''; },
  activity: r => { const d = cd(r, 'activity'); return d.days !== undefined && d.days !== null ? (d.days === 0 ? 'today' : `${d.days}d ago`) : ''; },
  lifecycle: r => { const d = cd(r, 'lifecycle'); return d.valid_to ? 'until ' + String(d.valid_to).slice(0, 10) : ''; }
};
const APP = {
  tool: 'IASGuard', subtitle: 'SAP Cloud Identity', title: 'SAP Cloud Identity posture',
  domSub: r => esc([r.display_name !== r.domain ? r.display_name : '', r.user_id, r._acc, r.email].filter(Boolean).join(', ')),
  profiles: {expired: 'Expired but active', privileged: 'Privileged with IAS password', password: 'IAS password', inactive: 'Inactive', federated: 'Corporate sign-in only'},
  badges: {expired: 'Expired but active', privileged: 'Privileged with IAS password', password: 'IAS password', inactive: 'Inactive'},
  accountLabel: 'User type',
  kpiFirst: (kpi, n) => kpi(TOT.active || n, TOT.limited ? `active users (${n} listed)` : 'active users', '', 'data-route="domains"'),
  kpis: kpi => {
    const pwd = R.filter(r => r._codes.has('PASSWORD_LOGIN') || r._codes.has('PASSWORD_LOGIN_PRIVILEGED')).length, inactive = R.filter(r => r.profile === 'inactive').length;
    return kpi(TOT.federated || 0, 'corporate sign-in only', 'k-pass', 'data-filter="profile" data-value="federated"')
      + (pwd ? kpi(pwd, 'with an unexpected IAS password', 'k-fail', 'data-filter="profile" data-value="password"') : '')
      + (inactive ? kpi(inactive, 'inactive or never used', 'k-warn', 'data-filter="profile" data-value="inactive"') : '');
  },
  accTitle: 'Organization findings', accSub: 'across the organization',
  presets: () => [
  ...(R.some(r => r.profile === 'privileged') ? [['prv', 'Privileged with IAS password', {profile: 'privileged'}]] : []),
  ...(R.some(r => r.profile === 'password') ? [['pwd', 'IAS password', {profile: 'password'}]] : []),
  ...(R.some(r => r._codes.has('PASSWORD_NO_MFA')) ? [['mfa', 'No second factor', {finding: 'PASSWORD_NO_MFA'}]] : []),
  ...(R.some(r => r.profile === 'inactive') ? [['ina', 'Inactive', {profile: 'inactive'}]] : []),
  ...(R.some(r => r.profile === 'expired') ? [['exp', 'Expired but active', {profile: 'expired'}]] : []),
  ],
  searchHint: 'Filter by user name, user id, e-mail, type or group',
  groupKeys: {account: r => [r._acc || '(no type)'], group: r => (r.groups && r.groups.length ? r.groups : ['(no group)']), os: r => [r.password || '(unknown)']},
  groupLabels: [['account', 'User type'], ['group', 'Group'], ['os', 'Password status']],
  policies: {
    label: 'Directory', show: () => true, count: () => null,
    render: () => {
  const accHtml = ACC.length ? `<section class="card" style="margin-bottom:16px"><header><h2>Tenant findings</h2><p>Across the whole directory</p></header><div class="body">${issueList(ACC)}</div></section>` : '';
  const pct2 = (a, b) => b ? Math.round(100 * a / b) + '%' : '-';
  const totals = `<section class="card" style="margin-bottom:16px"><header><h2>Directory</h2><p>${esc(TENANT)}</p></header>
    <div class="body"><div class="kv">${kv('Active users', TOT.active)}${kv('Deactivated accounts (not assessed)', TOT.inactive_accounts)}${kv('Groups', TOT.groups)}
      ${kv('Corporate sign-in only', `${TOT.federated} (${pct2(TOT.federated, TOT.active)})`)}${kv('With a local IAS password', `${TOT.password_enabled} (${pct2(TOT.password_enabled, TOT.active)})`)}
      ${kv('of which not expected', TOT.password_unexpected)}${kv('Privileged users', TOT.privileged)}${kv('Users needing action', TOT.with_findings)}
      ${kv('Last sign-in exposed by the tenant', TOT.last_login_visible ? 'Yes' : 'No')}${kv('Second factor exposed by the tenant', TOT.mfa_visible ? 'Yes' : 'No')}</div>
      ${TOT.limited ? `<p class="sub" style="margin-top:10px">Large directory: the report lists the ${esc(TOT.listed)} users that need action; the figures above cover every user.</p>` : ''}</div></section>`;
  const types = Object.entries(TOT.by_type || {});
  const typeHtml = types.length ? `<section class="card"><header><h2>Users by type</h2></header><div class="body"><table><thead><tr><th>User type</th><th class="r">Active users</th></tr></thead><tbody>
    ${types.map(([t, n]) => `<tr><td><button class="link" data-group="account" data-value="${esc(t === '(none)' ? '' : t)}">${esc(t)}</button></td><td class="r num">${esc(n)}</td></tr>`).join('')}</tbody></table></div></section>` : '';
  return accHtml + totals + typeHtml;
    }
  },
  config: {
    checks: ['signin', 'mfa', 'password'], label: 'Authentication',
    render: r => {
  let h = '';
  const d0 = (v, unit) => v === null || v === undefined ? '' : `${v} ${unit}`;
  if (vis(r, 'signin')) { const d = cd(r, 'signin');
    h += sec('signin', 'Sign-in method', `<div class="kv">${kv('User name', r.domain)}${kv('User ID', r.user_id)}${kv('User type', r._acc)}${kv('Password status', d.password_status)}${kv('Privileged', yesNo(d.privileged))}</div>
      <p class="sub" style="margin-top:10px">${d.password_status === 'disabled' ? 'The user signs in only through the corporate identity provider, with its MFA and conditional access.' : d.expected ? 'Users of this type are expected to use an IAS password: only its hygiene is evaluated.' : 'With an IAS password the user can sign in without the corporate identity provider, so without its MFA and conditional access.'}</p>`, pill(r._st('signin'))); }
  if (vis(r, 'mfa')) { const d = cd(r, 'mfa');
    h += sec('mfa', 'Second factor', r._st('mfa') === 'na' ? '<p class="muted">Not applicable: the corporate identity provider enforces it.</p>' : r._st('mfa') === 'unknown' ? '<p class="muted">The tenant does not expose second-factor enrollment through SCIM: check the conditional authentication of the applications.</p>' : `<div class="kv">${kv('Second factor', yesNo(d.mfa))}</div>`, pill(r._st('mfa'))); }
  if (vis(r, 'password')) { const d = cd(r, 'password');
    h += sec('password', 'Password', r._st('password') === 'na' ? '<p class="muted">No local IAS password.</p>' : `<div class="kv">${kv('Status', d.status)}${kv('Age', d0(d.age_days, 'days'))}${kv('Policy', d.policy)}${kv('Failed sign-ins', d.failed)}</div>`, pill(r._st('password'))); }
  return h;
    }
  },
  exposure: {
    checks: ['activity', 'lifecycle', 'email'], label: 'Account',
    render: r => {
  let h = '';
  if (vis(r, 'activity')) { const d = cd(r, 'activity');
    h += sec('activity', 'Activity', r._st('activity') === 'unknown' ? '<p class="muted">The tenant does not expose the last sign-in time.</p>' : `<div class="kv">${kv('Last sign-in', d.last_login ? String(d.last_login).slice(0, 16).replace('T', ' ') : 'never')}${kv('Days ago', d.days)}${kv('Created', String(d.created || '').slice(0, 10))}</div>`, pill(r._st('activity'))); }
  if (vis(r, 'lifecycle')) { const d = cd(r, 'lifecycle');
    h += sec('lifecycle', 'Validity', `<div class="kv">${kv('Valid from', String(d.valid_from || '').slice(0, 10) || 'not set')}${kv('Valid to', String(d.valid_to || '').slice(0, 10) || 'not set')}</div>`, pill(r._st('lifecycle'))); }
  if (vis(r, 'email')) { const d = cd(r, 'email');
    h += sec('email', 'E-mail and groups', `<div class="kv">${kv('E-mail', d.email)}${kv('Verified', yesNo(d.verified))}${kv('Other accounts with the same e-mail', d.shared_with)}${kv('Groups', (r.groups || []).join(', ') || 'none')}</div>`, pill(r._st('email'))); }
  return h || '<p class="muted">No account data.</p>';
    }
  },
  indicative: 'based on the user attributes the tenant exposes through SCIM.',
  fixesIntro: 'Where to act in the SAP Cloud Identity Services administration console. Prefer fixing groups and applications (conditional authentication, password policy) over single users.',
  metaTags: r => `${r._acc ? `<span class="tag">Type ${esc(r._acc)}</span>` : ''}${r.user_id ? `<span class="tag">${esc(r.user_id)}</span>` : ''}`,
  aboutCount: 'Users listed',
  csv: {head: ['user_name', 'user_id', 'user_type'], row: r => [r.domain, r.user_id, r._acc], file: 'iasguard-users'},
  copyNoun: 'user names'
};
/* @include asset-app.js */
})();
