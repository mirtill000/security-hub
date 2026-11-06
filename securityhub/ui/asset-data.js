/* Shared data header of the asset reports (EDR, Proofpoint, SAP IAS, PRA): parses the embedded payload.
   Included by each app before its own module data and APP config, then asset-app.js. */
/* ================= data ================= */
const D = JSON.parse(document.getElementById('mg-data').textContent);
const R = D.results, CHECKS = D.checks, L = D.labels, M = D.meta || {};
const FIND = D.findings, FW = D.frameworks, COMP = D.compliance;
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
const $ = (s, r) => (r || document).querySelector(s);
const SEV = {critical: 0, warning: 1, info: 2};
const ST = {
  valid: ['pass', '\u2713', 'Pass'], warning: ['warn', '!', 'Warning'], partial: ['warn', '\u25D0', 'Partial'],
  error: ['fail', '\u2715', 'Fail'], misconfigured: ['fail', '\u2715', 'Misconfigured'], bogus: ['fail', '\u2715', 'Bogus'],
  missing: ['none', '\u2013', 'Missing'], null: ['null', '\u2205', 'Null'], na: ['na', '\u00B7', 'Not tested'],
  dns_error: ['dns', '?', 'Read error'], unknown: ['dns', '?', 'Not verified'], skipped: ['na', '\u00B7', 'Skipped']
};
if (typeof window.ST_LABELS === 'object') Object.entries(window.ST_LABELS).forEach(([k, v]) => { ST[k] = v; });
const ST_ORDER = ['valid', 'partial', 'warning', 'misconfigured', 'error', 'bogus', 'missing', 'null', 'na', 'dns_error', 'unknown', 'skipped'];
const TIER_ORDER = ['critical', 'high', 'medium', 'low'];
const cd = (r, c) => ((r.checks || {})[c] || {}).data || {};
const cap = s => s.charAt(0).toUpperCase() + s.slice(1);
