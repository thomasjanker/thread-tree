'use strict';
// Pure formatting helpers (no DOM, no translations), tested outside a browser.

function trimZero(text) {
  return text.replace(/\.0$/, '');
}

function fmtDuration(sec) {
  if (sec === null || sec === undefined || Number.isNaN(sec)) return '–';
  if (sec < 60) return `${Math.round(sec)} s`;
  if (sec < 3600) return `${trimZero((sec / 60).toFixed(sec < 600 ? 1 : 0))} min`;
  if (sec < 86400) return `${trimZero((sec / 3600).toFixed(1))} h`;
  return `${trimZero((sec / 86400).toFixed(1))} d`;
}

function fmtBytes(n) {
  if (n === null || n === undefined) return '–';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${trimZero((n / 1024).toFixed(1))} KB`;
  if (n < 1024 * 1024 * 1024) return `${trimZero((n / 1024 / 1024).toFixed(1))} MB`;
  return `${trimZero((n / 1024 / 1024 / 1024).toFixed(1))} GB`;
}

function fmtPct(x, digits = 0) {
  return x === null || x === undefined ? '–' : `${(x * 100).toFixed(digits)} %`;
}

function fmtDbm(x) {
  return x === null || x === undefined ? '–' : `${Math.round(x)} dBm`;
}

// route cost of a link: unknown (null) while only the active diagnostics have described it
function fmtCost(c) {
  return c === null || c === undefined ? '–' : String(c);
}

function fmtDb(x) {
  return x === null || x === undefined ? '–' : `${Math.round(x)} dB`;
}

// a share that is already given in percent (the routers report their error rates that way); small values keep a decimal
function fmtPercentValue(p) {
  if (p === null || p === undefined) return '–';
  if (p < 0.05) return '0 %';
  return `${p < 9.95 ? p.toFixed(1) : p.toFixed(0)} %`;
}

// the version number devices report (4 = Thread 1.3) as the name people know
const THREAD_VERSIONS = { 1: '1.0', 2: '1.1', 3: '1.2', 4: '1.3', 5: '1.4' };
function fmtThreadVersion(v) {
  if (v === null || v === undefined) return '–';
  return THREAD_VERSIONS[v] ?? `v${v}`;
}

// "{name}" placeholders; format(key, value) turns a value into text, unknown placeholders stay visible.
// "{count:device|devices}" adds the singular or plural word after the number.
function fillTemplate(template, params, format) {
  return template.replace(/\{(\w+)(?::([^|}]*)\|([^}]*))?\}/g, (match, key, one, other) => {
    if (!(key in params)) return match;
    const text = format(key, params[key]);
    return one === undefined ? text : `${text} ${Number(params[key]) === 1 ? one : other}`;
  });
}
