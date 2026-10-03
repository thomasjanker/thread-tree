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

// "{name}" placeholders; format(key, value) turns a value into text, unknown placeholders stay visible.
// "{count:device|devices}" adds the singular or plural word after the number.
function fillTemplate(template, params, format) {
  return template.replace(/\{(\w+)(?::([^|}]*)\|([^}]*))?\}/g, (match, key, one, other) => {
    if (!(key in params)) return match;
    const text = format(key, params[key]);
    return one === undefined ? text : `${text} ${Number(params[key]) === 1 ? one : other}`;
  });
}
