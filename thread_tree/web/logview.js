'use strict';
// The "Log" page: device and network events, newest first, warnings marked (eventlog.py). Uses app.js and diag.js.

async function loadLog() {
  const level = state.logLevel === 'warn' ? 'warn' : 'all';
  state.log = await fetch(`/api/log?level=${level}&limit=2000`).then(r => r.json());
}

function logRows() {
  const q = (state.logFilter || '').trim().toLowerCase();
  return (state.log?.entries || []).map(e => {
    const n = e.node ? state.topo?.nodes[e.node] : null;
    const who = e.node ? (n ? nodeName(n) : e.node) : t('log.network');
    return { e, who, text: eventText(e) };
  }).filter(r => !q || `${r.who} ${r.text} ${r.e.kind} ${r.e.node || ''}`.toLowerCase().includes(q));
}

function renderLog() {
  const input = h('input', { type: 'search', placeholder: t('log.filter'), value: state.logFilter || '', 'aria-label': t('log.filter') });
  input.addEventListener('input', () => {
    state.logFilter = input.value; render();
    const fresh = document.querySelector('#view input[type="search"]');
    if (fresh) { fresh.focus(); fresh.setSelectionRange(fresh.value.length, fresh.value.length); }
  });
  const level = state.logLevel === 'warn' ? 'warn' : 'all';
  const tab = (value, key) => h('button', { type: 'button', role: 'tab', 'aria-selected': String(level === value),
    class: level === value ? 'active' : null, onclick: () => { state.logLevel = value; state.log = null; poll(); render(); } }, t(key));
  const rows = logRows();
  const body = rows.slice(0, 1000).map(({ e, who, text }) => h('tr', { class: e.severity === 'warn' ? 'log-warn' : null },
    h('td', { class: 'ev-time', title: absTime(e.ts) }, absTime(e.ts)),
    h('td', {}, sevChip(e.severity)),
    h('td', {}, e.node && state.topo?.nodes[e.node] ? nodeLinkTo(e.node, who) : h('span', { class: e.node ? null : 'muted' }, who)),
    h('td', {}, text)));
  return h('div', { class: 'diag' },
    h('div', { class: 'diag-head' }, h('h2', {}, t('view.log')),
      h('a', { class: 'btnlink', href: `/api/export/log.csv${level === 'warn' ? '?level=warn' : ''}`, download: 'thread-tree-log.csv' }, t('log.export'))),
    h('div', { class: 'toolbar' }, h('nav', { class: 'segmented' }, tab('all', 'log.all'), tab('warn', 'log.warn')), input),
    rows.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'logtable' },
      h('thead', {}, h('tr', {}, ...['log.col.time', 'log.col.severity', 'log.col.device', 'log.col.event'].map(k => h('th', {}, t(k))))),
      h('tbody', {}, body))) : h('p', { class: 'muted' }, state.log ? t('log.empty') : t('diag.loading')),
    h('p', { class: 'muted small' }, t('log.note')));
}
