'use strict';
// The "Live" page: the frames the sniffer receives right now, and the state of the capture. Uses app.js / diag.js.

const MLE_COMMANDS = ['Link Request', 'Link Accept', 'Link Accept and Request', 'Link Reject', 'Advertisement', 'Update',
  'Update Request', 'Data Request', 'Data Response', 'Parent Request', 'Parent Response', 'Child ID Request',
  'Child ID Response', 'Child Update Request', 'Child Update Response', 'Announce', 'Discovery Request', 'Discovery Response'];

async function loadLive() {
  if (state.livePaused) return;
  const data = await fetch(`/api/live?since=${state.liveSeq || 0}`).then(r => r.json());
  if (data.seq < (state.liveSeq || 0)) state.liveFrames = [];  // the capture restarted: numbering starts again
  state.liveFrames = [...data.frames.reverse(), ...(state.liveFrames || [])].slice(0, 300);
  state.liveSeq = data.seq;
  state.live = data.capture;
}

function liveWho(id, short) {
  const n = id ? state.topo?.nodes[id] : null;
  if (n) return nodeLinkTo(id, nodeName(n));
  if (id) return h('span', { class: 'mono' }, id.length === 16 ? fmtMac(id) : id);
  return h('span', { class: 'mono muted' }, short || '–');
}

function liveDst(f) {
  if (f.dst) return liveWho(state.topo?.nodes[f.dst] ? f.dst : f.dst);
  if (f.dst16 === '0xffff') return h('span', { class: 'muted' }, t('live.broadcast'));
  const id = f.dst16 && state.topo ? Object.values(state.topo.nodes).find(n => n.rloc16 === f.dst16)?.id : null;
  return id ? liveWho(id) : liveWho(null, f.dst16);
}

function renderLive() {
  const c = state.live || {};
  const st = c.stats || {};
  const age = c.last_frame ? Math.max(0, Date.now() / 1000 - c.last_frame) : null;
  const sniffer = c.waiting_for_sniffer ? t('sticks.sniffer.none') : c.sniffer || c.source || '–';
  const input = h('input', { type: 'search', placeholder: t('live.filter'), value: state.liveFilter || '', 'aria-label': t('live.filter') });
  input.addEventListener('input', () => {
    state.liveFilter = input.value; render();
    const fresh = document.querySelector('#view input[type="search"]');
    if (fresh) { fresh.focus(); fresh.setSelectionRange(fresh.value.length, fresh.value.length); }
  });
  const q = (state.liveFilter || '').trim().toLowerCase();
  const rows = (state.liveFrames || []).filter(f => {
    if (!q) return true;
    const n = f.src ? state.topo?.nodes[f.src] : null;
    return [n ? nodeName(n) : '', f.src, f.src16, f.dst, f.dst16, t('kind.' + f.kind), f.mle !== null ? MLE_COMMANDS[f.mle] : ''].join(' ').toLowerCase().includes(q);
  }).slice(0, 200);
  const body = rows.map(f => h('tr', { class: f.decrypt === 'failed' ? 'log-warn' : null },
    h('td', { class: 'ev-time' }, new Date(f.ts * 1000).toLocaleTimeString(state.lang)),
    h('td', {}, liveWho(f.src, f.src16)), h('td', {}, liveDst(f)),
    h('td', {}, t('kind.' + f.kind), f.mle !== null && f.mle !== undefined && f.kind !== 'adv' ? h('span', { class: 'muted' }, ` · ${MLE_COMMANDS[f.mle] || 'MLE ' + f.mle}`) : null,
      f.retry ? [' ', h('span', { class: 'tag' }, t('live.retry'))] : null,
      f.decrypt === 'failed' ? [' ', h('span', { class: 'tag reach-indirect' }, t('live.undecrypted'))] : null),
    h('td', { class: 'num' }, f.rssi === null || f.rssi === undefined ? '–' : fmtDbm(f.rssi)),
    h('td', { class: 'num' }, f.len === null || f.len === undefined ? '–' : `${f.len} B`)));
  const fact = (label, value) => [h('dt', {}, label), h('dd', {}, value)];
  return h('div', { class: 'diag' },
    h('div', { class: 'diag-head' }, h('h2', {}, t('view.live')),
      iconButton(state.livePaused ? 'play' : 'stop', t(state.livePaused ? 'live.resume' : 'live.pause'),
        { onclick: () => { state.livePaused = !state.livePaused; render(); if (!state.livePaused) poll(); } }),
      h('span', { class: 'muted small' }, t('live.auto'))),
    h('dl', { class: 'facts' },
      fact(t('live.sniffer'), h('span', { class: 'mono' }, sniffer)),
      fact(t('set.channel'), c.channel ?? '–'),
      fact(t('live.capture'), c.running ? t('status.live') : c.error ? `${t('status.stopped')}: ${c.error}` : c.waiting_for_dataset ? t('status.waiting') : t('status.stopped')),
      fact(t('live.decrypt'), c.decrypting ? tfillLive('live.decrypt_v', { ok: st.mle_ok || 0, failed: st.mle_failed || 0 }) : t('live.nokey')),
      fact(t('live.frames'), tfillLive('live.frames_v', { total: st.frames || 0, minute: c.per_minute || 0 })),
      fact(t('live.last'), age === null ? t('live.none') : fmtDuration(age))),
    c.messages && c.messages.length ? section('live.messages', h('pre', { class: 'live-messages' },
      c.messages.slice(-15).map(m => `${new Date(m.ts * 1000).toLocaleTimeString(state.lang)}  ${m.from}: ${m.text}\n`))) : null,
    h('div', { class: 'toolbar' }, input),
    rows.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'logtable' },
      h('thead', {}, h('tr', {}, ...['log.col.time', 'live.from', 'live.to', 'live.kind', 'diag.link.signal', 'live.len'].map(k => h('th', {}, t(k))))),
      h('tbody', {}, body))) : h('p', { class: 'muted' }, t('live.empty')),
    h('p', { class: 'muted small' }, t('live.note')));
}

function tfillLive(key, params) { return fillTemplate(t(key), params, (k, v) => v); }
