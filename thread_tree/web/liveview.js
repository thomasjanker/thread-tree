'use strict';
// The "Live" page: the frames the sniffer receives right now, and the state of the capture. Uses app.js / diag.js.

const MLE_COMMANDS = ['Link Request', 'Link Accept', 'Link Accept and Request', 'Link Reject', 'Advertisement', 'Update',
  'Update Request', 'Data Request', 'Data Response', 'Parent Request', 'Parent Response', 'Child ID Request',
  'Child ID Response', 'Child Update Request', 'Child Update Response', 'Announce', 'Discovery Request', 'Discovery Response'];

async function loadLive() {
  if (state.livePaused) return;
  const data = await fetch(`/api/live?since=${state.liveSeq || 0}`).then(r => r.json());
  if (data.seq < (state.liveSeq || 0)) state.liveFrames = [];  // the capture restarted: numbering starts again
  state.liveFrames = [...data.frames.reverse(), ...(state.liveFrames || [])].slice(0, 2000);
  state.liveSeq = data.seq;
  state.live = data.capture;
}

const MLE_TLVS = {0: 'Source Address', 1: 'Mode', 2: 'Timeout', 3: 'Challenge', 4: 'Response', 5: 'Link-layer Frame Counter',
  6: 'Link Quality', 7: 'Network Parameter', 8: 'MLE Frame Counter', 9: 'Route64', 10: 'Address16', 11: 'Leader Data',
  12: 'Network Data', 13: 'TLV Request', 14: 'Scan Mask', 15: 'Connectivity', 16: 'Link Margin', 17: 'Status', 18: 'Version',
  19: 'Address Registration', 20: 'Channel', 21: 'PAN ID', 22: 'Active Timestamp', 23: 'Pending Timestamp',
  24: 'Active Operational Dataset', 25: 'Pending Operational Dataset', 26: 'Discovery', 27: 'Supervision Interval',
  80: 'CSL Channel', 85: 'CSL Synchronized Timeout', 86: 'CSL Clock Accuracy', 87: 'Link Metrics Query',
  88: 'Link Metrics Management', 89: 'Link Metrics Report', 90: 'Link Probe'};
const TMF_URIS = {'/a/aq': 'Address Query', '/a/an': 'Address Notification', '/a/ae': 'Address Error', '/a/as': 'Address Solicit (router ID)',
  '/a/ar': 'Address Release (router ID)', '/a/sd': 'Server Data', '/n/dr': 'Data Response', '/d/dg': 'Diagnostic Get',
  '/d/dq': 'Diagnostic Query', '/d/da': 'Diagnostic Answer', '/d/dr': 'Diagnostic Reset', '/c/lp': 'Leader Petition',
  '/c/la': 'Leader Keep-Alive', '/c/ag': 'Active Get', '/c/as': 'Active Set', '/c/rx': 'Relay Receive', '/c/tx': 'Relay Transmit',
  '/c/jf': 'Joiner Finalize', '/c/je': 'Joiner Entrust', '/b/bmr': 'Backbone Multicast Registration'};
const ICMP_TYPES = {1: 'Destination Unreachable', 3: 'Time Exceeded', 128: 'Echo Request', 129: 'Echo Reply'};

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

// hiding the acknowledgements is remembered in this browser
function liveHideAcks() {
  if (state.liveHideAcks === undefined) {
    try { state.liveHideAcks = localStorage.getItem('liveHideAcks') === '1'; } catch { state.liveHideAcks = false; }
  }
  return state.liveHideAcks;
}

function toggleAcks() {
  state.liveHideAcks = !liveHideAcks();
  try { localStorage.setItem('liveHideAcks', state.liveHideAcks ? '1' : '0'); } catch { /* not available */ }
  render();
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
  const hideAcks = liveHideAcks();
  const acks = (state.liveFrames || []).filter(f => f.kind === 'ack').length;
  const rows = (state.liveFrames || []).filter(f => {
    if (hideAcks && f.kind === 'ack') return false;
    if (!q) return true;
    const n = f.src ? state.topo?.nodes[f.src] : null;
    return [n ? nodeName(n) : '', f.src, f.src16, f.dst, f.dst16, t('kind.' + f.kind), f.mle !== null ? MLE_COMMANDS[f.mle] : ''].join(' ').toLowerCase().includes(q);
  }).slice(0, 500);
  const body = rows.flatMap(f => [h('tr', { class: `row${f.decrypt === 'failed' ? ' log-warn' : ''}${state.liveOpen === f.seq ? ' selected' : ''}`,
    onclick: () => { state.liveOpen = state.liveOpen === f.seq ? null : f.seq; render(); } },
    h('td', { class: 'ev-time' }, new Date(f.ts * 1000).toLocaleTimeString(state.lang)),
    h('td', {}, liveWho(f.src, f.src16)), h('td', {}, liveDst(f)),
    h('td', {}, t('kind.' + f.kind), f.mle !== null && f.mle !== undefined && f.kind !== 'adv' ? h('span', { class: 'muted' }, ` · ${MLE_COMMANDS[f.mle] || 'MLE ' + f.mle}`) : null,
      f.proto && f.proto !== 'mle' ? h('span', { class: 'muted' }, ` · ${t('proto.' + f.proto)}${f.uri ? ' ' + (TMF_URIS[f.uri] || f.uri) : ''}`) : null,
      f.mesh ? [' ', h('span', { class: 'tag', title: t('live.d.mesh') }, t('live.relayed'))] : null,
      f.flags && f.flags.pending ? [' ', h('span', { class: 'tag' }, t('live.d.pending'))] : null,
      f.retry ? [' ', h('span', { class: 'tag' }, t('live.retry'))] : null,
      f.decrypt === 'failed' ? [' ', h('span', { class: 'tag reach-indirect' }, t('live.undecrypted'))] : null),
    h('td', { class: 'num' }, f.rssi === null || f.rssi === undefined ? '–' : fmtDbm(f.rssi)),
    h('td', { class: 'num' }, f.len === null || f.len === undefined ? '–' : `${f.len} B`)),
    state.liveOpen === f.seq ? h('tr', { class: 'live-detail' }, h('td', { colspan: 6 }, liveDetail(f))) : null]);
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
      fact(t('live.last'), age === null ? t('live.none') : fmtDuration(age)),
      fact(t('live.buffer'), c.oldest ? tfillLive('live.buffer_v', { n: (state.liveFrames || []).length, span: fmtDuration(Math.max(0, (c.last_frame || 0) - c.oldest)) }) : '–')),
    c.messages && c.messages.length ? section('live.messages', h('pre', { class: 'live-messages' },
      c.messages.slice(-15).map(m => `${new Date(m.ts * 1000).toLocaleTimeString(state.lang)}  ${m.from}: ${m.text}\n`))) : null,
    h('div', { class: 'toolbar' }, input,
      h('button', { type: 'button', class: `ibtn${hideAcks ? ' active' : ''}`, 'aria-pressed': String(hideAcks), onclick: toggleAcks },
        t(hideAcks ? 'live.acks.show' : 'live.acks.hide')),
      hideAcks && acks ? h('span', { class: 'muted small' }, fillTemplate(t('live.acks.hidden'), { n: acks }, (k, v) => v)) : null),
    rows.length ? h('div', { class: 'tablewrap' }, h('table', { class: 'logtable' },
      h('thead', {}, h('tr', {}, ...['log.col.time', 'live.from', 'live.to', 'live.kind', 'diag.link.signal', 'live.len'].map(k => h('th', {}, t(k))))),
      h('tbody', {}, body))) : h('p', { class: 'muted' }, t('live.empty')),
    h('p', { class: 'muted small' }, t('live.note')));
}

function tfillLive(key, params) { return fillTemplate(t(key), params, (k, v) => v); }

// a device name for an IPv6 address the topology knows
function liveAddr(addr) {
  if (!addr) return '–';
  const n = state.topo && Object.values(state.topo.nodes).find(x => (x.addresses || []).some(a => a.addr === addr));
  return n ? [h('span', { class: 'mono' }, addr), ' (', nodeLinkTo(n.id, nodeName(n)), ')'] : h('span', { class: 'mono' }, addr);
}

function liveNode(id) {
  return id ? liveWho(state.topo?.nodes[id] ? id : null, id) : '–';
}

// everything the summary of a frame says, and the full decode on request
function liveDetail(f) {
  const rows = [];
  const add = (label, value) => rows.push(h('dt', {}, label), h('dd', {}, value));
  if (f.no) add(t('live.d.no'), String(f.no));
  const fl = f.flags || {};
  const flags = [fl.security ? t('live.d.secured') : t('live.d.unsecured'), fl.ack_req ? t('live.d.ackreq') : null,
    fl.pending ? t('live.d.pending') : null, fl.version !== undefined ? `802.15.4-${{ 0: '2003', 1: '2006', 2: '2015' }[fl.version] || fl.version}` : null].filter(Boolean);
  add(t('live.d.flags'), flags.join(', '));
  if (f.sec) add(t('live.d.sec'), tfillLive('live.d.sec_v', { level: f.sec.level ?? '–', mode: f.sec.mode ?? '–', key: f.sec.key ?? '–', counter: f.sec.counter ?? '–' }));
  if (f.answers) add(t('live.d.poll'), [tfillLive(f.flags && f.flags.pending ? 'live.d.poll_pending' : 'live.d.poll_none', {}), ' ', liveNode(f.answers)]);
  if (f.mesh) add(t('live.d.mesh'), [liveNode(f.mesh.orig), ' → ', liveNode(f.mesh.dest), f.mesh.hops !== null && f.mesh.hops !== undefined ? ` (${tfillLive('live.d.hops', { n: f.mesh.hops })})` : '']);
  if (f.ip) add('IPv6', [liveAddr(f.ip.src), ' → ', liveAddr(f.ip.dst)]);
  if (f.udp) add('UDP', `${f.udp.src ?? '–'} → ${f.udp.dst ?? '–'}${f.proto ? ` (${t('proto.' + f.proto)})` : ''}${f.udp.len ? `, ${f.udp.len} B` : ''}`);
  if (f.icmp !== undefined) add('ICMPv6', ICMP_TYPES[f.icmp] || String(f.icmp));
  if (f.uri) add(t('live.d.tmf'), `${f.uri}${TMF_URIS[f.uri] ? ' — ' + TMF_URIS[f.uri] : ''}${f.coap ? ` (CoAP ${f.coap})` : ''}`);
  if (f.tlvs) add(t('live.d.tlvs'), f.tlvs.map(x => MLE_TLVS[x] || `TLV ${x}`).join(', '));
  if (f.dns) add(t('live.d.dns'), f.dns.join(', '));
  const decoded = (state.liveDecoded || {})[f.no];
  return h('div', {},
    h('dl', { class: 'info' }, rows),
    f.no ? (decoded === undefined
      ? iconButton('json', t('live.detail.decode'), { onclick: async e => { e.stopPropagation(); await liveDecode(f.no); } })
      : decoded === null ? h('p', { class: 'muted' }, t('live.detail.loading'))
        : decoded.error ? h('p', { class: 'muted' }, t('live.detail.gone'))
          : h('div', { class: 'decode' }, decodeTree(decoded, `dec:${f.no}`))) : null);
}

async function liveDecode(no) {
  state.liveDecoded = state.liveDecoded || {};
  state.liveDecoded[no] = null;
  render();
  try {
    const res = await fetch(`/api/live/frame/${no}`);
    state.liveDecoded[no] = res.ok ? await res.json() : { error: true };
  } catch { state.liveDecoded[no] = { error: true }; }
  render();
}

// the Wireshark decode as a tree: protocols and fields, foldable
function decodeTree(obj, path) {
  return Object.entries(obj).map(([key, value]) => {
    const label = key.replace(/_tree$/, '');
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return foldable(`${path}/${key}`, path.split('/').length < 2 && !key.startsWith('frame'), { class: 'decode-node' }, label,
        decodeTree(value, `${path}/${key}`));
    }
    const text = Array.isArray(value) ? value.map(v => (typeof v === 'object' ? JSON.stringify(v) : String(v))).join(', ') : String(value);
    return h('div', { class: 'decode-leaf' }, h('span', { class: 'muted' }, label + ': '), h('span', { class: 'mono' }, text));
  });
}
