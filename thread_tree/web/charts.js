'use strict';
// Small SVG charts without a library. The geometry helpers are pure functions (tested outside a browser);
// the builders use the DOM helper s() from app.js and take their colours from CSS classes, so they follow
// the light/dark theme.

const CHART_W = 720;

// smallest "nice" number (1, 2, 5 times a power of ten) that is >= v
function niceMax(v) {
  if (!(v > 0)) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const f = v / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}

// linear scale from [d0, d1] to [r0, r1]; a flat domain maps to the middle of the range
function scaleLinear(d0, d1, r0, r1) {
  return v => (d1 === d0 ? (r0 + r1) / 2 : r0 + ((v - d0) / (d1 - d0)) * (r1 - r0));
}

// x-axis labels: the buckets that start a full hour dividing `everyHours`, with their local HH:00 label
function hourTicks(startTs, bucketSeconds, count, everyHours, tzOffsetMinutes) {
  const tz = tzOffsetMinutes === undefined ? -new Date().getTimezoneOffset() : tzOffsetMinutes;
  const ticks = [];
  for (let i = 0; i < count; i++) {
    const local = startTs + i * bucketSeconds + tz * 60;
    const secondsIntoHour = ((local % 3600) + 3600) % 3600;
    const hour = Math.floor((((local % 86400) + 86400) % 86400) / 3600);
    if (secondsIntoHour < bucketSeconds && hour % everyHours === 0) ticks.push({ i, label: String(hour).padStart(2, '0') + ':00' });
  }
  return ticks;
}

function gridLines(svg, plot, yMax, steps, unit) {
  const y = scaleLinear(0, yMax, plot.y + plot.h, plot.y);
  for (let k = 0; k <= steps; k++) {
    const v = (yMax / steps) * k;
    svg.append(s('line', { class: 'ch-grid', x1: plot.x, x2: plot.x + plot.w, y1: y(v), y2: y(v) }));
    svg.append(s('text', { class: 'ch-axis', x: plot.x - 6, y: y(v) + 4, 'text-anchor': 'end' }, String(Math.round(v)) + (unit || '')));
  }
  return y;
}

function xAxis(svg, plot, ticks, count) {
  const step = plot.w / count;
  for (const t of ticks) {
    const x = plot.x + t.i * step;
    svg.append(s('line', { class: 'ch-grid', x1: x, x2: x, y1: plot.y, y2: plot.y + plot.h }));
    svg.append(s('text', { class: 'ch-axis', x, y: plot.y + plot.h + 16, 'text-anchor': 'middle' }, t.label));
  }
}

// frames per bucket as bars, the retransmitted share drawn over them
function activityChart(series, labels) {
  const n = series.frames.length, H = 170, plot = { x: 40, y: 8, w: CHART_W - 50, h: H - 36 };
  const yMax = niceMax(Math.max(1, ...series.frames));
  const svg = s('svg', { viewBox: `0 0 ${CHART_W} ${H}`, class: 'chart', role: 'img', 'aria-label': labels.title });
  const y = gridLines(svg, plot, yMax, 4);
  xAxis(svg, plot, hourTicks(series.start, series.bucket_seconds, n, 3), n);
  const step = plot.w / n;
  for (let i = 0; i < n; i++) {
    const x = plot.x + i * step + 0.5, w = Math.max(1, step - 1);
    const when = new Date((series.start + i * series.bucket_seconds) * 1000).toLocaleString(labels.lang, { weekday: 'short', hour: '2-digit', minute: '2-digit' });
    const g = s('g', {}, s('title', {}, `${when}: ${series.frames[i]} ${labels.frames}, ${series.retries[i]} ${labels.retries}`));
    if (series.frames[i]) g.append(s('rect', { class: 'ch-bar', x, width: w, y: y(series.frames[i]), height: plot.y + plot.h - y(series.frames[i]) }));
    if (series.retries[i]) g.append(s('rect', { class: 'ch-retry', x, width: w, y: y(series.retries[i]), height: plot.y + plot.h - y(series.retries[i]) }));
    g.append(s('rect', { class: 'ch-hit', x: plot.x + i * step, width: step, y: plot.y, height: plot.h }));
    svg.append(g);
  }
  return svg;
}

// y range of the signal chart: around the measured values in steps of 10 dB, at least 30 dB, within -100 .. -20
function rssiRange(values) {
  if (!values.length) return { lo: -100, hi: -20, step: 20 };
  let lo = Math.max(-100, Math.floor((Math.min(...values) - 3) / 10) * 10);
  let hi = Math.min(-20, Math.ceil((Math.max(...values) + 3) / 10) * 10);
  while (hi - lo < 30 && (lo > -100 || hi < -20)) {
    if ((hi - lo) % 20 === 0 && hi < -20 || lo <= -100) hi += 10; else lo -= 10;  // grow up and down alternately
  }
  return { lo, hi, step: hi - lo > 50 ? 20 : 10 };
}

// signal strength at the sniffer: min-max band and average per bucket, with the "weak" threshold
function rssiChart(series, labels, weak) {
  const n = series.rssi_avg.length, H = 170, plot = { x: 48, y: 8, w: CHART_W - 58, h: H - 36 };
  const { lo, hi, step: gridStep } = rssiRange([...series.rssi_min, ...series.rssi_max].filter(v => v !== null));
  const y = scaleLinear(lo, hi, plot.y + plot.h, plot.y);
  const svg = s('svg', { viewBox: `0 0 ${CHART_W} ${H}`, class: 'chart', role: 'img', 'aria-label': labels.title });
  for (let v = lo; v <= hi; v += gridStep) {
    svg.append(s('line', { class: 'ch-grid', x1: plot.x, x2: plot.x + plot.w, y1: y(v), y2: y(v) }));
    svg.append(s('text', { class: 'ch-axis', x: plot.x - 6, y: y(v) + 4, 'text-anchor': 'end' }, `${v}`));
  }
  if (weak >= lo && weak <= hi) svg.append(s('line', { class: 'ch-weak', x1: plot.x, x2: plot.x + plot.w, y1: y(weak), y2: y(weak) }));
  xAxis(svg, plot, hourTicks(series.start, series.bucket_seconds, n, 3), n);
  const step = plot.w / n;
  let path = '', pen = false;  // the line is interrupted where a bucket has no measurement
  for (let i = 0; i < n; i++) {
    if (series.rssi_avg[i] === null) { pen = false; continue; }
    const x = plot.x + i * step + step / 2, avg = series.rssi_avg[i];
    svg.append(s('line', { class: 'ch-band', x1: x, x2: x, y1: y(series.rssi_max[i]), y2: y(series.rssi_min[i]) }));
    path += `${pen ? 'L' : 'M'}${x.toFixed(1)},${y(avg).toFixed(1)} `;
    pen = true;
    const when = new Date((series.start + i * series.bucket_seconds) * 1000).toLocaleString(labels.lang, { weekday: 'short', hour: '2-digit', minute: '2-digit' });
    svg.append(s('circle', { class: 'ch-dot', cx: x, cy: y(avg), r: 1.8 }, s('title', {}, `${when}: Ø ${avg.toFixed(0)} dBm (${series.rssi_min[i]} … ${series.rssi_max[i]})`)));
  }
  if (path) svg.append(s('path', { class: 'ch-line', d: path.trim() }));
  return svg;
}

// distribution of all RSSI measurements in 5 dB classes
function histogramChart(hist, labels) {
  const H = 120, plot = { x: 40, y: 8, w: CHART_W - 50, h: H - 34 };
  const yMax = niceMax(Math.max(1, ...hist.map(h => h[1])));
  const svg = s('svg', { viewBox: `0 0 ${CHART_W} ${H}`, class: 'chart', role: 'img', 'aria-label': labels.title });
  const y = scaleLinear(0, yMax, plot.y + plot.h, plot.y), step = plot.w / hist.length;
  svg.append(s('line', { class: 'ch-grid', x1: plot.x, x2: plot.x + plot.w, y1: plot.y + plot.h, y2: plot.y + plot.h }));
  hist.forEach(([lo, count], i) => {
    const x = plot.x + i * step + 2;
    svg.append(s('rect', { class: lo < labels.weak ? 'ch-retry' : 'ch-bar', x, width: step - 4, y: y(count), height: plot.y + plot.h - y(count) },
      s('title', {}, `${lo} … ${lo + 4} dBm: ${count}`)));
    if (i % 2 === 0) svg.append(s('text', { class: 'ch-axis', x: x + (step - 4) / 2, y: plot.y + plot.h + 15, 'text-anchor': 'middle' }, String(lo)));
  });
  svg.append(s('text', { class: 'ch-axis', x: plot.x - 6, y: plot.y + 8, 'text-anchor': 'end' }, String(yMax)));
  return svg;
}

// link quality 0-3 as three small bars
function lqMeter(value) {
  const svg = s('svg', { viewBox: '0 0 22 14', class: 'lq', width: 22, height: 14, role: 'img', 'aria-label': `LQ ${value}` });
  for (let i = 0; i < 3; i++) svg.append(s('rect', { class: i < value ? `lq-on lq-${value}` : 'lq-off', x: i * 8, y: 12 - (i + 1) * 4, width: 6, height: (i + 1) * 4 }));
  svg.append(s('title', {}, `LQ ${value}`));
  return svg;
}
