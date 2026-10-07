/* SecuScope — comportements partagés (spotlight, sceau, radar, gras markdown). */
(() => {
  const NS = 'http://www.w3.org/2000/svg';
  const reduce = matchMedia('(prefers-reduced-motion:reduce)').matches;
  const el = (n, a) => { const e = document.createElementNS(NS, n); for (const k in a) e.setAttribute(k, a[k]); return e; };

  // spotlight : lueur qui suit le curseur
  document.querySelectorAll('.spot').forEach(c => c.addEventListener('pointermove', e => {
    const r = c.getBoundingClientRect();
    c.style.setProperty('--mx', (e.clientX - r.left) + 'px');
    c.style.setProperty('--my', (e.clientY - r.top) + 'px');
  }));

  // sceau-verdict : graduations, guilloché, arc de score (couleur du grade héritée via currentColor)
  const seal = document.getElementById('seal');
  if (seal) {
    const cx = 98, cy = 98;
    const target = Math.max(0, Math.min(100, Number(seal.dataset.score) || 0));
    const color = getComputedStyle(seal).color;
    seal.appendChild(el('circle', { cx, cy, r: 86, fill: 'none', stroke: 'rgba(255,255,255,.08)', 'stroke-width': 1 }));
    const R = 70, r = 23, d = 34, pts = [];
    for (let i = 0; i <= 1440; i++) {
      const t = i * Math.PI / 180;
      const x = cx + ((R - r) * Math.cos(t) + d * Math.cos((R - r) / r * t)) * 0.74;
      const y = cy + ((R - r) * Math.sin(t) - d * Math.sin((R - r) / r * t)) * 0.74;
      pts.push((i ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1));
    }
    seal.appendChild(el('path', { d: pts.join(' '), fill: 'none', stroke: color, 'stroke-width': 0.4, opacity: 0.13 }));
    for (let i = 0; i < 72; i++) {
      const a = i / 72 * 2 * Math.PI - Math.PI / 2, big = i % 6 === 0, r1 = big ? 76 : 79, r2 = 83;
      seal.appendChild(el('line', { x1: cx + r1 * Math.cos(a), y1: cy + r1 * Math.sin(a), x2: cx + r2 * Math.cos(a), y2: cy + r2 * Math.sin(a),
        stroke: '#5A6B7D', 'stroke-width': big ? 1.3 : 0.7, opacity: big ? .7 : .35 }));
    }
    const circ = 2 * Math.PI * 86;
    const arc = el('circle', { cx, cy, r: 86, fill: 'none', stroke: color, 'stroke-width': 5, 'stroke-linecap': 'round',
      'stroke-dasharray': circ.toFixed(1), 'stroke-dashoffset': circ.toFixed(1), transform: `rotate(-90 ${cx} ${cy})`,
      style: 'transition:stroke-dashoffset 1.3s cubic-bezier(.2,.7,.2,1)' });
    seal.appendChild(arc);
    const off = (circ * (1 - target / 100)).toFixed(1);
    const sEl = document.getElementById('score');
    if (reduce || !sEl) { arc.setAttribute('stroke-dashoffset', off); if (sEl) sEl.textContent = target; }
    else {
      requestAnimationFrame(() => setTimeout(() => {
        arc.setAttribute('stroke-dashoffset', off);
        const t0 = performance.now(), D = 1300, ease = t => 1 - Math.pow(1 - t, 4);
        const tick = now => { const t = Math.min((now - t0) / D, 1); sEl.textContent = Math.round(target * ease(t)); if (t < 1) requestAnimationFrame(tick); };
        requestAnimationFrame(tick);
      }, 250));
    }
  }

  // radar : pentagone, 5 axes (valeurs 0–100 lues dans data-values)
  const radar = document.getElementById('radarPlot');
  if (radar) {
    const vals = JSON.parse(radar.dataset.values), labels = JSON.parse(radar.dataset.labels);
    const Rmax = 90, ang = i => -Math.PI / 2 + i * 2 * Math.PI / 5;
    const pt = (k, i) => `${(Rmax * k * Math.cos(ang(i))).toFixed(1)},${(Rmax * k * Math.sin(ang(i))).toFixed(1)}`;
    const g = el('g', { transform: 'translate(140,118)' }); radar.appendChild(g);
    [1, .66, .33].forEach(k => g.appendChild(el('polygon', { fill: 'none', stroke: 'rgba(255,255,255,.1)', 'stroke-width': 1,
      points: vals.map((_, i) => pt(k, i)).join(' ') })));
    vals.forEach((_, i) => g.appendChild(el('line', { x1: 0, y1: 0, x2: Rmax * Math.cos(ang(i)), y2: Rmax * Math.sin(ang(i)), stroke: 'rgba(255,255,255,.1)' })));
    g.appendChild(el('polygon', { fill: 'url(#rg)', stroke: '#8B7CFF', 'stroke-width': 1.5, 'stroke-linejoin': 'round',
      points: vals.map((v, i) => pt(v / 100, i)).join(' ') }));
    labels.forEach((l, i) => {
      const c = Math.cos(ang(i));
      const t = el('text', { x: 108 * c, y: 108 * Math.sin(ang(i)) + 3, fill: '#98A3B4', 'font-family': 'IBM Plex Mono', 'font-size': 10,
        'text-anchor': Math.abs(c) < .2 ? 'middle' : (c > 0 ? 'start' : 'end') });
      t.textContent = l; g.appendChild(t);
    });
  }


  // courbe d'évolution : aire lissée (Catmull-Rom -> bézier), points réels lus dans data-points
  const trend = document.getElementById('trend');
  if (trend) {
    const data = JSON.parse(trend.dataset.points).map(d => d.score), n = data.length;
    const L = 12, Rr = 626, yOf = s => 170 - s / 100 * 156, xOf = i => L + i / (n - 1) * (Rr - L);
    const defs = el('defs', {}), grad = el('linearGradient', { id: 'tg', x1: 0, y1: 0, x2: 0, y2: 1 });
    grad.appendChild(el('stop', { offset: '0%', 'stop-color': 'rgba(139,124,255,.42)' }));
    grad.appendChild(el('stop', { offset: '100%', 'stop-color': 'rgba(139,124,255,0)' }));
    defs.appendChild(grad); trend.appendChild(defs);
    [['#F2B13D', 80, 60], ['#F58345', 60, 40]].forEach(([c, hi, lo]) =>
      trend.appendChild(el('rect', { x: 0, y: yOf(hi), width: 640, height: yOf(lo) - yOf(hi), fill: c, opacity: .045 })));
    [20, 40, 60, 80, 100].forEach(v => trend.appendChild(el('line', { x1: 0, y1: yOf(v), x2: 640, y2: yOf(v), stroke: 'rgba(255,255,255,.05)', 'stroke-width': 1 })));
    const P = data.map((s, i) => [xOf(i), yOf(s)]);
    let d = 'M' + P[0][0] + ' ' + P[0][1];
    for (let i = 0; i < P.length - 1; i++) {
      const p0 = P[i - 1] || P[i], p1 = P[i], p2 = P[i + 1], p3 = P[i + 2] || P[i + 1];
      d += `C${(p1[0] + (p2[0] - p0[0]) / 6).toFixed(1)} ${(p1[1] + (p2[1] - p0[1]) / 6).toFixed(1)} ${(p2[0] - (p3[0] - p1[0]) / 6).toFixed(1)} ${(p2[1] - (p3[1] - p1[1]) / 6).toFixed(1)} ${p2[0].toFixed(1)} ${p2[1].toFixed(1)}`;
    }
    trend.appendChild(el('path', { d: d + `L${Rr} 170 L${L} 170 Z`, fill: 'url(#tg)' }));
    const line = el('path', { d, fill: 'none', stroke: '#8B7CFF', 'stroke-width': 2.5, 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
      style: 'filter:drop-shadow(0 4px 10px rgba(139,124,255,.5))' });
    trend.appendChild(line);
    const last = P[P.length - 1];
    trend.appendChild(el('circle', { cx: last[0], cy: last[1], r: 4.5, fill: '#fff', stroke: '#8B7CFF', 'stroke-width': 2 }));
    if (!reduce) {
      const len = line.getTotalLength();
      line.style.strokeDasharray = len; line.style.strokeDashoffset = len;
      line.style.transition = 'stroke-dashoffset 1.4s cubic-bezier(.3,.7,.2,1) .35s';
      requestAnimationFrame(() => { line.style.strokeDashoffset = 0; });
    }
  }

  // gras markdown du texte LLM — nœuds DOM uniquement (texte non fiable)
  document.querySelectorAll('.markdown-text').forEach(node => {
    const parts = node.textContent.split(/\*\*(.*?)\*\*/g);
    node.textContent = '';
    parts.forEach((p, i) => {
      if (i % 2) { const s = document.createElement('b'); s.textContent = p; node.appendChild(s); }
      else node.appendChild(document.createTextNode(p));
    });
  });
})();
