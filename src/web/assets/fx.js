/*
 * Oculon motion kit, shared by the landing page and the app.
 *   OculonFX.liquid(canvas, opts)  grainy liquid gradient (WebGL fragment shader, domain-warped noise),
 *                                  pulled toward the pointer and stirred by scrolling.
 *   OculonFX.stream(canvas, opts)  a band of flowing particles with a scanning lens that flags the
 *                                  particles inside it; click sends a shockwave through the band.
 * Both pause when off screen and do nothing when the viewer prefers reduced motion.
 */
(function () {
  const REDUCE = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const pointer = { x: 0.5, y: 0.5, tx: 0.5, ty: 0.5, down: 0 };
  addEventListener('pointermove', (e) => { pointer.tx = e.clientX / innerWidth; pointer.ty = e.clientY / innerHeight; }, { passive: true });
  let scrollV = 0, lastY = scrollY;
  addEventListener('scroll', () => { scrollV += Math.abs(scrollY - lastY); lastY = scrollY; }, { passive: true });
  // Scroll energy: one smoothed, capped value shared by every effect, so scrolling nudges the motion
  // a little instead of making it race.
  let energy = 0;
  (function decay() { energy = Math.min(0.35, energy * 0.93 + Math.min(scrollV, 240) * 0.00035); scrollV = 0; requestAnimationFrame(decay); })();

  function whileVisible(el, start, stop) {
    if (!('IntersectionObserver' in window)) { start(); return; }
    new IntersectionObserver((es) => (es.some((e) => e.isIntersecting) ? start() : stop())).observe(el);
  }

  const FRAG = `
precision highp float;
uniform vec2 uRes; uniform float uTime; uniform vec2 uMouse; uniform float uStir; uniform float uIntensity; uniform vec3 uA; uniform vec3 uB; uniform vec3 uC;
float hash(vec2 p){ p = fract(p * vec2(123.34, 456.21)); p += dot(p, p + 45.32); return fract(p.x * p.y); }
float noise(vec2 p){ vec2 i = floor(p), f = fract(p); vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(mix(hash(i), hash(i + vec2(1,0)), u.x), mix(hash(i + vec2(0,1)), hash(i + vec2(1,1)), u.x), u.y); }
float fbm(vec2 p){ float v = 0.0, a = 0.5; mat2 m = mat2(1.6, 1.2, -1.2, 1.6); for (int i = 0; i < 5; i++) { v += a * noise(p); p = m * p; a *= 0.5; } return v; }
void main(){
  vec2 uv = gl_FragCoord.xy / uRes; vec2 p = uv * vec2(uRes.x / uRes.y, 1.0) * 1.6;
  vec2 m = uMouse * vec2(uRes.x / uRes.y, 1.0) * 1.6;
  float t = uTime * 0.07;
  // pull the fluid toward the pointer
  vec2 d = p - m; float pull = exp(-dot(d, d) * 1.6);
  p -= d * pull * 0.35;
  vec2 q = vec2(fbm(p + t), fbm(p + vec2(5.2, 1.3) - t));
  vec2 r = vec2(fbm(p + 3.8 * q + vec2(1.7, 9.2) + t * 1.3), fbm(p + 3.8 * q + vec2(8.3, 2.8) - t * 0.9));
  float f = fbm(p + 4.0 * r);
  float ink = smoothstep(0.38, 0.95, f + pull * 0.25);
  vec3 col = mix(uA, uB, smoothstep(0.15, 0.7, ink));
  col = mix(col, uC, smoothstep(0.72, 1.0, ink + length(q) * 0.15));
  // film grain, like the reference
  float g = hash(gl_FragCoord.xy + fract(uTime) * 100.0) - 0.5;
  col += g * 0.09;
  gl_FragColor = vec4(col * uIntensity, 1.0);
}`;

  function liquid(canvas, opts = {}) {
    if (REDUCE) return;
    const gl = canvas.getContext('webgl', { premultipliedAlpha: false, antialias: false });
    if (!gl) return;
    const sh = (type, src) => { const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s); return s; };
    const prog = gl.createProgram();
    gl.attachShader(prog, sh(gl.VERTEX_SHADER, 'attribute vec2 a; void main(){ gl_Position = vec4(a, 0.0, 1.0); }'));
    gl.attachShader(prog, sh(gl.FRAGMENT_SHADER, FRAG));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return;
    gl.useProgram(prog);
    const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, 'a'); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const u = (n) => gl.getUniformLocation(prog, n);
    const U = { res: u('uRes'), time: u('uTime'), mouse: u('uMouse'), stir: u('uStir'), int: u('uIntensity'), a: u('uA'), b: u('uB'), c: u('uC') };
    const hex = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
    gl.uniform3fv(U.a, hex(opts.base || '#000000'));
    gl.uniform3fv(U.b, hex(opts.mid || '#003a52'));
    gl.uniform3fv(U.c, hex(opts.hi || '#00f0ff'));
    const scale = opts.scale || 0.5; // render at half resolution; the shape is soft anyway
    const size = () => { const w = canvas.clientWidth, h = canvas.clientHeight; canvas.width = Math.max(1, Math.round(w * scale)); canvas.height = Math.max(1, Math.round(h * scale)); gl.viewport(0, 0, canvas.width, canvas.height); };
    size(); addEventListener('resize', size);
    let on = false, raf = 0, stir = 0;
    let phase = Math.random() * 60, prev = performance.now();
    const frame = (now) => {
      pointer.x += (pointer.tx - pointer.x) * 0.06; pointer.y += (pointer.ty - pointer.y) * 0.06;
      // Time is integrated, not scaled, so a speed change never makes the fluid jump.
      const dt = Math.min(0.05, (now - prev) / 1000); prev = now; phase += dt * (1 + energy * 1.2); stir = energy;
      const r = canvas.getBoundingClientRect();
      const mx = (pointer.x * innerWidth - r.left) / r.width, my = 1 - (pointer.y * innerHeight - r.top) / r.height;
      gl.uniform2f(U.res, canvas.width, canvas.height);
      gl.uniform1f(U.time, phase);
      gl.uniform2f(U.mouse, mx, my);
      gl.uniform1f(U.stir, stir);
      gl.uniform1f(U.int, opts.intensity ?? 1);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      if (on) raf = requestAnimationFrame(frame);
    };
    whileVisible(canvas, () => { if (!on) { on = true; raf = requestAnimationFrame(frame); } }, () => { on = false; cancelAnimationFrame(raf); });
  }

  function stream(canvas, opts = {}) {
    if (REDUCE) return;
    const x = canvas.getContext('2d');
    let W = 0, H = 0, dpr = 1, parts = [];
    const N = opts.count || 4200;
    const cyan = opts.color || '#00f0ff', hot = opts.hot || '#ff4d6d';
    // The band: a slow sine ribbon crossing the frame, thicker in the middle.
    const band = (u, t) => {
      const y = opts.y ?? 0.42;
      return H * (y + Math.sin(u * 2.4 + t * 0.22) * 0.09 + Math.sin(u * 5.3 - t * 0.31) * 0.035 + (u - 0.5) * (opts.tilt ?? 0.16));
    };
    const size = () => {
      dpr = Math.min(2, devicePixelRatio || 1); W = canvas.clientWidth; H = canvas.clientHeight;
      canvas.width = W * dpr; canvas.height = H * dpr; x.setTransform(dpr, 0, 0, dpr, 0, 0);
      const n = Math.round(N * Math.min(1.4, W / 1500));
      parts = Array.from({ length: n }, () => {
        const spread = (Math.random() + Math.random() + Math.random() - 1.5) / 1.5; // roughly normal
        return { u: Math.random(), off: spread, z: Math.random(), sp: 0.012 + Math.random() * 0.02, vx: 0, vy: 0, dx: 0, dy: 0, flag: 0, anomaly: Math.random() < 0.06 };
      });
    };
    size(); addEventListener('resize', size);
    // Lens: follows the pointer over the canvas, otherwise wanders along the band.
    const lens = { x: W * 0.55, y: H * 0.45, r: opts.lens || 90, active: false, count: 0, shown: 0 };
    let waves = [];
    canvas.addEventListener('pointermove', (e) => { const r = canvas.getBoundingClientRect(); lens.tx = e.clientX - r.left; lens.ty = e.clientY - r.top; lens.active = true; });
    canvas.addEventListener('pointerleave', () => { lens.active = false; });
    const host = opts.host || canvas;
    host.addEventListener('pointerdown', (e) => { const r = canvas.getBoundingClientRect(); waves.push({ x: e.clientX - r.left, y: e.clientY - r.top, t0: performance.now() }); });
    if (host !== canvas) {
      host.addEventListener('pointermove', (e) => { const r = canvas.getBoundingClientRect(); lens.tx = e.clientX - r.left; lens.ty = e.clientY - r.top; lens.active = true; });
      host.addEventListener('pointerleave', () => { lens.active = false; });
    }
    // Spontaneous bursts so the band never sits still.
    setInterval(() => { if (!document.hidden && W) waves.push({ x: W * (0.15 + Math.random() * 0.7), y: band(Math.random(), performance.now() / 1000), t0: performance.now(), soft: true }); }, 3800);
    let on = false, raf = 0, last = performance.now();
    const frame = (now) => {
      const t = now / 1000, dt = Math.min(0.05, (now - last) / 1000); last = now;
      const boost = 1 + energy * 1.5;
      x.clearRect(0, 0, W, H);
      if (!lens.active) { const wu = (Math.sin(t * 0.13) * 0.5 + 0.5) * 0.8 + 0.1; lens.tx = W * wu; lens.ty = band(wu, t) + Math.sin(t * 0.7) * 20; }
      lens.x += ((lens.tx ?? lens.x) - lens.x) * 0.12; lens.y += ((lens.ty ?? lens.y) - lens.y) * 0.12;
      waves = waves.filter((w) => now - w.t0 < 1800);
      let flagged = 0;
      const thick = H * (opts.thickness ?? 0.085);
      for (const p of parts) {
        p.u += p.sp * dt * boost * (0.6 + p.z * 0.8);
        if (p.u > 1.04) { p.u -= 1.08; p.dx = p.dy = 0; }
        let px = p.u * W, py = band(p.u, t) + p.off * thick * (0.7 + 0.6 * Math.sin(p.u * 9 + t));
        for (const w of waves) {
          const k = Math.max(0, (now - w.t0) / 1800), rad = k * (w.soft ? 260 : 520), dx = px - w.x, dy = py - w.y, dist = Math.hypot(dx, dy) || 1;
          const band2 = Math.abs(dist - rad);
          if (band2 < 40) { const f = (1 - band2 / 40) * (1 - k) * (w.soft ? 10 : 34); p.dx += (dx / dist) * f; p.dy += (dy / dist) * f; }
        }
        p.dx *= 0.93; p.dy *= 0.93;
        px += p.dx; py += p.dy;
        const inLens = (px - lens.x) ** 2 + (py - lens.y) ** 2 < lens.r * lens.r;
        p.flag = inLens ? Math.min(1, p.flag + 0.2) : Math.max(0, p.flag - 0.05);
        const isHot = inLens && p.anomaly;
        if (isHot) flagged++;
        const a = 0.25 + p.z * 0.65;
        if (isHot) { x.fillStyle = hot; x.fillRect(px - 1.6, py - 1.6, 3.2, 3.2); }
        else if (p.flag > 0) { x.fillStyle = `rgba(0,240,255,${0.5 + p.flag * 0.5})`; x.fillRect(px - 1.1, py - 1.1, 2.2, 2.2); }
        else { x.fillStyle = `rgba(${p.z > 0.85 ? '120,248,255' : '0,200,230'},${a})`; x.fillRect(px, py, p.z > 0.7 ? 1.6 : 1.1, p.z > 0.7 ? 1.6 : 1.1); }
        if (isHot && Math.random() < 0.35) { x.strokeStyle = 'rgba(255,77,109,.35)'; x.lineWidth = 0.6; x.beginPath(); x.moveTo(px, py); x.lineTo(lens.x, lens.y); x.stroke(); }
      }
      // shockwave rings
      for (const w of waves) { const k = Math.max(0, (now - w.t0) / 1800); x.strokeStyle = `rgba(0,240,255,${(1 - k) * (w.soft ? 0.25 : 0.7)})`; x.lineWidth = w.soft ? 1 : 1.6; x.beginPath(); x.arc(w.x, w.y, k * (w.soft ? 260 : 520), 0, 7); x.stroke(); }
      // lens ring with ticks and a live count
      lens.count = flagged; lens.shown += (flagged - lens.shown) * 0.2;
      x.strokeStyle = 'rgba(200,245,255,.55)'; x.lineWidth = 1; x.beginPath(); x.arc(lens.x, lens.y, lens.r, 0, 7); x.stroke();
      x.strokeStyle = 'rgba(0,240,255,.9)'; x.lineWidth = 2; x.beginPath(); x.arc(lens.x, lens.y, lens.r, t * 1.6, t * 1.6 + 0.9); x.stroke();
      for (let i = 0; i < 4; i++) { const ang = i * Math.PI / 2 + t * 0.4; x.beginPath(); x.moveTo(lens.x + Math.cos(ang) * (lens.r + 4), lens.y + Math.sin(ang) * (lens.r + 4)); x.lineTo(lens.x + Math.cos(ang) * (lens.r + 12), lens.y + Math.sin(ang) * (lens.r + 12)); x.strokeStyle = 'rgba(0,240,255,.7)'; x.lineWidth = 1; x.stroke(); }
      const left = lens.x + lens.r + 170 > W; x.textAlign = left ? 'right' : 'left'; const lx = left ? lens.x - lens.r - 16 : lens.x + lens.r + 16;
      x.font = '13px "Space Mono", monospace';
      const label = `${Math.round(lens.shown)} flagged`;
      x.fillStyle = flagged ? hot : 'rgba(170,236,255,.75)';
      x.fillText(label, lx, lens.y + 4);
      x.fillStyle = 'rgba(170,236,255,.45)'; x.font = '10.5px "Space Mono", monospace';
      x.fillText(opts.caption || 'anomaly scan', lx, lens.y + 20); x.textAlign = 'left';
      if (on) raf = requestAnimationFrame(frame);
    };
    whileVisible(canvas, () => { if (!on) { on = true; last = performance.now(); raf = requestAnimationFrame(frame); } }, () => { on = false; cancelAnimationFrame(raf); });
  }

  window.OculonFX = { liquid, stream, reduce: REDUCE };
})();

/*
 * Clean addresses: links to a part of the same page scroll there without adding "#section" to the
 * address bar, and a "#section" that arrives from another page is removed once the page has used it.
 * A page with its own views (the app) sets window.onOculonHash(name) to handle names that are not elements.
 */
(function () {
  if (window.__oculonCleanUrl) return;
  window.__oculonCleanUrl = true;
  window.oculonInitialHash = decodeURIComponent(location.hash.slice(1));
  document.addEventListener('click', (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = e.target.closest && e.target.closest('a[href]');
    if (!a || (a.target && a.target !== '_self') || a.hasAttribute('download')) return;
    const raw = a.getAttribute('href');
    if (raw === '#') { e.preventDefault(); return; }
    const u = new URL(a.href, location.href);
    if (!u.hash || u.origin !== location.origin || u.pathname !== location.pathname || u.search !== location.search) return;
    const name = decodeURIComponent(u.hash.slice(1));
    const el = document.getElementById(name);
    if (el) { e.preventDefault(); el.scrollIntoView({ behavior: 'smooth', block: 'start' }); return; }
    if (typeof window.onOculonHash === 'function') { e.preventDefault(); window.onOculonHash(name); }
  });
  const clear = () => { if (location.hash) history.replaceState(history.state, '', location.pathname + location.search); };
  window.oculonClearHash = clear;
  addEventListener('load', () => setTimeout(clear, 2500));
})();
