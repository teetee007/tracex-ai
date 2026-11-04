"""Animated widgets rendered in small iframes, because Streamlit strips <script> from markdown.

Each widget animates when it scrolls into view (or its tab is opened) and resets when it leaves,
so it replays every time the viewer comes back to it.
"""
import math

import streamlit as st

from .ui import _ANGLES, GAUGE_ARC, esc

BASE_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');
html,body{margin:0;background:transparent;color:#ececec;font-family:Inter,sans-serif;overflow:hidden}
.row{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.ring{position:relative;width:150px;flex:0 0 150px;text-align:center}
.ring svg{width:100%;display:block;overflow:visible}
.tick{stroke:rgba(255,255,255,.16);stroke-width:1.2;transition:stroke .15s}
.tick.on{stroke:#ececec}
.dial{position:relative}
.num{position:absolute;left:0;right:0;top:35%;font:500 40px 'JetBrains Mono',monospace;line-height:1;color:#ececec}
.num.long{font-size:32px;top:38%}
.unit{position:absolute;left:0;right:0;top:66%;font:500 11px 'JetBrains Mono',monospace;color:#8a8a8a;letter-spacing:1px}
.sub{font:500 10.5px 'JetBrains Mono',monospace;color:#9a9a9a;white-space:nowrap;margin-top:2px}
.title{color:#8a8a8a;font-size:10px;text-transform:uppercase;letter-spacing:.14em;margin-top:3px}
.info{flex:1 1 150px;min-width:150px}
.band{font:700 21px 'JetBrains Mono',monospace;letter-spacing:.14em;text-transform:uppercase;opacity:0;
  transform:translateY(6px);transition:opacity .35s, transform .35s}
.band.on{opacity:1;transform:none}
.band.flash{animation:flash .9s 2}
@keyframes flash{50%{opacity:.25}}
.counts{display:flex;gap:6px;flex-wrap:wrap;margin:9px 0 7px}
.tx-pill{display:inline-block;padding:1px 8px;font:500 10px 'JetBrains Mono',monospace;text-transform:uppercase;
  letter-spacing:.06em;border:1px solid currentColor;border-radius:2px;opacity:0;animation:pin .4s forwards}
.tx-pill:nth-child(2){animation-delay:.12s}.tx-pill:nth-child(3){animation-delay:.24s}
@keyframes pin{to{opacity:1}}
.tx-pill.high{color:#e5484d}.tx-pill.medium{color:#f08c2e}.tx-pill.low{color:#9a9a9a}.tx-pill.ok{color:#46a758}
.note{color:#8a8a8a;font-size:11.5px;line-height:1.45}
"""

SCRIPT = """
const ease = k => k < .5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;   // slow, accelerate, settle
const rings = [...document.querySelectorAll('.ring')].map(el => {
  const arc = el.querySelector('.arc'), head = el.querySelector('.head'), num = el.querySelector('.num');
  return {el, arc, head, num, len: arc.getTotalLength(), ticks: [...el.querySelectorAll('.tick')],
          target: +el.dataset.value, suffix: el.dataset.suffix || '', fixed: el.dataset.fixed};
});
const band = document.querySelector('.band');
let raf;
function draw(r, v) {
  r.arc.setAttribute('stroke-dasharray', `${v} 100`);
  const p = r.arc.getPointAtLength(r.len * v / 100);
  r.head.setAttribute('cx', p.x); r.head.setAttribute('cy', p.y);
  r.head.style.opacity = v > 0.5 ? 1 : 0;
  r.ticks.forEach((t, i) => t.classList.toggle('on', v > 0 && i * 10 <= v));
  r.num.textContent = r.fixed ?? (Math.round(v / 100 * r.scale) + r.suffix);
}
rings.forEach(r => { r.scale = +r.el.dataset.display; });
function reset() { cancelAnimationFrame(raf); rings.forEach(r => draw(r, 0)); if (band) band.className = 'band'; }
function run() {
  reset();
  const t0 = performance.now(), D = 1700;
  const step = now => {
    const k = Math.min(1, (now - t0) / D);
    rings.forEach(r => draw(r, r.target * ease(k)));
    if (k < 1) raf = requestAnimationFrame(step);
    else if (band) { band.className = 'band on' + (band.dataset.flash ? ' flash' : ''); }
  };
  raf = requestAnimationFrame(step);
}
reset();
new IntersectionObserver(es => es.forEach(e => e.isIntersecting ? run() : reset()), {threshold: 0.45})
  .observe(document.body);
"""


def _ticks():
    return "".join(
        f'<line class="tick" x1="{100 + 84 * math.cos(a):.1f}" y1="{95 + 84 * math.sin(a):.1f}" '
        f'x2="{100 + 91 * math.cos(a):.1f}" y2="{95 + 91 * math.sin(a):.1f}"/>' for a in _ANGLES)


def _ring(value, display, suffix, sub, title, color, fixed=None):
    """value: 0–100 fill; display: the number the counter ends on (e.g. 100 or 97)."""
    fixed_attr = f' data-fixed="{esc(fixed)}"' if fixed is not None else ""
    return f"""<div class="ring" data-value="{max(0, min(100, value)):.2f}" data-display="{display}"
  data-suffix="{esc(suffix)}"{fixed_attr}>
  <div class="dial"><svg viewBox="0 0 200 175">{_ticks()}
    <path d="{GAUGE_ARC}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="8"/>
    <path class="arc" d="{GAUGE_ARC}" fill="none" stroke="{color}" stroke-width="8" pathLength="100" stroke-dasharray="0 100"/>
    <circle class="head" r="5.5" fill="{color}" style="filter:drop-shadow(0 0 6px {color})"/>
  </svg>
    <div class="num{' long' if len(str(display) + suffix) >= 4 else ''}">0</div>
    {f'<div class="unit">{esc(sub)}</div>' if len(sub) <= 6 else ''}
  </div>
  {f'<div class="sub">{esc(sub)}</div>' if len(sub) > 6 else ''}
  {f'<div class="title">{esc(title)}</div>' if title else ''}
</div>"""


def _page(body, height):
    st.iframe(f"<!doctype html><html><head><meta charset='utf-8'><style>{BASE_CSS}</style></head>"
                    f"<body>{body}<script>{SCRIPT}</script></body></html>", height=height)


def threat_gauge(score, band, color, counts_html, flash):
    info = (f'<div class="info"><div class="band" style="color:{color}"{" data-flash=1" if flash else ""}>{esc(band)}</div>'
            f'<div class="counts">{counts_html}</div>'
            f'<div class="note">20 pts per high rule, 8 per medium, 2 per low. Each rule counts once; max 100.</div></div>')
    _page(f'<div class="row">{_ring(score, score, "", "/ 100", "", color)}{info}</div>', height=180)


def ring_row(items):
    """items: (value 0–100 or None, suffix, sub, title, colour)."""
    rings = "".join(
        _ring(0 if v is None else v, 0 if v is None else round(v), suffix, sub, title, color,
              fixed="—" if v is None else None)
        for v, suffix, sub, title, color in items)
    _page(f'<div class="row">{rings}</div>', height=200)
