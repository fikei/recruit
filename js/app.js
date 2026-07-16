/* Agape recruiting viewer — static, zero-backend.
   Data ships AES-GCM-encrypted in data/applicants.enc.json; the house
   passphrase derives the key (PBKDF2). Decisions live in localStorage. */
const VERSION = '1.1.0';
console.log(`[recruit] v${VERSION} - Agape recruiting viewer`);

const LS_DECISIONS = 'agape:decisions';
const SS_KEY = 'agape:pass';

const HOLD_REASONS = [
  { id: 'fit', label: 'Fit needs review' },
  { id: 'timing', label: 'Length of timing' },
  { id: 'needs', label: 'Current Agape needs (e.g. couple)' },
];
const DECISION_LABELS = { outreach: 'Outreach', hold: 'Hold', pass: 'Pass' };

let applicants = [];          // newest first (as shipped)
let decisions = loadDecisions();
let filter = 'all';           // all | undecided | outreach | hold | pass
let queue = [];               // ids in the currently open review queue
let qIndex = 0;

/* ---------- crypto ---------- */
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function decryptPayload(payload, passphrase) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64d(payload.salt), iterations: payload.iterations, hash: 'SHA-256' },
    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(payload.iv) }, key, b64d(payload.ct));
  return JSON.parse(new TextDecoder().decode(plain));
}

/* ---------- decisions store ---------- */
function loadDecisions() {
  try { return JSON.parse(localStorage.getItem(LS_DECISIONS)) || {}; } catch { return {}; }
}
function saveDecision(id, d, reason) {
  if (d === null) { delete decisions[id]; }
  else { decisions[id] = { d, ...(reason ? { reason } : {}), at: new Date().toISOString() }; }
  localStorage.setItem(LS_DECISIONS, JSON.stringify(decisions));
}

/* ---------- helpers ---------- */
const esc = s => String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const initials = a => ((a.first[0] || '') + (a.last[0] || '')).toUpperCase();
const fullName = a => `${a.first} ${a.last}`.trim();
const isSublet = a => /short/i.test(a.residency);
const trackLabel = a => isSublet(a) ? 'Sublet' : 'Full-time';
const fmtDate = iso => new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
const monthKey = iso => iso.slice(0, 7);
const monthLabel = iso => new Date(iso + (iso.length === 7 ? '-01T12:00' : '')).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });

function subLine(a) {
  const bits = [trackLabel(a)];
  const mi = normalizeMoveIn(a);
  const bu = normalizeBudget(a.budget);
  if (mi) bits.push(mi);
  if (bu) bits.push(bu);
  return bits.join(' · ');
}

/* ---------- normalizers (raw text stays behind the (i) tooltip) ---------- */
const MONTHS = ['january','february','march','april','may','june','july','august','september','october','november','december'];
const MONTH_ABBR = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

function normalizeMoveIn(a) {
  const raw = (a.movein || '').trim();
  if (!raw || /^n\/?a$/i.test(raw)) return '';
  const flexible = /flexib|anytime|any time|whenever|open to|open for/i.test(raw);
  if (/asap|as soon as/i.test(raw)) return 'ASAP' + (flexible ? ' · flexible' : '');

  // months mentioned, in text order (dedup, cap at a range of two)
  const found = [];
  const rx = new RegExp(`\\b(${MONTHS.join('|')}|${MONTH_ABBR.join('|')})\\b`, 'gi');
  let m;
  while ((m = rx.exec(raw))) {
    let idx = MONTHS.findIndex(x => x.startsWith(m[1].slice(0, 3).toLowerCase()));
    if (idx >= 0 && !found.includes(idx)) found.push(idx);
  }
  if (!found.length) return flexible ? 'Flexible' : '';

  // a day-of-month next to the first month ("August 1st", "14th July")
  const first = found[0];
  const monthName = `(?:${MONTHS[first]}|${MONTH_ABBR[first]})`;
  const day = raw.match(new RegExp(`${monthName}\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?\\b`, 'i'))
    || raw.match(new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(?:of\\s+)?${monthName}`, 'i'));

  // year: explicit, else inferred from application date
  const yearMatch = raw.match(/\b(20\d{2})\b/);
  const applied = new Date(a.ts_iso);
  const year = yearMatch ? +yearMatch[1] : (first < applied.getMonth() ? applied.getFullYear() + 1 : applied.getFullYear());

  let label;
  if (found.length > 1) {
    const lo = Math.min(...found), hi = Math.max(...found);
    label = `${MONTH_ABBR[lo]}–${MONTH_ABBR[hi]} ${year}`;
  } else if (day) {
    label = `${MONTH_ABBR[first]} ${+day[1]}, ${year}`;
  } else {
    label = `${MONTH_ABBR[first]} ${year}`;
  }
  return label + (flexible ? ' · flexible' : '');
}

function normalizeBudget(raw) {
  raw = (raw || '').trim();
  if (!raw || /^n\/?a$/i.test(raw)) return '';
  // pull dollar-ish numbers: $1,800 · 2000 · 1.2K · 4K/mo
  const nums = [];
  const rx = /\$?\s?(\d{1,2}(?:[.,]\d{1,3})?)\s*[kK]\b|\$?\s?(\d{1,3}(?:,\d{3})+|\d{3,4})(?!\d)/g;
  let m;
  while ((m = rx.exec(raw))) {
    let n = m[1] ? parseFloat(m[1].replace(',', '.')) * 1000 : parseInt(m[2].replace(/,/g, ''), 10);
    if (n >= 300 && n <= 10000) nums.push(Math.round(n));
  }
  if (!nums.length) return /flexib/i.test(raw) ? 'Flexible' : '';
  const fmt = n => '$' + n.toLocaleString('en-US');
  const lo = Math.min(...nums), hi = Math.max(...nums);
  const capped = /up to|max|below|under|less than|<|limit|upper bound|no more than/i.test(raw);
  const plus = /\d\s*\+/.test(raw);
  let label;
  if (lo !== hi) label = `${fmt(lo)}–${fmt(hi)}`;
  else if (capped) label = `Up to ${fmt(hi)}`;
  else if (plus) label = `${fmt(hi)}+`;
  else label = fmt(hi);
  return label + '/mo';
}

/* An (i) dot whose hover/focus reveals the original response text. */
function infoDot(raw, normalized) {
  if (!raw || !normalized || raw.trim() === normalized) return '';
  return `<button class="info-dot" type="button" data-tip="${esc(raw)}" aria-label="Original response">i</button>`;
}

/* ---------- links helper ---------- */
/* Collects links from the socials field and any URLs embedded in the long
   answers; resolves bare handles (@fikei, "IG: name") to clickable profiles. */
const HANDLE_STOPWORDS = /^(https?|www|and|but|not|the|don|dont|use|media|active|com|net|org|only|though|really)$/i;
const LINK_LABELS = [
  [/instagram\.com/i, 'Instagram'], [/linkedin\.com/i, 'LinkedIn'],
  [/facebook\.com/i, 'Facebook'], [/(?:^|\.)x\.com|twitter\.com/i, 'X'],
  [/github\.com/i, 'GitHub'], [/tiktok\.com/i, 'TikTok'],
  [/substack\.com/i, 'Substack'], [/youtube\.com|youtu\.be/i, 'YouTube'],
  [/soundcloud\.com/i, 'SoundCloud'], [/spotify\.com/i, 'Spotify'],
];

function linkLabel(url) {
  try {
    const u = new URL(url);
    for (const [rx, name] of LINK_LABELS) {
      if (rx.test(u.hostname + u.pathname)) {
        let seg = u.pathname.split('/').filter(Boolean).pop() || '';
        // subdomain platforms (akevinyang.substack.com) carry the handle up front
        if (!seg && /substack\.com$/i.test(u.hostname) && !/^www\./i.test(u.hostname)) seg = u.hostname.split('.')[0];
        const handle = decodeURIComponent(seg).replace(/^@/, '').replace(/\/$/, '');
        return handle && !/^(in|company|profile|people)$/i.test(handle) ? `${name} · ${handle}` : name;
      }
    }
    return u.hostname.replace(/^www\./, '') + (u.pathname !== '/' ? u.pathname.replace(/\/$/, '') : '');
  } catch { return url; }
}

function collectLinks(a) {
  const found = new Map(); // normalized url -> {url, label}
  const add = url => {
    if (!url) return;
    url = url.replace(/[.,;:!?)\]]+$/, '');
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    const key = url.toLowerCase().replace(/^https?:\/\/(www\.)?/, '').replace(/\/$/, '');
    if (!found.has(key)) found.set(key, { url, label: linkLabel(url) });
  };

  const social = a.social || '';
  const answers = [a.about, a.why, a.gifts].join('  ');
  const all = social + '  ' + answers;

  // 1. full URLs anywhere
  for (const m of all.matchAll(/https?:\/\/[^\s,<>()"']+/gi)) add(m[0]);
  // 2. bare domains anywhere (skip emails)
  for (const m of all.matchAll(/(?<![@\w.])((?:[a-z0-9-]+\.)+(?:com|org|net|io|co|ai|me|dev|house|fm|xyz))(\/[^\s,<>()"']*)?/gi)) {
    if (/@/.test(m[0])) continue;
    add(m[1] + (m[2] || ''));
  }
  // 3. handles — socials field only, resolved by platform hints in context
  const handleRx = /(?:(insta(?:gram)?|ig|tiktok|twitter|\bx\b|fb|facebook|linkedin)\b[:\s@]*)?@?([a-z0-9._]{3,30})(?:\s*\(?\s*(insta(?:gram)?|ig|tiktok|fb|facebook)\)?)?/gi;
  if (social && !/^(i don'?t|none|n\/?a|right now)/i.test(social.trim())) {
    for (const m of social.matchAll(/(?:^|[\s,])(?:(insta(?:gram)?|ig|tiktok|fb|facebook|linkedin|twitter|x)\b[:\s]*)?@([a-z0-9._]{2,30})\b(?:\s*(?:on\s+)?\(?(insta(?:gram)?|ig|tiktok|fb|facebook)\)?)?/gi)) {
      const hint = (m[1] || m[3] || 'instagram').toLowerCase();
      const handle = m[2];
      if (HANDLE_STOPWORDS.test(handle)) continue;
      const host = /tiktok/.test(hint) ? `tiktok.com/@${handle}`
        : /fb|facebook/.test(hint) ? `facebook.com/${handle}`
        : /linkedin/.test(hint) ? `linkedin.com/in/${handle}`
        : /twitter|^x$/.test(hint) ? `x.com/${handle}`
        : `instagram.com/${handle}`;
      add(host);
    }
    // "IG: rajufromdublin" / "harpershabitat on ig" — platform + bare word, no @
    for (const m of social.matchAll(/(?:(insta(?:gram)?|ig|fb|facebook)\b[:\s]+([a-z0-9._]{3,30})\b|\b([a-z0-9._]{3,30})\s+on\s+(insta(?:gram)?|ig|fb|facebook)\b)/gi)) {
      const hint = (m[1] || m[4] || '').toLowerCase();
      const handle = m[2] || m[3];
      if (!handle || HANDLE_STOPWORDS.test(handle)) continue;
      add(/fb|facebook/.test(hint) ? `facebook.com/${handle}` : `instagram.com/${handle}`);
    }
  }
  return [...found.values()];
}

function decisionChip(id) {
  const rec = decisions[id];
  if (!rec) return '';
  const reason = rec.reason ? ` · ${HOLD_REASONS.find(r => r.id === rec.reason)?.label || rec.reason}` : '';
  return `<span class="decision-chip decision-chip--${rec.d}" title="${esc(DECISION_LABELS[rec.d] + reason)}">${DECISION_LABELS[rec.d]}</span>`;
}

/* ---------- inbox render ---------- */
function matchesFilter(a) {
  const rec = decisions[a.id];
  if (filter === 'all') return true;
  if (filter === 'undecided') return !rec;
  return rec?.d === filter;
}

function counts() {
  const c = { all: applicants.length, undecided: 0, outreach: 0, hold: 0, pass: 0 };
  for (const a of applicants) {
    const rec = decisions[a.id];
    if (!rec) c.undecided++; else c[rec.d]++;
  }
  return c;
}

function renderFilters() {
  const c = counts();
  const defs = [
    ['all', 'All'], ['undecided', 'Needs review'],
    ['outreach', 'Outreach'], ['hold', 'Hold'], ['pass', 'Pass'],
  ];
  document.getElementById('filters').innerHTML = defs.map(([id, label]) =>
    `<button class="chip ${filter === id ? 'is-on' : ''}" data-filter="${id}">${label} <span class="chip__count">${c[id]}</span></button>`
  ).join('');
}

function renderInbox() {
  renderFilters();
  const list = applicants.filter(matchesFilter);
  document.getElementById('page-sub').textContent =
    `${applicants.length} applicants · ${counts().undecided} to review`;

  const host = document.getElementById('inbox');
  if (!list.length) {
    host.innerHTML = `<p class="inbox-empty">Nothing here — every applicant in this view is decided.</p>`;
    return;
  }
  // Group by month, newest group first (list already newest-first).
  const groups = [];
  for (const a of list) {
    const k = monthKey(a.ts_iso);
    if (!groups.length || groups[groups.length - 1].key !== k) groups.push({ key: k, items: [] });
    groups[groups.length - 1].items.push(a);
  }
  host.innerHTML = groups.map(g => `
    <section class="inbox-group">
      <div class="inbox-group__head">
        <h2 class="inbox-group__label">${monthLabel(g.key)}</h2>
        <span class="inbox-group__count">${g.items.length} applicant${g.items.length === 1 ? '' : 's'}</span>
      </div>
      <ul class="inbox-card">
        ${g.items.map(a => `
          <li class="inbox-row">
            <button class="inbox-row__main" data-review="${a.id}">
              <span class="avatar">${esc(initials(a))}</span>
              <span class="inbox-row__text">
                <span class="inbox-row__title">${esc(fullName(a))}</span>
                <span class="inbox-row__sub">${esc(subLine(a))} · applied ${fmtDate(a.ts_iso)}</span>
              </span>
            </button>
            <span class="inbox-row__actions">
              ${decisionChip(a.id)}
              <button class="btn inbox-row__review" data-review="${a.id}">Review</button>
            </span>
          </li>`).join('')}
      </ul>
    </section>`).join('');
}

/* ---------- review overlay ---------- */
function openReview(id) {
  queue = applicants.filter(matchesFilter).map(a => a.id);
  if (!queue.includes(id)) queue = applicants.map(a => a.id);
  qIndex = Math.max(0, queue.indexOf(id));
  document.getElementById('review').hidden = false;
  document.body.style.overflow = 'hidden';
  const url = new URL(location); url.searchParams.set('a', id);
  history.replaceState(null, '', url);
  hideHoldSheet();
  renderReview();
  resetScroll();
}

function closeReview() {
  document.getElementById('review').hidden = true;
  document.body.style.overflow = '';
  const url = new URL(location); url.searchParams.delete('a');
  history.replaceState(null, '', url);
  renderInbox();
}

function step(delta) {
  const next = qIndex + delta;
  if (next < 0 || next >= queue.length) { if (delta > 0) closeReview(); return; }
  qIndex = next;
  hideHoldSheet();
  renderReview();
  resetScroll();
}

function resetScroll() {
  const el = document.querySelector('.review__scroll');
  el.scrollTop = 0;
  requestAnimationFrame(() => { el.scrollTop = 0; });
}

function renderReview() {
  const a = applicants.find(x => x.id === queue[qIndex]);
  if (!a) { closeReview(); return; }
  const url = new URL(location); url.searchParams.set('a', a.id);
  history.replaceState(null, '', url);

  // progress: dots ≤12, else counter
  const dotsHost = document.getElementById('review-progress');
  dotsHost.innerHTML = queue.length <= 12
    ? `<span class="review__dots">${queue.map((_, i) => `<span class="review__dot ${i === qIndex ? 'is-current' : ''}"></span>`).join('')}</span>`
    : `<span class="review__counter">${qIndex + 1} of ${queue.length}</span>`;

  document.getElementById('review-prev').disabled = qIndex === 0;
  document.getElementById('review-next').disabled = qIndex === queue.length - 1;

  const rec = decisions[a.id];
  const links = collectLinks(a);
  const linksHtml = links.length
    ? `<div class="link-chips">${links.map(l =>
        `<a class="link-chip" href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.label)}</a>`).join('')}${a.social ? infoDot(a.social, 'links') : ''}</div>`
    : (a.social ? `<span class="review__fact-value">${esc(a.social)}</span>` : '');
  const miNorm = normalizeMoveIn(a);
  const buNorm = normalizeBudget(a.budget);

  document.getElementById('review-body').innerHTML = `
    ${rec ? `<p class="review__decided">Decided: ${DECISION_LABELS[rec.d]}${rec.reason ? ` — ${esc(HOLD_REASONS.find(r => r.id === rec.reason)?.label || rec.reason)}` : ''} · <button class="link-clear" data-clear="${a.id}">Undo</button></p>` : ''}
    <div class="review__card">
      <div class="review__head">
        <span class="avatar avatar--lg">${esc(initials(a))}</span>
        <div class="review__head-text">
          <h2 class="review__title">${esc(fullName(a))}${a.pronouns ? ` <span class="review__pronouns">${esc(a.pronouns)}</span>` : ''}</h2>
          <p class="review__meta"><a href="mailto:${esc(a.email)}">${esc(a.email)}</a></p>
          <div class="review__badges">
            <span class="review__badge review__badge--track">${trackLabel(a)}</span>
            ${a.source ? `<span class="review__badge" title="How they heard about Agape">${esc(a.source)}</span>` : ''}
          </div>
          <div class="review__facts">
            <div class="review__fact"><span class="review__fact-label">Move-in</span><span class="review__fact-value">${esc(miNorm || a.movein || '—')} ${infoDot(a.movein, miNorm)}</span></div>
            <div class="review__fact"><span class="review__fact-label">Budget</span><span class="review__fact-value">${esc(buNorm || a.budget || '—')} ${infoDot(a.budget, buNorm)}</span></div>
            <div class="review__fact"><span class="review__fact-label">Applied</span><span class="review__fact-value">${new Date(a.ts_iso).toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric' })}</span></div>
            ${linksHtml ? `<div class="review__fact"><span class="review__fact-label">Links</span>${linksHtml}</div>` : ''}
          </div>
        </div>
      </div>
    </div>
    ${section('About them', a.about)}
    ${section('Why Agape', a.why)}
    ${section('Gifts to share', a.gifts)}
  `;

  // footer active states
  for (const d of ['pass', 'hold', 'outreach']) {
    const btn = document.getElementById(`btn-${d}`);
    btn.classList.toggle(`is-active--${d}`, rec?.d === d);
  }
}

function section(title, text) {
  if (!text) return '';
  return `<section class="review__section">
    <h3 class="review__section-title">${title}</h3>
    <p class="review__prose">${esc(text)}</p>
  </section>`;
}

function decide(d, reason) {
  const a = applicants.find(x => x.id === queue[qIndex]);
  if (!a) return;
  saveDecision(a.id, d, reason);
  toast(`${fullName(a)} → ${DECISION_LABELS[d]}${reason ? ` (${HOLD_REASONS.find(r => r.id === reason)?.label})` : ''}`);
  if (qIndex === queue.length - 1) closeReview(); else step(1);
}

/* Hold reason sheet */
function showHoldSheet() {
  const a = applicants.find(x => x.id === queue[qIndex]);
  const current = decisions[a?.id]?.reason;
  document.getElementById('hold-options').innerHTML = HOLD_REASONS.map(r =>
    `<button class="hold-sheet__option ${current === r.id ? 'is-selected' : ''}" data-reason="${r.id}">${r.label}</button>`).join('');
  document.getElementById('hold-sheet').hidden = false;
  document.getElementById('review-foot').hidden = true;
}
function hideHoldSheet() {
  document.getElementById('hold-sheet').hidden = true;
  document.getElementById('review-foot').hidden = false;
}

/* ---------- export ---------- */
function exportCsv() {
  const cols = ['first', 'last', 'email', 'ts', 'residency', 'movein', 'budget', 'source'];
  const head = [...cols, 'decision', 'hold_reason', 'decided_at'];
  const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [head.join(',')];
  for (const a of applicants) {
    const rec = decisions[a.id] || {};
    lines.push([...cols.map(c => q(a[c])), q(DECISION_LABELS[rec.d] || ''),
      q(rec.reason ? (HOLD_REASONS.find(r => r.id === rec.reason)?.label || rec.reason) : ''), q(rec.at || '')].join(','));
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  const aEl = document.createElement('a');
  aEl.href = URL.createObjectURL(blob);
  aEl.download = `agape-decisions-${new Date().toISOString().slice(0, 10)}.csv`;
  aEl.click();
  URL.revokeObjectURL(aEl.href);
}

/* ---------- toast ---------- */
function toast(msg) {
  const host = document.getElementById('toast-host');
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  el.onclick = () => el.remove();
  host.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

/* ---------- theme ---------- */
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  localStorage.setItem('agape:theme', t);
}

/* ---------- boot ---------- */
async function unlock(passphrase) {
  const res = await fetch('data/applicants.enc.json');
  const payload = await res.json();
  applicants = await decryptPayload(payload, passphrase); // throws on bad pass
  sessionStorage.setItem(SS_KEY, passphrase);
  document.getElementById('gate').hidden = true;
  document.getElementById('app').hidden = false;
  renderInbox();
  const deep = new URLSearchParams(location.search).get('a');
  if (deep && applicants.some(x => x.id === deep)) openReview(deep);
}

function init() {
  applyTheme(localStorage.getItem('agape:theme') ||
    (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));

  // gate
  const form = document.getElementById('gate-form');
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const err = document.getElementById('gate-error');
    err.textContent = '';
    const btn = document.getElementById('gate-btn');
    btn.disabled = true; btn.textContent = 'Unlocking…';
    try { await unlock(document.getElementById('gate-input').value.trim()); }
    catch { err.textContent = 'That passphrase didn’t work.'; }
    btn.disabled = false; btn.textContent = 'Unlock';
  });
  const saved = sessionStorage.getItem(SS_KEY);
  if (saved) unlock(saved).catch(() => sessionStorage.removeItem(SS_KEY));

  // delegation
  document.addEventListener('click', e => {
    const review = e.target.closest('[data-review]');
    if (review) { openReview(review.dataset.review); return; }
    const fil = e.target.closest('[data-filter]');
    if (fil) { filter = fil.dataset.filter; renderInbox(); return; }
    const clear = e.target.closest('[data-clear]');
    if (clear) { saveDecision(clear.dataset.clear, null); renderReview(); return; }
    const reason = e.target.closest('[data-reason]');
    if (reason) { hideHoldSheet(); decide('hold', reason.dataset.reason); return; }
    if (!e.target.closest('.page-menu')) document.getElementById('menu-list')?.classList.remove('is-open');
  });

  document.getElementById('menu-trigger').onclick = () =>
    document.getElementById('menu-list').classList.toggle('is-open');
  document.getElementById('menu-export').onclick = () => { exportCsv(); document.getElementById('menu-list').classList.remove('is-open'); };
  document.getElementById('menu-theme').onclick = () => {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    document.getElementById('menu-list').classList.remove('is-open');
  };
  document.getElementById('menu-lock').onclick = () => { sessionStorage.removeItem(SS_KEY); location.search = ''; location.reload(); };
  document.getElementById('menu-sheet').onclick = () =>
    window.open('https://docs.google.com/spreadsheets/d/1dyDpPv7LhFSjL2Nz2E_2GMBIR-qGZg4qW4TjEkt7Epg/edit', '_blank');

  document.getElementById('review-close').onclick = closeReview;
  document.getElementById('review-prev').onclick = () => step(-1);
  document.getElementById('review-next').onclick = () => step(1);
  document.getElementById('btn-pass').onclick = () => decide('pass');
  document.getElementById('btn-outreach').onclick = () => decide('outreach');
  document.getElementById('btn-hold').onclick = showHoldSheet;
  document.getElementById('hold-cancel').onclick = hideHoldSheet;

  document.addEventListener('keydown', e => {
    if (document.getElementById('review').hidden) return;
    if (e.target instanceof Element && e.target.matches('input, textarea')) return;
    if (e.key === 'Escape') { if (!document.getElementById('hold-sheet').hidden) hideHoldSheet(); else closeReview(); }
    if (e.key === 'ArrowRight') step(1);
    if (e.key === 'ArrowLeft') step(-1);
  });
}

document.addEventListener('DOMContentLoaded', init);
