/* === FUFU Intelligence — Daily Report === */

const API_BASE = "https://api.btcmine.info";
const SYMBOL = "FUFU";
const SYMBOL_LC = "fufu";
const AUTH_HASH = "f65bae74278241c3d2364c3754742bc5ced87a8dfe170146571c5bcc7ba993ba";
const AUTH_KEY = "fufu_auth_v1";

let REPORT = null; // current report data

// ─── Auth ───────────────────────────────────────────────
async function sha256(text) {
    if (globalThis.crypto?.subtle) {
        const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    }
    function rr(n,x){return(x>>>n)|(x<<(32-n))}
    function ch(x,y,z){return(x&y)^(~x&z)}
    function maj(x,y,z){return(x&y)^(x&z)^(y&z)}
    function s0(x){return rr(2,x)^rr(13,x)^rr(22,x)}
    function s1(x){return rr(6,x)^rr(11,x)^rr(25,x)}
    function g0(x){return rr(7,x)^rr(18,x)^(x>>>3)}
    function g1(x){return rr(17,x)^rr(19,x)^(x>>>10)}
    const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
             0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
             0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
             0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
             0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
             0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
             0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
             0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    const bytes=new TextEncoder().encode(text);
    const bits=bytes.length*8;
    const pad=new Uint8Array(((bytes.length+9+63)&~63));
    pad.set(bytes);pad[bytes.length]=0x80;
    const dv=new DataView(pad.buffer);
    dv.setUint32(pad.length-4,bits);
    let[h0,h1,h2,h3,h4,h5,h6,h7]=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    for(let o=0;o<pad.length;o+=64){
        const w=new Array(64);
        for(let i=0;i<16;i++)w[i]=dv.getUint32(o+i*4);
        for(let i=16;i<64;i++)w[i]=(g1(w[i-2])+w[i-7]+g0(w[i-15])+w[i-16])>>>0;
        let[a,b,c,d,e,f,g,h]=[h0,h1,h2,h3,h4,h5,h6,h7];
        for(let i=0;i<64;i++){
            const t1=(h+s1(e)+ch(e,f,g)+K[i]+w[i])>>>0;
            const t2=(s0(a)+maj(a,b,c))>>>0;
            h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
        }
        h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;
        h4=(h4+e)>>>0;h5=(h5+f)>>>0;h6=(h6+g)>>>0;h7=(h7+h)>>>0;
    }
    return[h0,h1,h2,h3,h4,h5,h6,h7].map(v=>v.toString(16).padStart(8,"0")).join("");
}

function isAuthed() { return localStorage.getItem(AUTH_KEY) === AUTH_HASH; }
function logout() { localStorage.removeItem(AUTH_KEY); location.reload(); }

async function handleAuth() {
    const pwd = document.getElementById("auth-password").value;
    const hash = await sha256(pwd);
    if (hash === AUTH_HASH) {
        localStorage.setItem(AUTH_KEY, AUTH_HASH);
        showReport();
    } else {
        document.getElementById("auth-error").textContent = "Invalid access code";
        document.getElementById("auth-password").value = "";
        document.getElementById("auth-password").focus();
    }
}

function showReport() {
    document.getElementById("auth-gate").classList.add("hidden");
    document.getElementById("report-page").classList.remove("hidden");
    loadLatestReport(); // history is populated after dashboard loads
}

// ─── API ────────────────────────────────────────────────
async function fetchAPI(path) {
    try {
        const r = await fetch(`${API_BASE}${path}`, { signal: AbortSignal.timeout(15000) });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return await r.json();
    } catch (e) {
        console.warn(`API ${path}: ${e.message}`);
        return null;
    }
}

// ─── Dashboard → Report Transform ──────────────────────
// All data comes from the aggregated /dashboard endpoint (Cloudflare WAF blocks individual endpoints)
let DASHBOARD = null;

function transformDashboard(d) {
    const market = d.market || {};
    const wb = d.webull || {};
    const rpt = d.latest_report || {};
    const corr = d.correlation || {};
    const corrData = corr.data || corr;

    // Build peers array from market_peers dict
    const peersArr = [];
    if (d.market_peers && typeof d.market_peers === "object") {
        for (const [sym, info] of Object.entries(d.market_peers)) {
            peersArr.push({ symbol: sym, ...info });
        }
    }

    return {
        report_date: rpt.report_date || new Date().toISOString().slice(0, 10),
        generated_at: rpt.generated_at || "",
        report: {
            // Price / Level 1 — merge yfinance market + webull quote
            price: market,
            level1: market,
            // Webull data (capital flow, after hours, quote)
            webull: wb,
            // BTC context
            btc_context: {
                btc_price: d.btc_price,
                corr_7d: corrData.corr_7d ?? corrData.latest_corr_7d,
                corr_30d: corrData.corr_30d,
                corr_90d: corrData.corr_90d,
                beta_30d: corrData.beta_30d,
            },
            // Technicals
            technicals: d.indicators || {},
            // Analyst
            analyst: d.analyst || {},
            // Peer comparison
            peer_comparison: { peers: peersArr },
            // Short / Dark
            short_interest: d.short_interest || [],
            dark_pool: d.darkpool || [],
            // Ownership / Insider
            insider_trades_30d: d.insider || [],
            ownership_changes_90d: d.ownership || [],
            sec_events_30d: d.events || [],
            // Alerts
            alerts_today: d.alerts || [],
            // Commentary & Score (from daily report)
            commentary: rpt.commentary || {},
            score: rpt.score,
            score_details: rpt.score_details,
        },
    };
}

// ─── Report Loading ─────────────────────────────────────
async function loadLatestReport() {
    showLoading();
    const data = await fetchAPI(`/api/equity/${SYMBOL_LC}/dashboard`);
    if (data) {
        DASHBOARD = data;
        REPORT = transformDashboard(data);
        renderReport();
    } else {
        showError("Failed to load report data. API may be unavailable.");
    }
}

async function loadReportByDate(date) {
    // Date selection not yet supported through Cloudflare — show info
    if (!DASHBOARD) return;
    showError(`Historical report for ${date} — feature coming soon. Showing latest report.`);
    setTimeout(() => { if (REPORT) renderReport(); showContent(); }, 1500);
}

async function loadHistory() {
    // Load from dashboard's report_history field
    if (!DASHBOARD && !REPORT) {
        // Dashboard not loaded yet — will be called after loadLatestReport via renderReport
        return;
    }
    populateHistory();
}

function populateHistory() {
    const sel = document.getElementById("history-select");
    const hist = DASHBOARD?.report_history || [];
    sel.innerHTML = '<option value="">Report History</option>';
    for (const h of hist) {
        const opt = document.createElement("option");
        opt.value = h.report_date;
        opt.textContent = `${h.report_date} (${h.score != null ? 'Score: ' + h.score : ''})`;
        sel.appendChild(opt);
    }
}

function showLoading() {
    document.getElementById("report-loading").classList.remove("hidden");
    document.getElementById("report-content").classList.add("hidden");
    document.getElementById("report-error").classList.add("hidden");
}

function showError(msg) {
    document.getElementById("report-loading").classList.add("hidden");
    document.getElementById("report-content").classList.add("hidden");
    document.getElementById("report-error").classList.remove("hidden");
    document.getElementById("report-error-msg").textContent = msg;
}

function showContent() {
    document.getElementById("report-loading").classList.add("hidden");
    document.getElementById("report-content").classList.remove("hidden");
    document.getElementById("report-error").classList.add("hidden");
}

// ─── Utilities ──────────────────────────────────────────
function fmtNum(n) {
    if (n == null || isNaN(n)) return "--";
    n = Number(n);
    if (Math.abs(n) >= 1e9) return (n / 1e9).toFixed(2) + "B";
    if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(2) + "M";
    if (Math.abs(n) >= 1e3) return (n / 1e3).toFixed(1) + "K";
    return n.toLocaleString("en-US");
}

function fmtPct(n, decimals = 2) {
    if (n == null || isNaN(n)) return "--";
    const v = Number(n).toFixed(decimals);
    return (v > 0 ? "+" : "") + v + "%";
}

function fmtPrice(n) {
    if (n == null || isNaN(n)) return "--";
    return "$" + Number(n).toFixed(2);
}

function fmtPriceFull(n) {
    if (n == null || isNaN(n)) return "--";
    return "$" + Number(n).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function esc(s) {
    if (!s) return "";
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
}

function safeGet(obj, path, fallback = null) {
    return path.split(".").reduce((o, k) => (o && o[k] != null ? o[k] : fallback), obj);
}

function colorPct(val) {
    if (val == null) return "";
    return Number(val) >= 0 ? "var(--green)" : "var(--red)";
}

function toneColor(tone) {
    if (!tone) return "var(--text-dim)";
    const t = tone.toLowerCase();
    if (t.includes("bullish") || t.includes("bull")) return "var(--green)";
    if (t.includes("bearish") || t.includes("bear")) return "var(--red)";
    return "var(--accent)";
}

function toneBadgeClass(tone) {
    if (!tone) return "tone-neutral";
    const t = tone.toLowerCase();
    if (t.includes("bullish") || t.includes("bull")) return "tone-bullish";
    if (t.includes("bearish") || t.includes("bear")) return "tone-bearish";
    return "tone-neutral";
}

function signalBadgeClass(signal) {
    if (!signal) return "signal-neutral";
    const s = signal.toUpperCase();
    if (s.includes("BUY")) return "signal-buy";
    if (s.includes("SELL")) return "signal-sell";
    return "signal-neutral";
}

function rangeBar(low, high, current, lowLabel, highLabel) {
    if (low == null || high == null || current == null) return '<div class="empty">N/A</div>';
    const range = high - low;
    const pos = range > 0 ? ((current - low) / range * 100).toFixed(1) : 50;
    return `<div style="display:flex;align-items:center;gap:8px;font-size:13px;margin:8px 0">
        <span style="min-width:60px;text-align:right">${lowLabel || fmtPrice(low)}</span>
        <div style="flex:1;height:6px;background:var(--bg-input);border-radius:3px;position:relative">
            <div style="position:absolute;left:${pos}%;top:-3px;width:12px;height:12px;background:var(--accent);border-radius:50%;transform:translateX(-50%)"></div>
        </div>
        <span style="min-width:60px">${highLabel || fmtPrice(high)}</span>
    </div>`;
}

// ─── Render Report ──────────────────────────────────────
function renderReport() {
    if (!REPORT) return;

    const r = REPORT.report || REPORT;
    const reportDate = REPORT.report_date || r.meta?.report_date || "--";
    const generatedAt = REPORT.generated_at || r.meta?.generated_at || "--";

    // Update page title and meta
    document.title = `${reportDate} Daily Report | FUFU Intelligence`;
    document.getElementById("print-date").textContent = reportDate;
    document.getElementById("report-generated").textContent = `Generated: ${generatedAt}`;

    // Set date picker value
    if (reportDate && reportDate !== "--") {
        document.getElementById("date-picker").value = reportDate;
    }

    // Render report meta
    renderMeta(r, reportDate, generatedAt);

    // Render all sections
    renderSnapshot(r);
    renderPriceAction(r);
    renderCapitalFlow(r);
    renderAfterHours(r);
    renderTechSignals(r);
    renderAnalyst(r);
    renderPeers(r);
    renderValuation(r);
    renderShortDark(r);
    renderOwnership(r);
    renderBTCCorrelation(r);
    renderCommentary(r);

    // Populate history dropdown after dashboard is loaded
    populateHistory();

    showContent();
}

// ─── Section: Meta ──────────────────────────────────────
function renderMeta(r, reportDate, generatedAt) {
    const el = document.getElementById("report-meta");
    const alerts = r.alerts_today || [];
    let alertsHtml = "";
    if (alerts.length) {
        alertsHtml = `<div class="report-alerts">${alerts.map(a =>
            `<span class="alert-badge alert-${a.severity || 'medium'}">${esc(a.message || a.title || a.type || "Alert")}</span>`
        ).join("")}</div>`;
    }
    el.innerHTML = `
        <div class="report-meta-row">
            <span class="report-meta-item">Report Date: <strong>${reportDate}</strong></span>
            <span class="report-meta-item">Symbol: <strong>FUFU (BitFuFu Inc)</strong></span>
            <span class="report-meta-item">Generated: <strong>${generatedAt}</strong></span>
        </div>
        ${alertsHtml}
    `;
}

// ─── Section 1: Executive Snapshot ──────────────────────
function renderSnapshot(r) {
    const el = document.getElementById("snapshot-content");
    const price = r.price || {};
    const level1 = r.level1 || {};
    const btc = r.btc_context || {};
    const commentary = r.commentary || {};
    const alerts = r.alerts_today || [];
    const webull = r.webull || {};
    const quote = webull.quote || {};

    const closePrice = price.close || price.price || level1.price || "--";
    const changePct = price.change_pct ?? level1.change_pct ?? null;
    const volume = price.volume || level1.volume || "--";
    const rvol = level1.relative_volume ?? price.relative_volume ?? null;
    const ahPrice = safeGet(webull, "after_hours.price");
    const ahChange = safeGet(webull, "after_hours.change_pct");
    const btcPrice = btc.btc_price || btc.price;
    const corr7d = btc.corr_7d ?? btc.correlation_7d;
    const marketCap = level1.market_cap || price.market_cap || quote.market_cap;
    const pe = quote.pe || price.pe;
    const floatShares = level1.float || price.float;
    const tone = commentary.overall_tone || commentary.tone;

    let html = `<div class="snapshot-grid">`;

    // Price block
    html += `<div class="snapshot-price-block">
        <div class="snapshot-price" style="color:${colorPct(changePct)}">${fmtPrice(closePrice)}</div>
        <div class="snapshot-change" style="color:${colorPct(changePct)}">${fmtPct(changePct)}</div>
        <div class="snapshot-label">Close Price</div>
    </div>`;

    // Key metrics
    html += `<div class="snapshot-metrics">
        <div class="report-metric">
            <span class="report-metric-label">Volume</span>
            <span class="report-metric-value">${fmtNum(volume)}</span>
        </div>
        <div class="report-metric">
            <span class="report-metric-label">Rel. Volume</span>
            <span class="report-metric-value">${rvol != null ? `<span class="rvol-badge ${rvol >= 2 ? 'rvol-high' : rvol >= 0.8 ? 'rvol-normal' : 'rvol-low'}">${Number(rvol).toFixed(2)}x</span>` : '--'}</span>
        </div>
        <div class="report-metric">
            <span class="report-metric-label">After Hours</span>
            <span class="report-metric-value" style="color:${colorPct(ahChange)}">${ahPrice != null ? fmtPrice(ahPrice) + ' (' + fmtPct(ahChange) + ')' : 'N/A'}</span>
        </div>
        <div class="report-metric">
            <span class="report-metric-label">BTC Price</span>
            <span class="report-metric-value">${btcPrice != null ? '$' + Number(btcPrice).toLocaleString("en-US", {maximumFractionDigits:0}) : 'N/A'}</span>
        </div>
        <div class="report-metric">
            <span class="report-metric-label">BTC Corr (7d)</span>
            <span class="report-metric-value">${corr7d != null ? Number(corr7d).toFixed(3) : 'N/A'}</span>
        </div>
        <div class="report-metric">
            <span class="report-metric-label">Market Cap</span>
            <span class="report-metric-value">${marketCap != null ? '$' + fmtNum(marketCap) : 'N/A'}</span>
        </div>
        <div class="report-metric">
            <span class="report-metric-label">P/E Ratio</span>
            <span class="report-metric-value">${pe ?? 'N/A'}</span>
        </div>
        <div class="report-metric">
            <span class="report-metric-label">Float</span>
            <span class="report-metric-value">${floatShares != null ? fmtNum(floatShares) : 'N/A'}</span>
        </div>
    </div>`;

    html += `</div>`;

    // Alerts
    if (alerts.length) {
        html += `<div class="snapshot-alerts">`;
        for (const a of alerts) {
            html += `<span class="alert-badge alert-${a.severity || 'medium'}">${esc(a.message || a.title || a.type || "Alert")}</span>`;
        }
        html += `</div>`;
    }

    // Tone
    if (tone) {
        html += `<div class="snapshot-tone">
            <span class="tone-label">Overall Tone:</span>
            <span class="tone-badge ${toneBadgeClass(tone)}">${esc(tone.toUpperCase())}</span>
        </div>`;
    }

    el.innerHTML = html;
}

// ─── Section 2: Price Action & Trading ──────────────────
function renderPriceAction(r) {
    const el = document.getElementById("price-action-content");
    const price = r.price || {};
    const level1 = r.level1 || {};
    const m = { ...level1, ...price };

    let html = '<div class="grid-2">';

    // OHLC Table
    html += `<div class="report-card-inner">
        <h4>OHLC</h4>
        <div class="stat-row"><span class="stat-label">Open</span><span class="stat-value">${fmtPrice(m.open)}</span></div>
        <div class="stat-row"><span class="stat-label">High</span><span class="stat-value" style="color:var(--green)">${fmtPrice(m.high)}</span></div>
        <div class="stat-row"><span class="stat-label">Low</span><span class="stat-value" style="color:var(--red)">${fmtPrice(m.low)}</span></div>
        <div class="stat-row"><span class="stat-label">Close</span><span class="stat-value">${fmtPrice(m.close || m.price)}</span></div>
        <div class="stat-row"><span class="stat-label">Prev Close</span><span class="stat-value">${fmtPrice(m.prev_close)}</span></div>
        <div class="stat-row"><span class="stat-label">VWAP</span><span class="stat-value" style="color:var(--accent)">${m.vwap != null ? '$' + Number(m.vwap).toFixed(4) : 'N/A'}</span></div>
        <div class="stat-row"><span class="stat-label">Vibrate Ratio</span><span class="stat-value">${m.vibrate_ratio != null ? Number(m.vibrate_ratio).toFixed(4) : 'N/A'}</span></div>
    </div>`;

    // Volume & Range
    html += `<div class="report-card-inner">
        <h4>Volume Analysis</h4>
        <div class="stat-row"><span class="stat-label">Volume</span><span class="stat-value">${fmtNum(m.volume)}</span></div>
        <div class="stat-row"><span class="stat-label">Avg Volume</span><span class="stat-value">${fmtNum(m.avg_volume)}</span></div>
        <div class="stat-row"><span class="stat-label">10D Avg Volume</span><span class="stat-value">${fmtNum(m.avg_volume_10d)}</span></div>
        <div class="stat-row"><span class="stat-label">Relative Volume</span><span class="stat-value">${m.relative_volume != null ? `<span class="rvol-badge ${m.relative_volume >= 2 ? 'rvol-high' : m.relative_volume >= 0.8 ? 'rvol-normal' : 'rvol-low'}">${Number(m.relative_volume).toFixed(2)}x ${m.relative_volume >= 2 ? 'HIGH' : m.relative_volume >= 0.8 ? 'NORMAL' : 'LOW'}</span>` : 'N/A'}</span></div>
    </div>`;

    html += '</div>';

    // Day range bar
    if (m.low != null && m.high != null && (m.close || m.price)) {
        html += `<div class="report-card-inner" style="margin-top:16px">
            <h4>Day Range</h4>
            ${rangeBar(m.low, m.high, m.close || m.price, fmtPrice(m.low), fmtPrice(m.high))}
        </div>`;
    }

    // 52-week range bar
    if (m.week52_low != null && m.week52_high != null && (m.close || m.price)) {
        html += `<div class="report-card-inner" style="margin-top:12px">
            <h4>52-Week Range</h4>
            ${rangeBar(m.week52_low, m.week52_high, m.close || m.price,
                `<span style="color:var(--red)">${fmtPrice(m.week52_low)}</span>`,
                `<span style="color:var(--green)">${fmtPrice(m.week52_high)}</span>`)}
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px">
                From 52W High: ${m.from_52h_pct || '--'}% | From 52W Low: +${m.from_52l_pct || '--'}%
            </div>
        </div>`;
    }

    // Buy/Sell Pressure
    if (m.buy_pct != null) {
        const sellPct = (100 - m.buy_pct).toFixed(1);
        html += `<div class="report-card-inner" style="margin-top:16px">
            <h4>Buy/Sell Pressure</h4>
            <div class="pressure-bar">
                <div class="pressure-buy" style="width:${m.buy_pct}%">BUY ${Number(m.buy_pct).toFixed(1)}%</div>
                <div class="pressure-sell" style="width:${sellPct}%">SELL ${sellPct}%</div>
            </div>
            <div class="grid-2" style="margin-top:8px">
                <div class="stat-row"><span class="stat-label">Buy Volume</span><span class="stat-value" style="color:var(--green)">${fmtNum(m.buy_volume)}</span></div>
                <div class="stat-row"><span class="stat-label">Sell Volume</span><span class="stat-value" style="color:var(--red)">${fmtNum(m.sell_volume)}</span></div>
            </div>
        </div>`;
    }

    el.innerHTML = html;
}

// ─── Section 3: Capital Flow ────────────────────────────
function renderCapitalFlow(r) {
    const el = document.getElementById("capital-flow-content");
    const wb = r.webull || {};
    const cf = wb.capital_flow;
    if (!cf) { el.innerHTML = '<div class="empty">No capital flow data</div>'; return; }

    const categories = [
        { label: "Major (Inst.)", net: cf.major_net || 0, inflow: cf.major_inflow || 0, outflow: cf.major_outflow || 0 },
        { label: "Large Orders", net: cf.large_net || 0 },
        { label: "Medium Orders", net: cf.medium_net || 0 },
        { label: "Small (Retail)", net: cf.small_net || 0 },
    ];
    const maxVal = Math.max(...categories.map(c => Math.abs(c.net)), 1);

    let html = `<div class="grid-2">`;

    // Net flow bars
    html += `<div class="report-card-inner">
        <h4>Net Flow by Order Size</h4>`;
    for (const cat of categories) {
        const pct = Math.abs(cat.net) / maxVal * 100;
        html += `<div class="vol-bar-row" style="margin-bottom:6px">
            <span class="vol-bar-label" style="width:100px">${cat.label}</span>
            <div class="vol-bar-track">
                <div class="vol-bar-fill" style="width:${Math.min(pct,100)}%;background:${cat.net >= 0 ? 'var(--green)' : 'var(--red)'}"></div>
            </div>
            <span class="vol-bar-val" style="width:80px;color:${cat.net >= 0 ? 'var(--green)' : 'var(--red)'}">${cat.net >= 0 ? '+' : ''}$${fmtNum(Math.abs(cat.net))}</span>
        </div>`;
    }
    html += `</div>`;

    // Inflow composition
    const totalIn = (cf.major_inflow || 0) + (cf.retail_inflow || 0);
    const majorPct = totalIn > 0 ? ((cf.major_inflow || 0) / totalIn * 100).toFixed(1) : 0;
    html += `<div class="report-card-inner">
        <h4>Inflow Composition</h4>
        ${totalIn > 0 ? `<div class="pressure-bar" style="margin:8px 0">
            <div class="pressure-buy" style="width:${majorPct}%;background:var(--blue)">Inst ${majorPct}%</div>
            <div class="pressure-sell" style="width:${100 - majorPct}%;background:var(--purple)">Retail ${(100 - majorPct).toFixed(1)}%</div>
        </div>` : '<div class="empty">N/A</div>'}
        <div class="stat-row"><span class="stat-label">Inst. Inflow %</span><span class="stat-value">${(cf.major_inflow_pct || 0).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label">Inst. Outflow %</span><span class="stat-value">${(cf.major_outflow_pct || 0).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label">Retail Inflow %</span><span class="stat-value">${(cf.retail_inflow_pct || 0).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label">Retail Outflow %</span><span class="stat-value">${(cf.retail_outflow_pct || 0).toFixed(1)}%</span></div>
    </div>`;

    html += `</div>`;

    // 5-day history
    const hist = wb.capital_flow_history;
    if (hist && hist.length) {
        html += `<div class="report-card-inner" style="margin-top:16px">
            <h4>5-Day Flow History</h4>
            <table class="data-table">
                <thead><tr><th>Date</th><th class="num">Major Net</th><th class="num">Large Net</th><th class="num">Medium Net</th><th class="num">Small Net</th><th class="num">Total Net</th></tr></thead>
                <tbody>${hist.slice(0, 5).map(h => {
                    const total = (h.major_net || 0) + (h.large_net || 0) + (h.medium_net || 0) + (h.small_net || 0);
                    const dt = h.date || '--';
                    return `<tr>
                        <td>${dt}</td>
                        <td class="num" style="color:${(h.major_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${fmtNum(h.major_net||0)}</td>
                        <td class="num" style="color:${(h.large_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${fmtNum(h.large_net||0)}</td>
                        <td class="num" style="color:${(h.medium_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${fmtNum(h.medium_net||0)}</td>
                        <td class="num" style="color:${(h.small_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${fmtNum(h.small_net||0)}</td>
                        <td class="num" style="color:${total >= 0 ? 'var(--green)' : 'var(--red)'}; font-weight:700">${total >= 0 ? '+' : ''}$${fmtNum(Math.abs(total))}</td>
                    </tr>`;
                }).join("")}</tbody>
            </table>
        </div>`;
    }

    el.innerHTML = html;
}

// ─── Section 4: After Hours ─────────────────────────────
function renderAfterHours(r) {
    const el = document.getElementById("after-hours-content");
    const wb = r.webull || {};
    const ah = wb.after_hours;
    const quote = wb.quote || {};

    if (!ah) { el.innerHTML = '<div class="empty">No after-hours data</div>'; return; }

    el.innerHTML = `<div class="grid-2">
        <div class="report-card-inner">
            <h4>After Hours Trading</h4>
            <div class="stat-row"><span class="stat-label">AH Price</span><span class="stat-value" style="color:${colorPct(ah.change_pct)}">${fmtPrice(ah.price)}</span></div>
            <div class="stat-row"><span class="stat-label">AH Change</span><span class="stat-value" style="color:${colorPct(ah.change_pct)}">${fmtPct(ah.change_pct)}</span></div>
            <div class="stat-row"><span class="stat-label">AH Volume</span><span class="stat-value">${fmtNum(ah.volume)}</span></div>
            <div class="stat-row"><span class="stat-label">AH Range</span><span class="stat-value">${ah.low != null && ah.high != null ? fmtPrice(ah.low) + ' — ' + fmtPrice(ah.high) : 'N/A'}</span></div>
        </div>
        <div class="report-card-inner">
            <h4>Key Metrics</h4>
            <div class="stat-row"><span class="stat-label">P/E (TTM)</span><span class="stat-value">${quote.pe ?? 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">EPS</span><span class="stat-value">${quote.eps != null ? '$' + Number(quote.eps).toFixed(2) : 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">P/B</span><span class="stat-value">${quote.pb ?? 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">P/S</span><span class="stat-value">${quote.ps ?? 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">Forward P/E</span><span class="stat-value">${quote.forward_pe ?? quote.forwardPe ?? 'N/A'}</span></div>
        </div>
    </div>`;
}

// ─── Section 5: Technical Signals ───────────────────────
function renderTechSignals(r) {
    const el = document.getElementById("tech-signals-content");
    const tech = r.technicals || {};
    const indicators = tech.indicators || tech;

    if (!indicators || !Object.keys(indicators).length) {
        el.innerHTML = '<div class="empty">No technical indicator data</div>';
        return;
    }

    let html = '<div class="grid-2">';

    // RSI
    const rsi = indicators.RSI_14 || indicators.rsi || indicators.RSI;
    if (rsi) {
        const rsiVal = Number(rsi.value ?? rsi);
        const rsiZone = rsiVal > 70 ? "Overbought" : rsiVal < 30 ? "Oversold" : "Neutral";
        const rsiColor = rsiVal > 70 ? "var(--red)" : rsiVal < 30 ? "var(--green)" : "var(--accent)";
        html += `<div class="report-card-inner">
            <h4>RSI (14)</h4>
            <div class="rsi-gauge">
                <div class="rsi-value" style="color:${rsiColor}">${rsiVal.toFixed(2)}</div>
                <div class="rsi-zone" style="color:${rsiColor}">${rsiZone}</div>
                <div class="rsi-bar">
                    <div class="rsi-bar-zone rsi-oversold" style="width:30%">30</div>
                    <div class="rsi-bar-zone rsi-neutral" style="width:40%"></div>
                    <div class="rsi-bar-zone rsi-overbought" style="width:30%">70</div>
                    <div class="rsi-bar-marker" style="left:${Math.min(Math.max(rsiVal, 0), 100)}%"></div>
                </div>
            </div>
        </div>`;
    }

    // MACD
    const macd = indicators.MACD || indicators.macd;
    if (macd) {
        const macdVal = macd.value ?? macd.macd ?? 0;
        const signal = macd.extra?.signal ?? macd.signal ?? 0;
        const histogram = macd.extra?.histogram ?? macd.histogram ?? 0;
        html += `<div class="report-card-inner">
            <h4>MACD</h4>
            <div class="stat-row"><span class="stat-label">MACD</span><span class="stat-value">${Number(macdVal).toFixed(4)}</span></div>
            <div class="stat-row"><span class="stat-label">Signal</span><span class="stat-value">${Number(signal).toFixed(4)}</span></div>
            <div class="stat-row"><span class="stat-label">Histogram</span><span class="stat-value" style="color:${Number(histogram) >= 0 ? 'var(--green)' : 'var(--red)'}">${Number(histogram).toFixed(4)}</span></div>
        </div>`;
    }

    html += '</div><div class="grid-2" style="margin-top:16px">';

    // Bollinger Bands
    const bb = indicators.BB || indicators.bollinger;
    if (bb) {
        const upper = bb.extra?.upper ?? bb.upper ?? 0;
        const lower = bb.extra?.lower ?? bb.lower ?? 0;
        const middle = bb.value ?? bb.middle ?? 0;
        html += `<div class="report-card-inner">
            <h4>Bollinger Bands</h4>
            <div class="stat-row"><span class="stat-label">Upper</span><span class="stat-value" style="color:var(--red)">${Number(upper).toFixed(4)}</span></div>
            <div class="stat-row"><span class="stat-label">Middle</span><span class="stat-value">${Number(middle).toFixed(4)}</span></div>
            <div class="stat-row"><span class="stat-label">Lower</span><span class="stat-value" style="color:var(--green)">${Number(lower).toFixed(4)}</span></div>
        </div>`;
    }

    // EMA Crossover
    const ema7 = indicators.EMA_7 || indicators.ema_7;
    const ema25 = indicators.EMA_25 || indicators.ema_25;
    const ema99 = indicators.EMA_99 || indicators.ema_99;
    if (ema7 || ema25 || ema99) {
        html += `<div class="report-card-inner">
            <h4>EMA Crossover</h4>
            ${ema7 ? `<div class="stat-row"><span class="stat-label">EMA 7</span><span class="stat-value">${Number(ema7.value ?? ema7).toFixed(4)}</span></div>` : ''}
            ${ema25 ? `<div class="stat-row"><span class="stat-label">EMA 25</span><span class="stat-value">${Number(ema25.value ?? ema25).toFixed(4)}</span></div>` : ''}
            ${ema99 ? `<div class="stat-row"><span class="stat-label">EMA 99</span><span class="stat-value">${Number(ema99.value ?? ema99).toFixed(4)}</span></div>` : ''}
        </div>`;
    }

    html += '</div>';

    // Overall signal
    const overallSignal = tech.overall_signal || tech.signal || indicators.overall_signal;
    if (overallSignal) {
        html += `<div style="margin-top:16px;text-align:center">
            <span class="signal-indicator ${signalBadgeClass(overallSignal)}">${esc(overallSignal.toUpperCase())}</span>
        </div>`;
    }

    el.innerHTML = html;
}

// ─── Section 6: Analyst Coverage ────────────────────────
function renderAnalyst(r) {
    const el = document.getElementById("analyst-content");
    const analyst = r.analyst || {};

    if (!analyst || !Object.keys(analyst).length) {
        el.innerHTML = '<div class="empty">No analyst data</div>';
        return;
    }

    let html = '';

    // Consensus rating
    const consensus = analyst.consensus || analyst.rating || {};
    if (consensus && Object.keys(consensus).length) {
        const strongBuy = consensus.strong_buy || consensus.strongBuy || 0;
        const buy = consensus.buy || 0;
        const hold = consensus.hold || 0;
        const sell = consensus.sell || 0;
        const strongSell = consensus.strong_sell || consensus.strongSell || 0;
        const total = strongBuy + buy + hold + sell + strongSell || 1;

        html += `<div class="report-card-inner">
            <h4>Consensus Rating</h4>
            <div class="consensus-bar">
                ${strongBuy > 0 ? `<div class="consensus-seg" style="width:${strongBuy/total*100}%;background:#059669" title="Strong Buy: ${strongBuy}">SB ${strongBuy}</div>` : ''}
                ${buy > 0 ? `<div class="consensus-seg" style="width:${buy/total*100}%;background:var(--green)" title="Buy: ${buy}">B ${buy}</div>` : ''}
                ${hold > 0 ? `<div class="consensus-seg" style="width:${hold/total*100}%;background:var(--accent)" title="Hold: ${hold}">H ${hold}</div>` : ''}
                ${sell > 0 ? `<div class="consensus-seg" style="width:${sell/total*100}%;background:#dc2626" title="Sell: ${sell}">S ${sell}</div>` : ''}
                ${strongSell > 0 ? `<div class="consensus-seg" style="width:${strongSell/total*100}%;background:#991b1b" title="Strong Sell: ${strongSell}">SS ${strongSell}</div>` : ''}
            </div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:6px;text-align:center">
                Total: ${total} analysts | Consensus: <strong>${consensus.label || consensus.consensus || 'N/A'}</strong>
            </div>
        </div>`;
    }

    // Price target
    const target = analyst.price_targets || analyst.price_target || analyst.target || {};
    if (target && Object.keys(target).length) {
        const current = target.current || r.price?.close || r.price?.price || r.level1?.price;
        const mean = target.mean || target.average;
        const median = target.median;
        const low = target.low;
        const high = target.high;
        const upside = mean && current ? ((mean - current) / current * 100).toFixed(1) : null;

        html += `<div class="report-card-inner" style="margin-top:16px">
            <h4>Price Target</h4>
            <div class="grid-2">
                <div>
                    <div class="stat-row"><span class="stat-label">Current</span><span class="stat-value">${fmtPrice(current)}</span></div>
                    <div class="stat-row"><span class="stat-label">Mean Target</span><span class="stat-value" style="color:var(--accent)">${fmtPrice(mean)}</span></div>
                    <div class="stat-row"><span class="stat-label">Median Target</span><span class="stat-value">${fmtPrice(median)}</span></div>
                    <div class="stat-row"><span class="stat-label">Low / High</span><span class="stat-value">${fmtPrice(low)} — ${fmtPrice(high)}</span></div>
                    ${upside != null ? `<div class="stat-row"><span class="stat-label">Upside/Downside</span><span class="stat-value" style="color:${Number(upside) >= 0 ? 'var(--green)' : 'var(--red)'}; font-weight:700">${upside > 0 ? '+' : ''}${upside}%</span></div>` : ''}
                </div>
                <div>
                    ${(low != null && high != null && current != null) ? rangeBar(low, high, current, fmtPrice(low), fmtPrice(high)) : ''}
                    ${mean != null && low != null && high != null ? `<div style="text-align:center;margin-top:8px;font-size:12px;color:var(--accent)">Mean: ${fmtPrice(mean)}</div>` : ''}
                </div>
            </div>
        </div>`;
    }

    // Upgrades/Downgrades
    const changes = analyst.upgrades_downgrades || analyst.changes || analyst.recent || [];
    if (changes.length) {
        html += `<div class="report-card-inner" style="margin-top:16px">
            <h4>Recent Upgrades/Downgrades</h4>
            <table class="data-table">
                <thead><tr><th>Date</th><th>Firm</th><th>Action</th><th>From</th><th>To</th><th class="num">Target</th></tr></thead>
                <tbody>${changes.slice(0, 10).map(c => `<tr>
                    <td>${c.date || c.action_date || '--'}</td>
                    <td>${esc(c.firm || c.analyst || '')}</td>
                    <td><span class="badge ${(c.action||'').toLowerCase().includes('upgrade') ? 'badge-buy' : (c.action||'').toLowerCase().includes('downgrade') ? 'badge-sell' : 'badge-medium'}">${esc(c.action || '')}</span></td>
                    <td>${esc(c.from_rating || c.from_grade || c.from || '')}</td>
                    <td>${esc(c.to_rating || c.to_grade || c.to || '')}</td>
                    <td class="num">${c.target_price != null ? fmtPrice(c.target_price) : '--'}</td>
                </tr>`).join("")}</tbody>
            </table>
        </div>`;
    }

    // EPS Estimates
    const eps = analyst.eps_estimates || analyst.eps || [];
    if (eps.length) {
        html += `<div class="report-card-inner" style="margin-top:16px">
            <h4>EPS Estimates</h4>
            <table class="data-table">
                <thead><tr><th>Period</th><th class="num">Estimate</th><th class="num">Actual</th><th class="num">Surprise</th></tr></thead>
                <tbody>${eps.slice(0, 8).map(e => `<tr>
                    <td>${e.period || e.quarter || '--'}</td>
                    <td class="num">${e.estimate != null ? '$' + Number(e.estimate).toFixed(2) : '--'}</td>
                    <td class="num">${e.actual != null ? '$' + Number(e.actual).toFixed(2) : '--'}</td>
                    <td class="num" style="color:${(e.surprise||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${e.surprise != null ? fmtPct(e.surprise) : '--'}</td>
                </tr>`).join("")}</tbody>
            </table>
        </div>`;
    }

    if (!html) html = '<div class="empty">No analyst data available</div>';
    el.innerHTML = html;
}

// ─── Section 7: Peer Comparison ─────────────────────────
function renderPeers(r) {
    const el = document.getElementById("peers-content");
    const peers = r.peer_comparison || {};
    const peerList = peers.peers || (Array.isArray(peers) ? peers : []);

    if (!peerList.length) {
        el.innerHTML = '<div class="empty">No peer comparison data</div>';
        return;
    }

    // Add FUFU row if not already included
    const price = r.price || r.level1 || {};
    let rows = [...peerList];
    if (!rows.find(p => (p.symbol || p.sym) === SYMBOL)) {
        rows.unshift({
            symbol: SYMBOL, sym: SYMBOL,
            price: price.close || price.price,
            change_pct: price.change_pct,
            volume: price.volume,
            relative_volume: price.relative_volume,
            pe: price.pe,
            market_cap: price.market_cap,
        });
    }

    el.innerHTML = `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr>
            <th>Symbol</th><th class="num">Price</th><th class="num">Change %</th>
            <th class="num">Volume</th><th class="num">RVol</th><th class="num">P/E</th><th class="num">Mkt Cap</th>
        </tr></thead>
        <tbody>${rows.map(p => {
            const sym = p.symbol || p.sym || '--';
            const isFufu = sym === SYMBOL;
            return `<tr${isFufu ? ' style="background:rgba(245,158,11,.08)"' : ''}>
                <td style="font-weight:700;${isFufu ? 'color:var(--accent)' : ''}">${sym}</td>
                <td class="num">${fmtPrice(p.price)}</td>
                <td class="num" style="color:${colorPct(p.change_pct)}">${fmtPct(p.change_pct)}</td>
                <td class="num">${fmtNum(p.volume)}</td>
                <td class="num">${p.relative_volume != null ? `<span class="rvol-badge ${p.relative_volume >= 2 ? 'rvol-high' : p.relative_volume >= 0.8 ? 'rvol-normal' : 'rvol-low'}">${Number(p.relative_volume).toFixed(1)}x</span>` : '--'}</td>
                <td class="num">${p.pe ?? '--'}</td>
                <td class="num">${p.market_cap != null ? '$' + fmtNum(p.market_cap) : '--'}</td>
            </tr>`;
        }).join("")}</tbody>
    </table></div>`;
}

// ─── Section 8: Valuation & Fundamentals ────────────────
function renderValuation(r) {
    const el = document.getElementById("valuation-content");
    const price = r.price || {};
    const level1 = r.level1 || {};
    const wb = r.webull || {};
    const quote = wb.quote || {};
    const m = { ...level1, ...price, ...quote };

    el.innerHTML = `<div class="grid-2">
        <div class="report-card-inner">
            <h4>Market & Shares</h4>
            <div class="stat-row"><span class="stat-label">Market Cap</span><span class="stat-value">${m.market_cap != null ? '$' + fmtNum(m.market_cap) : 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">Total Shares</span><span class="stat-value">${fmtNum(m.total_shares || m.shares_outstanding)}</span></div>
            <div class="stat-row"><span class="stat-label">Float</span><span class="stat-value">${fmtNum(m.float || m.float_shares)}</span></div>
            <div class="stat-row"><span class="stat-label">Float %</span><span class="stat-value">${m.float_pct != null ? Number(m.float_pct).toFixed(1) + '%' : 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">Turnover Rate</span><span class="stat-value">${m.turnover_rate != null ? Number(m.turnover_rate).toFixed(2) + '%' : 'N/A'}</span></div>
        </div>
        <div class="report-card-inner">
            <h4>Valuation Ratios</h4>
            <div class="stat-row"><span class="stat-label">P/E (TTM)</span><span class="stat-value">${m.pe ?? 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">Forward P/E</span><span class="stat-value">${m.forward_pe ?? m.forwardPe ?? 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">P/B</span><span class="stat-value">${m.pb ?? 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">P/S</span><span class="stat-value">${m.ps ?? 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">EPS</span><span class="stat-value">${m.eps != null ? '$' + Number(m.eps).toFixed(2) : 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">Next Earnings</span><span class="stat-value">${m.next_earnings || m.earnings_date || 'N/A'}</span></div>
        </div>
    </div>`;
}

// ─── Section 9: Short Interest & Dark Pool ──────────────
function renderShortDark(r) {
    const el = document.getElementById("short-dark-content");
    const si = r.short_interest || {};
    const dp = r.dark_pool || {};

    let html = '<div class="grid-2">';

    // Short Interest
    const siLatest = Array.isArray(si) ? si[0] : si;
    if (siLatest && Object.keys(siLatest).length) {
        html += `<div class="report-card-inner">
            <h4>Short Interest</h4>
            <div class="stat-row"><span class="stat-label">Short Volume</span><span class="stat-value">${fmtNum(siLatest.short_volume)}</span></div>
            <div class="stat-row"><span class="stat-label">Short % Float</span><span class="stat-value" style="color:${(siLatest.short_pct_float||0) > 20 ? 'var(--red)' : 'var(--text)'}">${siLatest.short_pct_float != null ? Number(siLatest.short_pct_float).toFixed(2) + '%' : 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">Days to Cover</span><span class="stat-value">${siLatest.days_to_cover != null ? Number(siLatest.days_to_cover).toFixed(1) : 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">Short Change</span><span class="stat-value" style="color:${(siLatest.short_change_pct||0) > 0 ? 'var(--red)' : 'var(--green)'}">${siLatest.short_change_pct != null ? fmtPct(siLatest.short_change_pct) : 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">Settlement Date</span><span class="stat-value">${siLatest.settlement_date || 'N/A'}</span></div>
        </div>`;
    } else {
        html += `<div class="report-card-inner"><h4>Short Interest</h4><div class="empty">No short interest data</div></div>`;
    }

    // Dark Pool
    const dpLatest = Array.isArray(dp) ? dp[0] : dp;
    if (dpLatest && Object.keys(dpLatest).length) {
        html += `<div class="report-card-inner">
            <h4>Dark Pool</h4>
            <div class="stat-row"><span class="stat-label">ATS Volume</span><span class="stat-value">${fmtNum(dpLatest.ats_volume || dpLatest.volume)}</span></div>
            <div class="stat-row"><span class="stat-label">Total Volume</span><span class="stat-value">${fmtNum(dpLatest.total_volume)}</span></div>
            <div class="stat-row"><span class="stat-label">Dark Pool %</span><span class="stat-value" style="color:var(--purple)">${dpLatest.dark_pct != null ? Number(dpLatest.dark_pct).toFixed(1) + '%' : 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">Num Trades</span><span class="stat-value">${fmtNum(dpLatest.num_trades || dpLatest.trade_count)}</span></div>
            <div class="stat-row"><span class="stat-label">Week Of</span><span class="stat-value">${dpLatest.week_of || dpLatest.date || 'N/A'}</span></div>
        </div>`;
    } else {
        html += `<div class="report-card-inner"><h4>Dark Pool</h4><div class="empty">No dark pool data</div></div>`;
    }

    html += '</div>';
    el.innerHTML = html;
}

// ─── Section 10: Ownership & Insider Activity ───────────
function renderOwnership(r) {
    const el = document.getElementById("ownership-content");
    const insiders = r.insider_trades_30d || [];
    const owners = r.ownership_changes_90d || [];
    const secEvents = r.sec_events_30d || [];

    let html = '';

    // Insider trades
    if (insiders.length) {
        html += `<div class="report-card-inner">
            <h4>Insider Trades (30d)</h4>
            <div style="overflow-x:auto"><table class="data-table">
                <thead><tr><th>Date</th><th>Insider</th><th>Title</th><th>Type</th><th class="num">Shares</th><th class="num">Price</th><th class="num">Value</th></tr></thead>
                <tbody>${insiders.map(t => `<tr>
                    <td>${t.transaction_date || t.filing_date || '--'}</td>
                    <td>${esc(t.insider_name || t.name)}</td>
                    <td>${esc(t.title || '')}</td>
                    <td>${txnBadge(t.type || t.transaction_type)}</td>
                    <td class="num">${fmtNum(t.shares)}</td>
                    <td class="num">${t.price != null ? fmtPrice(t.price) : '--'}</td>
                    <td class="num">${t.total_value != null ? '$' + fmtNum(t.total_value) : '--'}</td>
                </tr>`).join("")}</tbody>
            </table></div>
        </div>`;
    } else {
        html += `<div class="report-card-inner"><h4>Insider Trades (30d)</h4><div class="empty">No insider trades in last 30 days</div></div>`;
    }

    // Major shareholders
    if (owners.length) {
        html += `<div class="report-card-inner" style="margin-top:16px">
            <h4>Major Shareholders (5%+)</h4>
            <div style="overflow-x:auto"><table class="data-table">
                <thead><tr><th>Filing Date</th><th>Filer</th><th>Form</th><th class="num">Shares</th><th class="num">Ownership %</th></tr></thead>
                <tbody>${owners.map(o => `<tr>
                    <td>${o.filing_date || '--'}</td>
                    <td>${esc(o.filer_name || o.name)}</td>
                    <td>${esc(o.form_type || '')}</td>
                    <td class="num">${fmtNum(o.shares_held || o.shares)}</td>
                    <td class="num">${o.pct_ownership != null ? Number(o.pct_ownership).toFixed(2) + '%' : '--'}</td>
                </tr>`).join("")}</tbody>
            </table></div>
        </div>`;
    }

    // SEC events (8-K)
    if (secEvents.length) {
        html += `<div class="report-card-inner" style="margin-top:16px">
            <h4>SEC Events (8-K, 30d)</h4>
            <div style="overflow-x:auto"><table class="data-table">
                <thead><tr><th>Date</th><th>Item</th><th>Description</th><th>Severity</th></tr></thead>
                <tbody>${secEvents.map(e => `<tr>
                    <td>${e.filing_date || '--'}</td>
                    <td style="white-space:nowrap">${esc(e.item_code || '')}</td>
                    <td>${esc(e.item_description || e.description || '')}</td>
                    <td><span class="badge badge-${e.severity || 'medium'}">${(e.severity || '').toUpperCase() || 'N/A'}</span></td>
                </tr>`).join("")}</tbody>
            </table></div>
        </div>`;
    }

    if (!html) html = '<div class="empty">No ownership or insider data</div>';
    el.innerHTML = html;
}

function txnBadge(type) {
    const map = {
        P: ["BUY", "badge-buy"], S: ["SELL", "badge-sell"],
        A: ["GRANT", "badge-grant"], M: ["EXERCISE", "badge-grant"],
        G: ["GIFT", "badge-medium"], F: ["TAX", "badge-medium"],
    };
    const [label, cls] = map[type] || [type || "N/A", "badge-medium"];
    return `<span class="badge ${cls}">${label}</span>`;
}

// ─── Section 11: BTC Correlation ────────────────────────
function renderBTCCorrelation(r) {
    const el = document.getElementById("btc-corr-content");
    const btc = r.btc_context || {};

    if (!btc || !Object.keys(btc).length) {
        el.innerHTML = '<div class="empty">No BTC correlation data</div>';
        return;
    }

    const price = r.price || r.level1 || {};
    const fufuChange = price.change_pct;
    const btcChange = btc.btc_change_24h || btc.change_24h;

    let html = `<div class="grid-2">
        <div class="report-card-inner">
            <h4>BTC Market</h4>
            <div class="stat-row"><span class="stat-label">BTC Price</span><span class="stat-value">${btc.btc_price || btc.price ? '$' + Number(btc.btc_price || btc.price).toLocaleString("en-US", {maximumFractionDigits:0}) : 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">24h Change</span><span class="stat-value" style="color:${colorPct(btcChange)}">${btcChange != null ? fmtPct(btcChange) : 'N/A'}</span></div>
        </div>
        <div class="report-card-inner">
            <h4>Correlation Coefficients</h4>
            <div class="stat-row"><span class="stat-label">7-Day Corr</span><span class="stat-value">${btc.corr_7d != null ? Number(btc.corr_7d).toFixed(3) : 'N/A'}</span></div>
            <div class="stat-row"><span class="stat-label">30-Day Corr</span><span class="stat-value">${btc.corr_30d != null ? Number(btc.corr_30d).toFixed(3) : 'N/A'}</span></div>
            ${btc.corr_90d != null ? `<div class="stat-row"><span class="stat-label">90-Day Corr</span><span class="stat-value">${Number(btc.corr_90d).toFixed(3)}</span></div>` : ''}
            ${btc.beta_30d != null ? `<div class="stat-row"><span class="stat-label">Beta (30d)</span><span class="stat-value">${Number(btc.beta_30d).toFixed(3)}</span></div>` : ''}
        </div>
    </div>`;

    // Performance comparison
    if (fufuChange != null && btcChange != null) {
        html += `<div class="report-card-inner" style="margin-top:16px">
            <h4>Performance Comparison</h4>
            <div class="grid-2">
                <div style="text-align:center">
                    <div style="font-size:12px;color:var(--text-muted)">FUFU</div>
                    <div style="font-size:24px;font-weight:700;color:${colorPct(fufuChange)}">${fmtPct(fufuChange)}</div>
                </div>
                <div style="text-align:center">
                    <div style="font-size:12px;color:var(--text-muted)">BTC</div>
                    <div style="font-size:24px;font-weight:700;color:${colorPct(btcChange)}">${fmtPct(btcChange)}</div>
                </div>
            </div>`;

        const divergence = Number(fufuChange) - Number(btcChange);
        html += `<div style="text-align:center;margin-top:12px">
            <span style="font-size:12px;color:var(--text-muted)">Divergence: </span>
            <span style="font-weight:700;color:${colorPct(divergence)}">${fmtPct(divergence, 2)}</span>
            <span style="font-size:12px;color:var(--text-dim);margin-left:8px">${Math.abs(divergence) > 3 ? '(Significant)' : '(Normal range)'}</span>
        </div>`;
        html += `</div>`;
    }

    el.innerHTML = html;
}

// ─── Section 12: Daily Commentary ───────────────────────
function renderCommentary(r) {
    const el = document.getElementById("commentary-content");
    const c = r.commentary || {};

    if (!c || !Object.keys(c).length) {
        el.innerHTML = '<div class="empty">No commentary available</div>';
        return;
    }

    let html = '';

    // One-liner summary
    if (c.one_liner || c.summary_one_liner) {
        html += `<div class="commentary-highlight">
            "${esc(c.one_liner || c.summary_one_liner)}"
        </div>`;
    }

    // Overall tone
    if (c.overall_tone || c.tone) {
        const tone = c.overall_tone || c.tone;
        html += `<div style="text-align:center;margin-bottom:20px">
            <span class="tone-badge ${toneBadgeClass(tone)}" style="font-size:14px;padding:6px 20px">${esc(tone.toUpperCase())}</span>
        </div>`;
    }

    // Analyst verdict (new detailed section)
    if (c.analyst_verdict) {
        html += `<div class="commentary-block">
            <h4>ANALYST VERDICT</h4>
            <p>${esc(c.analyst_verdict)}</p>
        </div>`;
    }

    // Commentary sections
    const sections = [
        { key: "price_action", label: "PRICE ACTION" },
        { key: "technical_signal", label: "TECHNICAL SIGNALS" },
        { key: "flow_analysis", label: "FLOW ANALYSIS" },
        { key: "smart_money_read", label: "SMART MONEY READ" },
        { key: "btc_correlation", label: "BTC CORRELATION" },
        { key: "peer_context", label: "PEER CONTEXT" },
        { key: "short_squeeze_risk", label: "SHORT SQUEEZE ASSESSMENT" },
        { key: "catalyst_watch", label: "CATALYST WATCH" },
    ];

    for (const sec of sections) {
        const text = c[sec.key] || c[sec.key + "_commentary"] || c[sec.key.replace("_", "")] || null;
        if (text) {
            html += `<div class="commentary-block">
                <h4>${sec.label}</h4>
                <p>${esc(text)}</p>
            </div>`;
        }
    }

    // Trading plan
    if (c.trading_plan) {
        html += `<div class="commentary-block">
            <h4>TRADING PLAN</h4>
            <p>${esc(c.trading_plan)}</p>
        </div>`;
    }

    // Risk flags
    const risks = c.risk_flags || c.risks || c.risk || [];
    if (risks.length) {
        html += `<div class="commentary-block">
            <h4>RISK FLAGS</h4>
            <ul class="risk-list">${risks.map(r => `<li>${esc(typeof r === 'string' ? r : r.message || r.description || JSON.stringify(r))}</li>`).join("")}</ul>
        </div>`;
    }

    if (!html) html = '<div class="empty">No commentary data</div>';
    el.innerHTML = html;
}

// ─── Init ───────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    // Auth
    if (isAuthed()) {
        showReport();
    }

    document.getElementById("auth-form").addEventListener("submit", (e) => {
        e.preventDefault();
        handleAuth();
    });

    // Controls
    document.getElementById("logout-btn").addEventListener("click", logout);
    document.getElementById("print-btn").addEventListener("click", () => window.print());

    // Date picker
    document.getElementById("date-picker").addEventListener("change", (e) => {
        if (e.target.value) loadReportByDate(e.target.value);
    });

    // History dropdown
    document.getElementById("history-select").addEventListener("change", (e) => {
        if (e.target.value) {
            loadReportByDate(e.target.value);
            document.getElementById("date-picker").value = e.target.value;
        }
    });
});
