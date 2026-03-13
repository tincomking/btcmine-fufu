/* === FUFU Intelligence — Private Dashboard === */

const API_BASE = "https://api.btcmine.info";
const SYMBOL = "FUFU";
const SYMBOL_LC = "fufu"; // Cloudflare WAF blocks uppercase tickers in URLs
// SHA-256 hash of the access password
const AUTH_HASH = "f65bae74278241c3d2364c3754742bc5ced87a8dfe170146571c5bcc7ba993ba";
const AUTH_KEY = "fufu_auth_v1";

// ─── Auth ───────────────────────────────────────────────
async function sha256(text) {
    // crypto.subtle requires secure context (HTTPS/localhost)
    if (globalThis.crypto?.subtle) {
        const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    }
    // Fallback: pure JS SHA-256 for HTTP
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

function isAuthed() {
    return localStorage.getItem(AUTH_KEY) === AUTH_HASH;
}

function logout() {
    localStorage.removeItem(AUTH_KEY);
    location.reload();
}

async function handleAuth() {
    const pwd = document.getElementById("auth-password").value;
    const hash = await sha256(pwd);
    if (hash === AUTH_HASH) {
        localStorage.setItem(AUTH_KEY, AUTH_HASH);
        showDashboard();
    } else {
        document.getElementById("auth-error").textContent = "Invalid access code";
        document.getElementById("auth-password").value = "";
        document.getElementById("auth-password").focus();
    }
}

function showDashboard() {
    document.getElementById("auth-gate").classList.add("hidden");
    document.getElementById("dashboard").classList.remove("hidden");
    loadAllData();
}

// ─── Navigation ─────────────────────────────────────────
function initNav() {
    document.querySelectorAll(".nav-tab").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
            btn.classList.add("active");
            document.getElementById(`sec-${btn.dataset.section}`).classList.add("active");
        });
    });
}

// ─── Data Loading ───────────────────────────────────────
let DATA = {};

async function fetchAPI(path) {
    try {
        const r = await fetch(`${API_BASE}${path}`, { signal: AbortSignal.timeout(10000) });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return await r.json();
    } catch (e) {
        console.warn(`API ${path}: ${e.message}`);
        return null;
    }
}

async function loadAllData() {
    // Single aggregated endpoint — bypasses Cloudflare WAF keyword filtering
    const dashboard = await fetchAPI(`/api/equity/${SYMBOL_LC}/dashboard`);
    if (dashboard) {
        DATA.entity = dashboard.entity ? { entity: dashboard.entity } : null;
        DATA.insider = { trades: dashboard.insider || [] };
        DATA.institutions = { holdings: dashboard.institutions || [] };
        DATA.events = { events: dashboard.events || [] };
        DATA.ownership = { ownership: dashboard.ownership || [] };
        DATA.shortInterest = { short_interest: dashboard.short_interest || [] };
        DATA.darkpool = { darkpool: dashboard.darkpool || [] };
        DATA.actions = { actions: dashboard.actions || [] };
        DATA.indicators = { indicators: dashboard.indicators || {} };
        DATA.correlation = { correlations: dashboard.correlation?.data ? { [SYMBOL]: dashboard.correlation.data } : {} };
        DATA.alerts = { alerts: dashboard.alerts || [] };
        DATA.market = dashboard.market || null;
        DATA.marketPeers = dashboard.market_peers || null;
        DATA.webull = dashboard.webull || null;
        // Price
        DATA.quote = dashboard.price ? { [SYMBOL]: dashboard.price } : null;
        DATA.btc = dashboard.btc_price ? { price: dashboard.btc_price } : null;
    }

    renderAll();
    updateLastUpdate();
}

function updateLastUpdate() {
    document.getElementById("last-update").textContent =
        `Last update: ${new Date().toLocaleTimeString()}`;
}

// ─── Render Functions ───────────────────────────────────
function renderAll() {
    renderPriceHeader();
    renderEntity();
    renderShortSummary();
    renderDarkpool();
    renderInsiderPreview();
    renderEventsPreview();
    renderActions();
    renderMarketData();
    renderCapitalFlow();
    renderInsiderFull();
    renderInstitutionsFull();
    renderOwnershipFull();
    renderShortFull();
    renderDarkpoolFull();
    renderEventsFull();
    renderTechnicals();
    renderCorrelation();
}

// ─── Price Header ───────────────────────────────────────
function renderPriceHeader() {
    // FUFU price from dashboard aggregated data
    if (DATA.quote) {
        const fufu = DATA.quote[SYMBOL] || DATA.quote;
        if (fufu && fufu.price) {
            document.getElementById("fufu-price").textContent = `$${Number(fufu.price).toFixed(2)}`;
            const changeEl = document.getElementById("fufu-change");
            const pct = Number(fufu.change_pct || 0).toFixed(2);
            changeEl.textContent = `${pct > 0 ? "+" : ""}${pct}%`;
            changeEl.className = `price-change ${pct >= 0 ? "up" : "down"}`;
        }
    }
    // BTC price
    if (DATA.btc && DATA.btc.price) {
        document.getElementById("btc-price").textContent =
            `$${Number(DATA.btc.price).toLocaleString("en-US", { maximumFractionDigits: 0 })}`;
    }
}

// ─── Entity / Company Profile ───────────────────────────
function renderEntity() {
    const el = document.getElementById("entity-content");
    const entity = DATA.entity?.entity;
    if (!entity) { el.innerHTML = '<div class="empty">No entity data</div>'; return; }

    el.innerHTML = `
        <div class="stat-row"><span class="stat-label">Name</span><span class="stat-value">${entity.name || "--"}</span></div>
        <div class="stat-row"><span class="stat-label">Sector</span><span class="stat-value">${entity.sector || "--"}</span></div>
        <div class="stat-row"><span class="stat-label">Industry</span><span class="stat-value">${entity.industry || "--"}</span></div>
        <div class="stat-row"><span class="stat-label">Country</span><span class="stat-value">${entity.country || "--"}</span></div>
        <div class="stat-row"><span class="stat-label">Exchange</span><span class="stat-value">${entity.exchange || "--"}</span></div>
        <div class="stat-row"><span class="stat-label">Market Cap</span><span class="stat-value">${entity.market_cap ? "$" + fmtNum(entity.market_cap) : "--"}</span></div>
        <div class="stat-row"><span class="stat-label">CUSIP</span><span class="stat-value">${entity.cusip || "N/A"}</span></div>
        <div class="stat-row"><span class="stat-label">ISIN</span><span class="stat-value">${entity.isin || "N/A"}</span></div>
    `;
}

// ─── Short Interest Summary ─────────────────────────────
function renderShortSummary() {
    const el = document.getElementById("short-summary-content");
    const items = DATA.shortInterest?.short_interest;
    if (!items?.length) { el.innerHTML = '<div class="empty">No short interest data</div>'; return; }

    const latest = items[0];
    el.innerHTML = `
        <div class="stat-row"><span class="stat-label">Settlement Date</span><span class="stat-value">${latest.settlement_date}</span></div>
        <div class="stat-row"><span class="stat-label">Short Volume</span><span class="stat-value">${fmtNum(latest.short_volume)}</span></div>
        <div class="stat-row"><span class="stat-label">Short % Float</span><span class="stat-value" style="color:${latest.short_pct_float > 20 ? 'var(--red)' : 'var(--text)'}">${Number(latest.short_pct_float).toFixed(2)}%</span></div>
        <div class="stat-row"><span class="stat-label">Days to Cover</span><span class="stat-value">${Number(latest.days_to_cover).toFixed(1)}</span></div>
        <div class="stat-row"><span class="stat-label">Avg Daily Volume</span><span class="stat-value">${fmtNum(latest.avg_daily_volume)}</span></div>
        <div class="stat-row"><span class="stat-label">Change</span><span class="stat-value" style="color:${latest.short_change_pct > 0 ? 'var(--red)' : 'var(--green)'}">${latest.short_change_pct > 0 ? "+" : ""}${Number(latest.short_change_pct).toFixed(2)}%</span></div>
        <div class="stat-row"><span class="stat-label">Source</span><span class="stat-value" style="text-transform:uppercase;font-size:11px;color:var(--text-muted)">${latest.source}</span></div>
    `;
}

// ─── Dark Pool ──────────────────────────────────────────
function renderDarkpool() {
    const el = document.getElementById("darkpool-content");
    const items = DATA.darkpool?.darkpool;
    if (!items?.length) { el.innerHTML = '<div class="empty">No dark pool data</div>'; return; }

    const latest = items[0];
    el.innerHTML = `
        <div class="stat-row"><span class="stat-label">Week Of</span><span class="stat-value">${latest.week_of}</span></div>
        <div class="stat-row"><span class="stat-label">ATS Volume</span><span class="stat-value">${fmtNum(latest.ats_volume)}</span></div>
        <div class="stat-row"><span class="stat-label">Total Volume</span><span class="stat-value">${fmtNum(latest.total_volume)}</span></div>
        <div class="stat-row"><span class="stat-label">Dark Pool %</span><span class="stat-value" style="color:var(--purple)">${Number(latest.dark_pct).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label">Source</span><span class="stat-value" style="text-transform:uppercase;font-size:11px;color:var(--text-muted)">${latest.source}</span></div>
    `;
}

// ─── Insider Trades ─────────────────────────────────────
function renderInsiderPreview() {
    const el = document.getElementById("insider-preview");
    const trades = DATA.insider?.trades;
    if (!trades?.length) { el.innerHTML = '<div class="empty">No insider trades</div>'; return; }

    el.innerHTML = renderInsiderTable(trades.slice(0, 5));
}

function renderInsiderFull() {
    const el = document.getElementById("insider-full");
    const trades = DATA.insider?.trades;
    if (!trades?.length) { el.innerHTML = '<div class="empty">No insider trades recorded</div>'; return; }

    el.innerHTML = renderInsiderTable(trades);
}

function renderInsiderTable(trades) {
    return `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr>
            <th>Date</th><th>Insider</th><th>Title</th><th>Type</th>
            <th class="num">Shares</th><th class="num">Price</th><th class="num">Value</th>
        </tr></thead>
        <tbody>${trades.map(t => `<tr>
            <td>${t.transaction_date || t.filing_date || "--"}</td>
            <td>${esc(t.insider_name)}</td>
            <td>${esc(t.title || "")}</td>
            <td>${txnBadge(t.type)}</td>
            <td class="num">${fmtNum(t.shares)}</td>
            <td class="num">${t.price ? "$" + Number(t.price).toFixed(2) : "--"}</td>
            <td class="num">${t.total_value ? "$" + fmtNum(t.total_value) : "--"}</td>
        </tr>`).join("")}</tbody>
    </table></div>`;
}

function txnBadge(type) {
    const map = {
        P: ["BUY", "badge-buy"], S: ["SELL", "badge-sell"],
        A: ["GRANT", "badge-grant"], M: ["EXERCISE", "badge-grant"],
        G: ["GIFT", "badge-medium"], F: ["TAX", "badge-medium"],
    };
    const [label, cls] = map[type] || [type, "badge-medium"];
    return `<span class="badge ${cls}">${label}</span>`;
}

// ─── Institutions ───────────────────────────────────────
function renderInstitutionsFull() {
    const el = document.getElementById("institutions-full");
    const holdings = DATA.institutions?.holdings;
    if (!holdings?.length) { el.innerHTML = '<div class="empty">No institutional holdings data</div>'; return; }

    el.innerHTML = `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr>
            <th>Report Date</th><th>Institution</th>
            <th class="num">Shares</th><th class="num">Value (USD)</th><th class="num">Change</th>
        </tr></thead>
        <tbody>${holdings.map(h => `<tr>
            <td>${h.report_date}</td>
            <td>${esc(h.institution)}</td>
            <td class="num">${fmtNum(h.shares)}</td>
            <td class="num">${h.value_usd ? "$" + fmtNum(h.value_usd) : "--"}</td>
            <td class="num" style="color:${(h.change_shares || 0) >= 0 ? 'var(--green)' : 'var(--red)'}">${h.change_shares ? fmtNum(h.change_shares) : "--"}</td>
        </tr>`).join("")}</tbody>
    </table></div>`;
}

// ─── Ownership (SC 13G/13D) ─────────────────────────────
function renderOwnershipFull() {
    const el = document.getElementById("ownership-full");
    const items = DATA.ownership?.ownership;
    if (!items?.length) { el.innerHTML = '<div class="empty">No major shareholder filings</div>'; return; }

    el.innerHTML = `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr>
            <th>Filing Date</th><th>Filer</th><th>Form</th>
            <th class="num">Shares</th><th class="num">Ownership %</th><th>Type</th>
        </tr></thead>
        <tbody>${items.map(o => `<tr>
            <td>${o.filing_date}</td>
            <td>${esc(o.filer_name)}</td>
            <td>${esc(o.form_type)}</td>
            <td class="num">${fmtNum(o.shares_held)}</td>
            <td class="num">${o.pct_ownership ? Number(o.pct_ownership).toFixed(2) + "%" : "--"}</td>
            <td><span class="badge ${o.event_type?.includes('activist') ? 'badge-high' : 'badge-medium'}">${esc(o.event_type || "")}</span></td>
        </tr>`).join("")}</tbody>
    </table></div>`;
}

// ─── Short Interest Full ────────────────────────────────
function renderShortFull() {
    const el = document.getElementById("short-full");
    const items = DATA.shortInterest?.short_interest;
    if (!items?.length) { el.innerHTML = '<div class="empty">No short interest history</div>'; return; }

    el.innerHTML = `<table class="data-table">
        <thead><tr>
            <th>Date</th><th class="num">Short Vol</th><th class="num">% Float</th>
            <th class="num">DTC</th><th class="num">Change</th><th>Src</th>
        </tr></thead>
        <tbody>${items.map(s => `<tr>
            <td>${s.settlement_date}</td>
            <td class="num">${fmtNum(s.short_volume)}</td>
            <td class="num" style="color:${s.short_pct_float > 20 ? 'var(--red)' : ''}">${Number(s.short_pct_float).toFixed(2)}%</td>
            <td class="num">${Number(s.days_to_cover).toFixed(1)}</td>
            <td class="num" style="color:${s.short_change_pct > 0 ? 'var(--red)' : 'var(--green)'}">${s.short_change_pct > 0 ? "+" : ""}${Number(s.short_change_pct).toFixed(1)}%</td>
            <td style="text-transform:uppercase;font-size:11px;color:var(--text-muted)">${s.source}</td>
        </tr>`).join("")}</tbody>
    </table>`;
}

// ─── Dark Pool Full ─────────────────────────────────────
function renderDarkpoolFull() {
    const el = document.getElementById("darkpool-full");
    const items = DATA.darkpool?.darkpool;
    if (!items?.length) { el.innerHTML = '<div class="empty">No dark pool history</div>'; return; }

    el.innerHTML = `<table class="data-table">
        <thead><tr>
            <th>Week</th><th class="num">ATS Vol</th><th class="num">Total Vol</th>
            <th class="num">Dark %</th><th>Src</th>
        </tr></thead>
        <tbody>${items.map(d => `<tr>
            <td>${d.week_of}</td>
            <td class="num">${fmtNum(d.ats_volume)}</td>
            <td class="num">${fmtNum(d.total_volume)}</td>
            <td class="num" style="color:var(--purple)">${Number(d.dark_pct).toFixed(1)}%</td>
            <td style="text-transform:uppercase;font-size:11px;color:var(--text-muted)">${d.source}</td>
        </tr>`).join("")}</tbody>
    </table>`;
}

// ─── Events (8-K) ───────────────────────────────────────
function renderEventsPreview() {
    const el = document.getElementById("events-preview");
    const events = DATA.events?.events;
    if (!events?.length) { el.innerHTML = '<div class="empty">No recent events</div>'; return; }

    el.innerHTML = renderEventsTable(events.slice(0, 5));
}

function renderEventsFull() {
    const el = document.getElementById("events-full");
    const events = DATA.events?.events;
    if (!events?.length) { el.innerHTML = '<div class="empty">No 8-K events recorded</div>'; return; }

    el.innerHTML = renderEventsTable(events);
}

function renderEventsTable(events) {
    return `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr>
            <th>Date</th><th>Item</th><th>Description</th><th>Severity</th>
        </tr></thead>
        <tbody>${events.map(e => `<tr>
            <td>${e.filing_date}</td>
            <td style="white-space:nowrap">${esc(e.item_code || "")}</td>
            <td>${esc(e.item_description || "")}</td>
            <td><span class="badge badge-${e.severity || 'medium'}">${(e.severity || "").toUpperCase()}</span></td>
        </tr>`).join("")}</tbody>
    </table></div>`;
}

// ─── Corporate Actions ──────────────────────────────────
function renderActions() {
    const el = document.getElementById("actions-content");
    const items = DATA.actions?.actions;
    if (!items?.length) { el.innerHTML = '<div class="empty">No corporate actions recorded</div>'; return; }

    el.innerHTML = `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr>
            <th>Date</th><th>Type</th><th>Description</th><th class="num">Value/Ratio</th>
        </tr></thead>
        <tbody>${items.map(a => `<tr>
            <td>${a.action_date}</td>
            <td><span class="badge badge-medium">${(a.action_type || "").toUpperCase()}</span></td>
            <td>${esc(a.description || "")}</td>
            <td class="num">${a.action_type === "split" ? a.ratio + ":1" : a.value ? "$" + Number(a.value).toFixed(4) : "--"}</td>
        </tr>`).join("")}</tbody>
    </table></div>`;
}

// ─── Technical Indicators ───────────────────────────────
function renderTechnicals() {
    const el = document.getElementById("technicals-content");
    const ind = DATA.indicators?.indicators;
    if (!ind || !Object.keys(ind).length) { el.innerHTML = '<div class="empty">No technical indicator data</div>'; return; }

    const order = ["RSI_14", "MACD", "BB", "EMA_7", "EMA_25", "EMA_99", "VWAP"];
    let html = '<div class="indicator-grid">';

    for (const key of order) {
        if (!ind[key]) continue;
        const v = ind[key];
        let extra = "";
        if (v.extra) {
            extra = Object.entries(v.extra)
                .map(([k, val]) => `${k}: ${Number(val).toFixed(4)}`)
                .join(" | ");
        }

        // Color RSI based on value
        let color = "";
        if (key === "RSI_14") {
            const rsi = Number(v.value);
            color = rsi > 70 ? "var(--red)" : rsi < 30 ? "var(--green)" : "";
        }

        html += `<div class="indicator-item">
            <div class="indicator-name">${key}</div>
            <div class="indicator-value" ${color ? `style="color:${color}"` : ""}>${Number(v.value).toFixed(4)}</div>
            ${extra ? `<div class="indicator-extra">${extra}</div>` : ""}
        </div>`;
    }

    html += "</div>";
    if (ind[order[0]]?.ts) {
        html += `<div style="margin-top:12px;font-size:11px;color:var(--text-muted)">Updated: ${ind[order[0]].ts}</div>`;
    }
    el.innerHTML = html;
}

// ─── BTC Correlation ────────────────────────────────────
function renderCorrelation() {
    const el = document.getElementById("correlation-content");
    const corr = DATA.correlation?.correlations;
    if (!corr) { el.innerHTML = '<div class="empty">No correlation data</div>'; return; }

    const fufu = corr[SYMBOL];
    if (!fufu) { el.innerHTML = '<div class="empty">FUFU not in correlation matrix</div>'; return; }

    el.innerHTML = `
        <div class="stat-row"><span class="stat-label">7-Day Correlation</span><span class="stat-value">${fufu.corr_7d != null ? Number(fufu.corr_7d).toFixed(3) : "--"}</span></div>
        <div class="stat-row"><span class="stat-label">30-Day Correlation</span><span class="stat-value">${fufu.corr_30d != null ? Number(fufu.corr_30d).toFixed(3) : "--"}</span></div>
        <div class="stat-row"><span class="stat-label">90-Day Correlation</span><span class="stat-value">${fufu.corr_90d != null ? Number(fufu.corr_90d).toFixed(3) : "--"}</span></div>
        <div class="stat-row"><span class="stat-label">Beta (30d)</span><span class="stat-value">${fufu.beta_30d != null ? Number(fufu.beta_30d).toFixed(3) : "--"}</span></div>
        <div class="stat-row"><span class="stat-label">Data Points</span><span class="stat-value">${fufu.data_points || "--"}</span></div>
    `;
}

// ─── Market Data (盘口) ────────────────────────────────
function renderMarketData() {
    const m = DATA.market;
    renderMarketOrderbook(m);
    renderMarketVolume(m);
    renderMarketRange(m);
    renderMarketPressure(m);
    renderMarketProfile(m);
    renderMarketIntraday(m);
    renderMarketPeers(m, DATA.marketPeers);
    renderAfterHours();
    renderMarketCapitalFlow();
}

function renderCapitalFlow() {
    const el = document.getElementById("capitalflow-content");
    if (!el) return;
    const wb = DATA.webull;
    if (!wb || !wb.capital_flow) { el.innerHTML = '<div class="empty">No capital flow data</div>'; return; }
    const cf = wb.capital_flow;
    const totalIn = (cf.major_inflow || 0) + (cf.retail_inflow || 0);
    const totalOut = (cf.major_outflow || 0) + (cf.retail_outflow || 0);
    const totalNet = totalIn - totalOut;
    const majorPct = totalIn > 0 ? ((cf.major_inflow || 0) / totalIn * 100).toFixed(1) : 0;

    let html = `
        <div style="margin-bottom:12px;font-size:11px;color:var(--text-muted)">Date: ${cf.date || "--"}</div>
        <div class="stat-row"><span class="stat-label">Total Net Flow</span>
            <span class="stat-value" style="color:${totalNet >= 0 ? 'var(--green)' : 'var(--red)'}">$${fmtNum(Math.abs(totalNet))} ${totalNet >= 0 ? 'IN' : 'OUT'}</span></div>
        <div class="stat-row"><span class="stat-label">Major (Institutional)</span>
            <span class="stat-value" style="color:${(cf.major_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${(cf.major_net||0) >= 0 ? '+' : ''}$${fmtNum(Math.abs(cf.major_net||0))}</span></div>
        <div class="stat-row"><span class="stat-label">Large Orders</span>
            <span class="stat-value" style="color:${(cf.large_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${(cf.large_net||0) >= 0 ? '+' : ''}$${fmtNum(Math.abs(cf.large_net||0))}</span></div>
        <div class="stat-row"><span class="stat-label">Medium Orders</span>
            <span class="stat-value" style="color:${(cf.medium_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${(cf.medium_net||0) >= 0 ? '+' : ''}$${fmtNum(Math.abs(cf.medium_net||0))}</span></div>
        <div class="stat-row"><span class="stat-label">Small (Retail)</span>
            <span class="stat-value" style="color:${(cf.small_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${(cf.small_net||0) >= 0 ? '+' : ''}$${fmtNum(Math.abs(cf.small_net||0))}</span></div>
    `;

    // Pressure bar: institutional vs retail
    if (totalIn > 0) {
        html += `
        <div style="margin-top:12px;font-size:11px;color:var(--text-muted);margin-bottom:4px">INFLOW COMPOSITION</div>
        <div class="pressure-bar">
            <div class="pressure-buy" style="width:${majorPct}%;background:var(--blue)">Inst ${majorPct}%</div>
            <div class="pressure-sell" style="width:${100-majorPct}%;background:var(--purple)">Retail ${(100-majorPct).toFixed(1)}%</div>
        </div>`;
    }

    // History chart
    const hist = wb.capital_flow_history;
    if (hist && hist.length) {
        html += '<div style="margin-top:12px;font-size:11px;color:var(--text-muted);margin-bottom:4px">RECENT DAYS</div>';
        for (const h of hist.slice(0, 5)) {
            const net = (h.large_net || 0) + (h.medium_net || 0) + (h.small_net || 0);
            const dt = h.date ? h.date.slice(4,6)+'/'+h.date.slice(6) : '--';
            html += `<div class="stat-row"><span class="stat-label">${dt}</span>
                <span class="stat-value" style="color:${net >= 0 ? 'var(--green)' : 'var(--red)'}; font-size:12px">${net >= 0 ? '+' : ''}$${fmtNum(Math.abs(net))}</span></div>`;
        }
    }

    el.innerHTML = html;
}

function renderMarketCapitalFlow() {
    const el = document.getElementById("market-capitalflow");
    if (!el) return;
    const wb = DATA.webull;
    if (!wb || !wb.capital_flow) { el.innerHTML = '<div class="empty">No capital flow data</div>'; return; }
    const cf = wb.capital_flow;

    // Build bar chart of inflow vs outflow by size
    const categories = [
        { label: "Major (Inst.)", inflow: cf.major_inflow || 0, outflow: cf.major_outflow || 0, color: "var(--blue)" },
        { label: "Large", inflow: cf.large_net > 0 ? cf.large_net : 0, outflow: cf.large_net < 0 ? Math.abs(cf.large_net) : 0, color: "var(--purple)" },
        { label: "Medium", inflow: cf.medium_net > 0 ? cf.medium_net : 0, outflow: cf.medium_net < 0 ? Math.abs(cf.medium_net) : 0, color: "var(--accent)" },
        { label: "Small (Retail)", inflow: cf.small_net > 0 ? cf.small_net : 0, outflow: cf.small_net < 0 ? Math.abs(cf.small_net) : 0, color: "var(--green)" },
    ];
    const maxVal = Math.max(...categories.map(c => Math.max(c.inflow, c.outflow)), 1);

    let html = `<div style="display:flex;gap:24px">`;
    // Left: bar chart
    html += `<div style="flex:1"><div style="font-size:11px;color:var(--text-muted);margin-bottom:8px">NET FLOW BY ORDER SIZE</div>`;
    for (const cat of categories) {
        const net = cat.inflow - cat.outflow;
        const pct = Math.abs(net) / maxVal * 100;
        html += `<div class="vol-bar-row" style="margin-bottom:4px">
            <span class="vol-bar-label" style="width:90px">${cat.label}</span>
            <div class="vol-bar-track">
                <div class="vol-bar-fill" style="width:${Math.min(pct,100)}%;background:${net >= 0 ? 'var(--green)' : 'var(--red)'}"></div>
            </div>
            <span class="vol-bar-val" style="width:80px;color:${net >= 0 ? 'var(--green)' : 'var(--red)'}">${net >= 0 ? '+' : ''}$${fmtNum(Math.abs(net))}</span>
        </div>`;
    }
    html += `</div>`;

    // Right: summary stats
    html += `<div style="min-width:180px">
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px">INFLOW RATIO</div>
        <div class="stat-row"><span class="stat-label">Inst. In</span><span class="stat-value" style="font-size:12px">${(cf.major_inflow_pct||0).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label">Inst. Out</span><span class="stat-value" style="font-size:12px">${(cf.major_outflow_pct||0).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label">Retail In</span><span class="stat-value" style="font-size:12px">${(cf.retail_inflow_pct||0).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label">Retail Out</span><span class="stat-value" style="font-size:12px">${(cf.retail_outflow_pct||0).toFixed(1)}%</span></div>
    </div></div>`;

    el.innerHTML = html;
}

function renderAfterHours() {
    const el = document.getElementById("market-afterhours");
    if (!el) return;
    const wb = DATA.webull;
    if (!wb || !wb.after_hours) { el.innerHTML = '<div class="empty">No after-hours data</div>'; return; }
    const ah = wb.after_hours;
    const q = wb.quote || {};
    el.innerHTML = `
        <div class="stat-row"><span class="stat-label">After-Hours Price</span>
            <span class="stat-value" style="color:${(ah.change_pct||0) >= 0 ? 'var(--green)' : 'var(--red)'}">$${Number(ah.price).toFixed(2)}</span></div>
        <div class="stat-row"><span class="stat-label">Change</span>
            <span class="stat-value" style="color:${(ah.change_pct||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${(ah.change_pct||0) >= 0 ? '+' : ''}${Number(ah.change_pct).toFixed(2)}%</span></div>
        <div class="stat-row"><span class="stat-label">AH Volume</span>
            <span class="stat-value">${fmtNum(ah.volume)}</span></div>
        <div class="stat-row"><span class="stat-label">AH Range</span>
            <span class="stat-value">$${Number(ah.low).toFixed(2)} — $${Number(ah.high).toFixed(2)}</span></div>
        <div style="margin-top:12px;font-size:11px;color:var(--text-muted)">
            P/E: ${q.pe || '--'} | EPS: $${q.eps || '--'} | P/B: ${q.pb || '--'} | Turnover: ${q.turnover_rate || '--'}%
        </div>
    `;
}

function renderMarketOrderbook(m) {
    const el = document.getElementById("market-orderbook");
    if (!m) { el.innerHTML = '<div class="empty">No market data</div>'; return; }
    el.innerHTML = `
        <div class="orderbook-row">
            <span class="orderbook-label">Best Bid</span>
            <span class="orderbook-value orderbook-bid">$${Number(m.bid).toFixed(2)} <span style="font-size:12px;font-weight:400">(${m.bid_size} lot)</span></span>
        </div>
        <div class="orderbook-row">
            <span class="orderbook-label">Best Ask</span>
            <span class="orderbook-value orderbook-ask">$${Number(m.ask).toFixed(2)} <span style="font-size:12px;font-weight:400">(${m.ask_size} lot)</span></span>
        </div>
        <div class="orderbook-row">
            <span class="orderbook-label">Spread</span>
            <span class="orderbook-value orderbook-spread">$${m.spread} (${m.spread_pct}%)</span>
        </div>
        <div class="orderbook-row">
            <span class="orderbook-label">VWAP</span>
            <span class="orderbook-value">$${Number(m.vwap).toFixed(4)}</span>
        </div>
        <div class="orderbook-row">
            <span class="orderbook-label">Last Price</span>
            <span class="orderbook-value" style="color:${m.change_pct >= 0 ? 'var(--green)' : 'var(--red)'}">$${Number(m.price).toFixed(2)} (${m.change_pct > 0 ? '+' : ''}${m.change_pct}%)</span>
        </div>
    `;
}

function renderMarketVolume(m) {
    const el = document.getElementById("market-volume");
    if (!m) { el.innerHTML = '<div class="empty">No market data</div>'; return; }
    const rvolClass = m.relative_volume >= 2 ? 'rvol-high' : m.relative_volume >= 0.8 ? 'rvol-normal' : 'rvol-low';
    const rvolLabel = m.relative_volume >= 2 ? 'HIGH' : m.relative_volume >= 0.8 ? 'NORMAL' : 'LOW';
    el.innerHTML = `
        <div class="stat-row"><span class="stat-label">Today Volume</span><span class="stat-value">${fmtNum(m.volume)}</span></div>
        <div class="stat-row"><span class="stat-label">Avg Volume</span><span class="stat-value">${fmtNum(m.avg_volume)}</span></div>
        <div class="stat-row"><span class="stat-label">10D Avg Volume</span><span class="stat-value">${fmtNum(m.avg_volume_10d)}</span></div>
        <div class="stat-row"><span class="stat-label">Relative Volume</span><span class="stat-value"><span class="rvol-badge ${rvolClass}">${m.relative_volume}x ${rvolLabel}</span></span></div>
        <div class="stat-row"><span class="stat-label">Market Cap</span><span class="stat-value">${fmtNum(m.market_cap)}</span></div>
    `;
}

function renderMarketRange(m) {
    const el = document.getElementById("market-range");
    if (!m) { el.innerHTML = '<div class="empty">No market data</div>'; return; }
    const dayRange = m.high - m.low;
    const dayPos = dayRange > 0 ? ((m.price - m.low) / dayRange * 100).toFixed(0) : 50;
    const w52Range = m.week52_high - m.week52_low;
    const w52Pos = w52Range > 0 ? ((m.price - m.week52_low) / w52Range * 100).toFixed(0) : 50;
    el.innerHTML = `
        <div class="stat-row"><span class="stat-label">Open</span><span class="stat-value">$${Number(m.open).toFixed(2)}</span></div>
        <div class="stat-row"><span class="stat-label">Prev Close</span><span class="stat-value">$${Number(m.prev_close).toFixed(2)}</span></div>
        <div style="margin:12px 0">
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">DAY RANGE</div>
            <div style="display:flex;align-items:center;gap:8px;font-size:13px">
                <span>$${Number(m.low).toFixed(2)}</span>
                <div style="flex:1;height:6px;background:var(--bg-input);border-radius:3px;position:relative">
                    <div style="position:absolute;left:${dayPos}%;top:-3px;width:12px;height:12px;background:var(--accent);border-radius:50%;transform:translateX(-50%)"></div>
                </div>
                <span>$${Number(m.high).toFixed(2)}</span>
            </div>
        </div>
        <div>
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">52-WEEK RANGE</div>
            <div style="display:flex;align-items:center;gap:8px;font-size:13px">
                <span style="color:var(--red)">$${Number(m.week52_low).toFixed(2)}</span>
                <div style="flex:1;height:6px;background:var(--bg-input);border-radius:3px;position:relative">
                    <div style="position:absolute;left:${w52Pos}%;top:-3px;width:12px;height:12px;background:var(--accent);border-radius:50%;transform:translateX(-50%)"></div>
                </div>
                <span style="color:var(--green)">$${Number(m.week52_high).toFixed(2)}</span>
            </div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px">From 52W High: ${m.from_52h_pct}% | From 52W Low: +${m.from_52l_pct}%</div>
        </div>
    `;
}

function renderMarketPressure(m) {
    const el = document.getElementById("market-pressure");
    if (!m) { el.innerHTML = '<div class="empty">No market data</div>'; return; }
    const sellPct = (100 - m.buy_pct).toFixed(1);
    el.innerHTML = `
        <div class="pressure-bar">
            <div class="pressure-buy" style="width:${m.buy_pct}%">BUY ${m.buy_pct}%</div>
            <div class="pressure-sell" style="width:${sellPct}%">SELL ${sellPct}%</div>
        </div>
        <div class="stat-row"><span class="stat-label">Buy Volume (est.)</span><span class="stat-value" style="color:var(--green)">${fmtNum(m.buy_volume)}</span></div>
        <div class="stat-row"><span class="stat-label">Sell Volume (est.)</span><span class="stat-value" style="color:var(--red)">${fmtNum(m.sell_volume)}</span></div>
        <div style="margin-top:8px;font-size:11px;color:var(--text-muted)">Based on 5-min candle close vs open direction</div>
    `;
}

function renderMarketProfile(m) {
    const el = document.getElementById("market-profile");
    if (!m || !m.volume_profile?.length) { el.innerHTML = '<div class="empty">No volume profile</div>'; return; }
    const maxVol = Math.max(...m.volume_profile.map(b => b.volume));
    let html = '<div class="vol-bar-container">';
    for (const bin of m.volume_profile) {
        const pct = maxVol > 0 ? (bin.volume / maxVol * 100).toFixed(0) : 0;
        const isCurrentPrice = m.price >= bin.price_lo && m.price <= bin.price_hi;
        html += `<div class="vol-bar-row">
            <span class="vol-bar-label">$${bin.price_lo.toFixed(2)}-${bin.price_hi.toFixed(2)}</span>
            <div class="vol-bar-track">
                <div class="vol-bar-fill" style="width:${pct}%;${isCurrentPrice ? 'background:var(--accent)' : ''}"></div>
            </div>
            <span class="vol-bar-val">${fmtNum(bin.volume)}</span>
        </div>`;
    }
    html += '</div>';
    if (m.vwap) html += `<div style="margin-top:8px;font-size:12px;color:var(--accent)">VWAP: $${Number(m.vwap).toFixed(4)}</div>`;
    el.innerHTML = html;
}

function renderMarketIntraday(m) {
    const el = document.getElementById("market-intraday");
    if (!m || !m.intraday?.length) { el.innerHTML = '<div class="empty">No intraday data</div>'; return; }
    const candles = m.intraday;
    const allPrices = candles.flatMap(c => [c.open, c.close]);
    const minP = Math.min(...allPrices);
    const maxP = Math.max(...allPrices);
    const range = maxP - minP || 1;

    let html = '<div style="overflow-x:auto">';
    for (const c of candles) {
        const isUp = c.close >= c.open;
        const lo = Math.min(c.open, c.close);
        const hi = Math.max(c.open, c.close);
        const left = ((lo - minP) / range * 100).toFixed(1);
        const width = Math.max(((hi - lo) / range * 100), 0.5).toFixed(1);
        html += `<div class="candle-row">
            <span class="candle-time">${c.time}</span>
            <span class="candle-price" style="color:${isUp ? 'var(--green)' : 'var(--red)'}">$${c.close.toFixed(2)}</span>
            <div class="candle-bar"><div class="candle-bar-inner ${isUp ? 'candle-up' : 'candle-down'}" style="left:${left}%;width:${width}%"></div></div>
            <span class="candle-vol">${fmtNum(c.volume)}</span>
        </div>`;
    }
    html += '</div>';
    el.innerHTML = html;
}

function renderMarketPeers(m, peers) {
    const el = document.getElementById("market-peers");
    if (!peers || !Object.keys(peers).length) { el.innerHTML = '<div class="empty">No peer data</div>'; return; }

    // Build combined array with FUFU first
    const rows = [];
    if (m) rows.push({ sym: SYMBOL, ...m });
    for (const [sym, p] of Object.entries(peers)) {
        rows.push({ sym, ...p });
    }

    el.innerHTML = `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr>
            <th>Symbol</th><th class="num">Price</th><th class="num">Change</th>
            <th class="num">Volume</th><th class="num">RVol</th><th class="num">Spread%</th>
            <th class="num">Buy%</th><th class="num">Mkt Cap</th>
        </tr></thead>
        <tbody>${rows.map(r => `<tr${r.sym === SYMBOL ? ' style="background:rgba(245,158,11,.08)"' : ''}>
            <td style="font-weight:700;${r.sym === SYMBOL ? 'color:var(--accent)' : ''}">${r.sym}</td>
            <td class="num">$${Number(r.price).toFixed(2)}</td>
            <td class="num" style="color:${r.change_pct >= 0 ? 'var(--green)' : 'var(--red)'}">${r.change_pct > 0 ? '+' : ''}${Number(r.change_pct).toFixed(2)}%</td>
            <td class="num">${fmtNum(r.volume)}</td>
            <td class="num"><span class="rvol-badge ${r.relative_volume >= 2 ? 'rvol-high' : r.relative_volume >= 0.8 ? 'rvol-normal' : 'rvol-low'}">${r.relative_volume}x</span></td>
            <td class="num">${Number(r.spread_pct).toFixed(2)}%</td>
            <td class="num">${Number(r.buy_pct).toFixed(1)}%</td>
            <td class="num">${fmtNum(r.market_cap)}</td>
        </tr>`).join("")}</tbody>
    </table></div>`;
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

function esc(s) {
    if (!s) return "";
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
}

// ─── Init ───────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    // Auth
    if (isAuthed()) {
        showDashboard();
    }

    document.getElementById("auth-form").addEventListener("submit", (e) => {
        e.preventDefault();
        handleAuth();
    });

    // Nav
    initNav();

    // Buttons
    document.getElementById("refresh-btn").addEventListener("click", loadAllData);
    document.getElementById("logout-btn").addEventListener("click", logout);

    // Auto-refresh every 5 minutes
    setInterval(loadAllData, 5 * 60 * 1000);
});
