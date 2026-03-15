/* === FUFU Intelligence — Private Dashboard === */

const APP_VERSION = "v1.0316A";
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
    renderPriceChart();
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
        <div class="stat-row"><span class="stat-label" data-tip="公司所属行业大类（FUFU 归类为 Financial Services）">Sector</span><span class="stat-value">${entity.sector || "--"}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="细分行业分类（FUFU = Capital Markets，提供算力服务和云算力）">Industry</span><span class="stat-value">${entity.industry || "--"}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="公司注册地 / 总部所在国（FUFU 在开曼群岛注册，运营总部位于新加坡）">Country</span><span class="stat-value">${entity.country || "--"}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="上市交易所：NCM = Nasdaq Capital Market（纳斯达克资本市场层，适合中小型公司）">Exchange</span><span class="stat-value">${entity.exchange || "--"}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="市场总估值 = 股价 × 总流通股数。反映市场对公司当前的综合定价">Market Cap</span><span class="stat-value">${entity.market_cap ? "$" + fmtNum(entity.market_cap) : "--"}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="美国证券唯一识别码。G1152A104 中 G 开头表示开曼群岛注册的外国私人发行人（FPI）">CUSIP</span><span class="stat-value">${entity.cusip || "N/A"}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="国际证券识别码（ISIN），全球通用的证券唯一标识">ISIN</span><span class="stat-value">${entity.isin || "N/A"}</span></div>
    `;
}

// ─── Short Interest Summary ─────────────────────────────
function renderShortSummary() {
    const el = document.getElementById("short-summary-content");
    const items = DATA.shortInterest?.short_interest;
    if (!items?.length) { el.innerHTML = '<div class="empty">No short interest data</div>'; return; }

    const latest = items[0];
    el.innerHTML = `
        <div class="stat-row"><span class="stat-label" data-tip="做空数据结算日期（FINRA 每两周公布一次双周期数据）">Settlement Date</span><span class="stat-value">${latest.settlement_date}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="当前市场持有的做空股数。数值越高说明空头力量越强，挤仓反弹潜力也越大">Short Volume</span><span class="stat-value">${fmtNum(latest.short_volume)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="做空量占自由流通股的比例。>20% 为高度做空区域，挤仓（Short Squeeze）风险显著增大；<5% 偏低">Short % Float</span><span class="stat-value" style="color:${latest.short_pct_float > 20 ? 'var(--red)' : 'var(--text)'}">${Number(latest.short_pct_float).toFixed(2)}%</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="Days to Cover：以当前日均成交量计算，全部空头完全回补所需的交易日数。>5 天为警示信号">Days to Cover</span><span class="stat-value">${Number(latest.days_to_cover).toFixed(1)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="历史平均日成交量，用于计算 Days to Cover（回补天数）">Avg Daily Volume</span><span class="stat-value">${fmtNum(latest.avg_daily_volume)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="与上一结算期相比的做空量变化。正值（红色）= 做空增加（利空信号）；负值（绿色）= 做空减少（利多信号）">Change</span><span class="stat-value" style="color:${latest.short_change_pct > 0 ? 'var(--red)' : 'var(--green)'}">${latest.short_change_pct > 0 ? "+" : ""}${Number(latest.short_change_pct).toFixed(2)}%</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="数据来源（FINRA ATS 报告 / NASDAQ 官方做空数据）">Source</span><span class="stat-value" style="text-transform:uppercase;font-size:11px;color:var(--text-muted)">${latest.source}</span></div>
    `;
}

// ─── Dark Pool ──────────────────────────────────────────
function renderDarkpool() {
    const el = document.getElementById("darkpool-content");
    const items = DATA.darkpool?.darkpool;
    if (!items?.length) { el.innerHTML = '<div class="empty">No dark pool data</div>'; return; }

    const latest = items[0];
    el.innerHTML = `
        <div class="stat-row"><span class="stat-label" data-tip="该暗池数据的统计周（FINRA ATS 数据每周发布，通常延迟约 2 周）">Week Of</span><span class="stat-value">${latest.week_of}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="在 ATS（另类交易系统 / 暗池）中完成的成交股数，不在公开交易所显示">ATS Volume</span><span class="stat-value">${fmtNum(latest.ats_volume)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="当周全市场总成交量（公开交易所 + 暗池 ATS 合计）">Total Volume</span><span class="stat-value">${fmtNum(latest.total_volume)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="暗池成交量占总成交量的比例。>40% 说明大量机构正在场外低调建仓或减仓，后续可能有方向性突破">Dark Pool %</span><span class="stat-value" style="color:var(--purple)">${Number(latest.dark_pct).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="数据来源（FINRA ATS Transparency Data）">Source</span><span class="stat-value" style="text-transform:uppercase;font-size:11px;color:var(--text-muted)">${latest.source}</span></div>
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
            <th data-tip="交易发生日期（SEC Form 4 规定必须在交易后 2 个工作日内提交）">Date</th>
            <th data-tip="内部人姓名（董事、高管、或持股 10% 以上大股东）">Insider</th>
            <th data-tip="在公司的职务（CEO / CFO / Director / VP 等）">Title</th>
            <th data-tip="交易类型：P=公开市场买入（强烈看涨信号）S=公开卖出 A=股权激励授予 M=期权行权 G=赠予 F=税款代扣股">Type</th>
            <th class="num" data-tip="此次交易涉及的股数">Shares</th>
            <th class="num" data-tip="每股交易价格（美元）">Price</th>
            <th class="num" data-tip="此次交易总价值 = 股数 × 每股价格（美元）">Value</th>
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
            <th data-tip="SEC 13F 季度申报日期（季度结束后 45 天内必须提交）">Report Date</th>
            <th data-tip="机构投资者名称（管理资产 >$1 亿须申报 13F）">Institution</th>
            <th class="num" data-tip="持有股数（截至报告期末）">Shares</th>
            <th class="num" data-tip="持仓市值（美元），基于报告期末股价估算">Value (USD)</th>
            <th class="num" data-tip="较上季度持股变化：绿色正值 = 增持；红色负值 = 减持">Change</th>
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
            <th data-tip="大股东变动申报日期（持股首次达 5% 后，须在 10 日内提交）">Filing Date</th>
            <th data-tip="申报人姓名（个人或机构）">Filer</th>
            <th data-tip="SC 13G = 被动持股（无控制意图）；SC 13D = 主动/激进持股（可能推动公司治理变革）">Form</th>
            <th class="num" data-tip="申报时持有的股数">Shares</th>
            <th class="num" data-tip="持股比例（占公司总流通股数）">Ownership %</th>
            <th data-tip="ACTIVIST = 主动型投资（13D 申报，潜在激进行动）；PASSIVE = 被动型持股（13G 申报）">Type</th>
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
            <th data-tip="FINRA 做空数据的结算日期（双周发布）">Date</th>
            <th class="num" data-tip="当期做空总股数（空头持仓合计）">Short Vol</th>
            <th class="num" data-tip="做空量占自由流通股的比例。>20% = 高度做空，挤仓风险大">% Float</th>
            <th class="num" data-tip="Days to Cover：回补天数 = 做空量 / 日均成交量。数值越大，潜在挤仓力度越强">DTC</th>
            <th class="num" data-tip="较上期的做空量变化百分比。正值（红）= 做空增加；负值（绿）= 做空减少">Change</th>
            <th data-tip="数据来源">Src</th>
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
            <th data-tip="暗池数据统计周（FINRA ATS 数据，通常延迟约 2 周发布）">Week</th>
            <th class="num" data-tip="ATS（另类交易系统 / 暗池）成交量，不在公开交易所显示">ATS Vol</th>
            <th class="num" data-tip="含暗池的全市场总成交量（公开交易所 + ATS 合计）">Total Vol</th>
            <th class="num" data-tip="暗池占总成交量比例。FUFU 近期约 42%，说明机构主要在场外低调成交，后续可能有方向性突破">Dark %</th>
            <th data-tip="数据来源">Src</th>
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
            <th data-tip="SEC 申报文件提交日期（FUFU 作为外国私人发行人提交 6-K；美国本土公司提交 8-K）">Date</th>
            <th data-tip="事件类型码：6K-EARNINGS=财报（季度/年度业绩）6K=月度运营更新 6K-ACQUISITION=收购 6K-MGMT=高管变动 6K-SHARES=股权变动">Item</th>
            <th data-tip="从 SEC EDGAR 归档文件提取的实际公告标题（EX-99.1 展品说明）">Description</th>
            <th data-tip="重要程度：HIGH = 财报/高管变动/重大协议（直接影响股价）MEDIUM = 月度运营更新 LOW = 常规披露">Severity</th>
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
            <th data-tip="公司行动执行日期">Date</th>
            <th data-tip="公司行动类型：SPLIT=股票拆分 DIVIDEND=股息分红 MERGER=合并 BUYBACK=股票回购">Type</th>
            <th data-tip="公司行动的详细说明">Description</th>
            <th class="num" data-tip="分红金额（美元/股）或拆股比例（如 3:1 表示每股变3股）">Value/Ratio</th>
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

        const INDICATOR_TIPS = {
            RSI_14: "相对强弱指数（14日）\n>70 = 超买区域（注意回调风险）\n<30 = 超卖区域（可能出现反弹）\n50 = 多空中性分界线",
            MACD: "移动平均收敛发散指标\nHistogram 为正且金叉 = 看涨\nHistogram 为负且死叉 = 看跌\nSignal = 9日信号线，Histogram = MACD-Signal",
            BB: "布林带（Bollinger Bands，20日±2σ）\n价格触上轨 = 可能超买\n价格触下轨 = 可能超卖\nMiddle = 20日移动均线",
            EMA_7: "7日指数移动均线（短期趋势参考）\n价格站上 EMA7 为短期偏多",
            EMA_25: "25日指数移动均线（中期趋势参考）\n价格站上 EMA25 为中期偏多\nEMA7 > EMA25 = 短中期金叉看涨",
            EMA_99: "99日指数移动均线（长期趋势参考）\n价格站上 EMA99 = 长期牛市格局\n价格跌破 EMA99 = 长期转弱信号",
            VWAP: "成交量加权均价（Volume-Weighted Average Price，当日）\n价格 > VWAP = 多头主导，买方占优\n价格 < VWAP = 空头主导，卖方占优",
        };
        html += `<div class="indicator-item" data-tip="${INDICATOR_TIPS[key] || key}">
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
        <div class="stat-row"><span class="stat-label" data-tip="FUFU 与 BTC 的 7 日价格相关系数\n+1 = 完全正相关（同涨同跌）\n-1 = 完全负相关\n0 = 无相关性">7-Day Correlation</span><span class="stat-value">${fufu.corr_7d != null ? Number(fufu.corr_7d).toFixed(3) : "--"}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="30 日相关系数，反映中期走势联动性。矿企股价通常与 BTC 高度正相关">30-Day Correlation</span><span class="stat-value">${fufu.corr_30d != null ? Number(fufu.corr_30d).toFixed(3) : "--"}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="90 日相关系数，反映长期 BTC 依赖度。FUFU 作为矿企长期与 BTC 高度绑定">90-Day Correlation</span><span class="stat-value">${fufu.corr_90d != null ? Number(fufu.corr_90d).toFixed(3) : "--"}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="FUFU 相对 BTC 的 30 日 β 值\nβ > 1 = FUFU 涨跌幅比 BTC 更剧烈（矿企天然杠杆特征）\nβ = 1 = 与 BTC 同步\nβ < 1 = 波动性低于 BTC">Beta (30d)</span><span class="stat-value">${fufu.beta_30d != null ? Number(fufu.beta_30d).toFixed(3) : "--"}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="计算相关性和 Beta 所使用的历史价格数据点数量">Data Points</span><span class="stat-value">${fufu.data_points || "--"}</span></div>
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
    renderMarketDepth();
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
        <div class="stat-row"><span class="stat-label" data-tip="全部资金净流量 = 总流入 - 总流出。绿色（IN）= 净买入；红色（OUT）= 净卖出。是衡量当日整体资金意愿的核心指标">Total Net Flow</span>
            <span class="stat-value" style="color:${totalNet >= 0 ? 'var(--green)' : 'var(--red)'}">$${fmtNum(Math.abs(totalNet))} ${totalNet >= 0 ? 'IN' : 'OUT'}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="机构超大单净流量（主力资金）。正值表示机构主动买入，是最有参考价值的资金信号">Major (Institutional)</span>
            <span class="stat-value" style="color:${(cf.major_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${(cf.major_net||0) >= 0 ? '+' : ''}$${fmtNum(Math.abs(cf.major_net||0))}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="大单净流量（单笔金额较高，介于机构与散户之间）">Large Orders</span>
            <span class="stat-value" style="color:${(cf.large_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${(cf.large_net||0) >= 0 ? '+' : ''}$${fmtNum(Math.abs(cf.large_net||0))}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="中单净流量（中等规模订单）">Medium Orders</span>
            <span class="stat-value" style="color:${(cf.medium_net||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${(cf.medium_net||0) >= 0 ? '+' : ''}$${fmtNum(Math.abs(cf.medium_net||0))}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="散户小单净流量（零售投资者合计）。散户情绪指标，往往为反向信号">Small (Retail)</span>
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
        <div class="stat-row"><span class="stat-label" data-tip="机构资金流入量占总流入的比例">Inst. In</span><span class="stat-value" style="font-size:12px">${(cf.major_inflow_pct||0).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="机构资金流出量占总流出的比例">Inst. Out</span><span class="stat-value" style="font-size:12px">${(cf.major_outflow_pct||0).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="散户资金流入量占总流入的比例">Retail In</span><span class="stat-value" style="font-size:12px">${(cf.retail_inflow_pct||0).toFixed(1)}%</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="散户资金流出量占总流出的比例">Retail Out</span><span class="stat-value" style="font-size:12px">${(cf.retail_outflow_pct||0).toFixed(1)}%</span></div>
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
        <div class="stat-row"><span class="stat-label" data-tip="盘后交易价格（美东时间 16:00–20:00）。流动性极低，大幅波动不可靠">After-Hours Price</span>
            <span class="stat-value" style="color:${(ah.change_pct||0) >= 0 ? 'var(--green)' : 'var(--red)'}">$${Number(ah.price).toFixed(2)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="盘后价格相对正常收盘价的变化幅度">Change</span>
            <span class="stat-value" style="color:${(ah.change_pct||0) >= 0 ? 'var(--green)' : 'var(--red)'}">${(ah.change_pct||0) >= 0 ? '+' : ''}${Number(ah.change_pct).toFixed(2)}%</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="盘后成交量（通常极低，价格波动参考价值有限）">AH Volume</span>
            <span class="stat-value">${fmtNum(ah.volume)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="盘后交易的最低价 ~ 最高价区间">AH Range</span>
            <span class="stat-value">$${Number(ah.low).toFixed(2)} — $${Number(ah.high).toFixed(2)}</span></div>
        <div style="margin-top:12px;font-size:11px;color:var(--text-muted)" data-tip="P/E=市盈率（股价/EPS）P/B=市净率（股价/账面价值）EPS=每股收益 Turnover=换手率（今日量/流通股数）">
            P/E: ${q.pe || '--'} | EPS: $${q.eps || '--'} | P/B: ${q.pb || '--'} | Turnover: ${q.turnover_rate || '--'}%
        </div>
    `;
}

function renderMarketOrderbook(m) {
    const el = document.getElementById("market-orderbook");
    if (!m) { el.innerHTML = '<div class="empty">No market data</div>'; return; }
    el.innerHTML = `
        <div class="orderbook-row">
            <span class="orderbook-label" data-tip="当前最高买入报价及挂单数量（做市商买价，你卖出时的成交价）">Best Bid</span>
            <span class="orderbook-value orderbook-bid">$${Number(m.bid).toFixed(2)} <span style="font-size:12px;font-weight:400">(${m.bid_size} lot)</span></span>
        </div>
        <div class="orderbook-row">
            <span class="orderbook-label" data-tip="当前最低卖出报价及挂单数量（做市商卖价，你买入时的成交价）">Best Ask</span>
            <span class="orderbook-value orderbook-ask">$${Number(m.ask).toFixed(2)} <span style="font-size:12px;font-weight:400">(${m.ask_size} lot)</span></span>
        </div>
        <div class="orderbook-row">
            <span class="orderbook-label" data-tip="买卖价差（Ask - Bid）及占中间价的百分比。FUFU 流动性有限，价差偏大属正常；价差越小流动性越好">Spread</span>
            <span class="orderbook-value orderbook-spread">$${m.spread} (${m.spread_pct}%)</span>
        </div>
        <div class="orderbook-row">
            <span class="orderbook-label" data-tip="当日成交量加权均价（Volume-Weighted Average Price）。价格 > VWAP = 当日强势；< VWAP = 当日弱势">VWAP</span>
            <span class="orderbook-value">$${Number(m.vwap).toFixed(4)}</span>
        </div>
        <div class="orderbook-row">
            <span class="orderbook-label" data-tip="最新成交价及今日涨跌幅（相对昨日收盘价）">Last Price</span>
            <span class="orderbook-value" style="color:${m.change_pct >= 0 ? 'var(--green)' : 'var(--red)'}">$${Number(m.price).toFixed(2)} (${m.change_pct > 0 ? '+' : ''}${m.change_pct}%)</span>
        </div>
    `;
}

function renderMarketDepth() {
    const el = document.getElementById("market-depth");
    if (!el) return;
    const m = DATA.market;
    const candles = m && m.intraday;
    if (!candles || !candles.length) {
        el.innerHTML = '<div class="empty">No intraday data available for depth analysis</div>';
        return;
    }

    // Aggregate volume by price level, split into buy (close>open) and sell (close<open)
    const currentPrice = m.price || candles[candles.length - 1].close;
    const step = 0.01; // $0.01 per level
    const buckets = {}; // price -> { buy: vol, sell: vol }

    for (const c of candles) {
        const mid = ((c.high + c.low) / 2);
        const priceKey = (Math.round(mid / step) * step).toFixed(2);
        if (!buckets[priceKey]) buckets[priceKey] = { buy: 0, sell: 0 };
        if (c.close >= c.open) {
            buckets[priceKey].buy += (c.volume || 0);
        } else {
            buckets[priceKey].sell += (c.volume || 0);
        }
    }

    // Sort by price descending, limit to reasonable number of levels
    let levels = Object.entries(buckets)
        .map(([price, vols]) => ({ price: parseFloat(price), buy: vols.buy, sell: vols.sell, total: vols.buy + vols.sell }))
        .filter(l => l.total > 0)
        .sort((a, b) => b.price - a.price);

    // If too many levels, merge into wider buckets
    if (levels.length > 20) {
        const allPrices = levels.map(l => l.price);
        const minP = Math.min(...allPrices);
        const maxP = Math.max(...allPrices);
        const range = maxP - minP;
        const bucketSize = Math.max(0.02, Math.ceil(range / 15 * 100) / 100);
        const merged = {};
        for (const l of levels) {
            const key = (Math.round(l.price / bucketSize) * bucketSize).toFixed(2);
            if (!merged[key]) merged[key] = { price: parseFloat(key), buy: 0, sell: 0, total: 0 };
            merged[key].buy += l.buy;
            merged[key].sell += l.sell;
            merged[key].total += l.total;
        }
        levels = Object.values(merged).sort((a, b) => b.price - a.price);
    }

    if (!levels.length) {
        el.innerHTML = '<div class="empty">No trade data to build depth</div>';
        return;
    }

    const maxVol = Math.max(...levels.map(l => Math.max(l.buy, l.sell)), 1);
    const totalBuy = levels.reduce((s, l) => s + l.buy, 0);
    const totalSell = levels.reduce((s, l) => s + l.sell, 0);

    let html = '<div class="depth-container">';

    // Header
    html += '<div class="depth-header">';
    html += '<span class="depth-h-left">BUY VOL</span>';
    html += '<span class="depth-h-center">PRICE</span>';
    html += '<span class="depth-h-right">SELL VOL</span>';
    html += '</div>';

    // Rows
    for (const lv of levels) {
        const buyPct = (lv.buy / maxVol * 100);
        const sellPct = (lv.sell / maxVol * 100);
        const isCurrent = Math.abs(lv.price - currentPrice) <= 0.02;

        html += `<div class="depth-row${isCurrent ? ' depth-row-current' : ''}">`;

        // Buy side
        html += '<div class="depth-bid-cell">';
        if (lv.buy > 0) {
            html += `<span class="depth-vol">${fmtNum(lv.buy)}</span>`;
            html += `<div class="depth-bar-wrap depth-bar-bid-wrap"><div class="depth-bar depth-bar-bid" style="width:${buyPct}%"></div></div>`;
        }
        html += '</div>';

        // Price
        html += `<div class="depth-price-cell"><span class="${isCurrent ? 'depth-price-current' : ''}" style="color:${lv.price >= currentPrice ? 'var(--green)' : 'var(--red)'}">$${lv.price.toFixed(2)}</span></div>`;

        // Sell side
        html += '<div class="depth-ask-cell">';
        if (lv.sell > 0) {
            html += `<div class="depth-bar-wrap depth-bar-ask-wrap"><div class="depth-bar depth-bar-ask" style="width:${sellPct}%"></div></div>`;
            html += `<span class="depth-vol">${fmtNum(lv.sell)}</span>`;
        }
        html += '</div>';

        html += '</div>';
    }

    // Summary bar
    const totalVol = totalBuy + totalSell || 1;
    const buyPctTotal = (totalBuy / totalVol * 100).toFixed(1);
    const sellPctTotal = (totalSell / totalVol * 100).toFixed(1);
    const imbalance = totalBuy > totalSell * 1.1 ? "BUY DOMINANT" : totalSell > totalBuy * 1.1 ? "SELL DOMINANT" : "BALANCED";
    const imbClass = imbalance.startsWith("BUY") ? "depth-imb-buy" : imbalance.startsWith("SELL") ? "depth-imb-sell" : "depth-imb-even";

    html += '<div class="depth-summary">';
    html += `<div class="depth-summary-bar">`;
    html += `<div class="depth-sum-bid" style="width:${buyPctTotal}%">${buyPctTotal}%</div>`;
    html += `<div class="depth-sum-ask" style="width:${sellPctTotal}%">${sellPctTotal}%</div>`;
    html += `</div>`;
    html += `<div class="depth-summary-text">`;
    html += `<span>Buy: ${fmtNum(totalBuy)}</span>`;
    html += `<span class="${imbClass}">${imbalance}</span>`;
    html += `<span>Sell: ${fmtNum(totalSell)}</span>`;
    html += `</div>`;
    html += '</div>';

    html += '</div>';
    el.innerHTML = html;
}

function renderMarketVolume(m) {
    const el = document.getElementById("market-volume");
    if (!m) { el.innerHTML = '<div class="empty">No market data</div>'; return; }
    const rvolClass = m.relative_volume >= 2 ? 'rvol-high' : m.relative_volume >= 0.8 ? 'rvol-normal' : 'rvol-low';
    const rvolLabel = m.relative_volume >= 2 ? 'HIGH' : m.relative_volume >= 0.8 ? 'NORMAL' : 'LOW';
    el.innerHTML = `
        <div class="stat-row"><span class="stat-label" data-tip="今日已成交股数（实时更新）">Today Volume</span><span class="stat-value">${fmtNum(m.volume)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="历史日均成交量（用于计算相对成交量基准）">Avg Volume</span><span class="stat-value">${fmtNum(m.avg_volume)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="近 10 个交易日平均成交量（短期均量参考）">10D Avg Volume</span><span class="stat-value">${fmtNum(m.avg_volume_10d)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="今日成交量 / 历史均量\nHIGH(>2x) = 异常放量，可能有重大消息或机构集中动作\nNORMAL = 正常水平\nLOW(<0.8x) = 缩量，观望为主">Relative Volume</span><span class="stat-value"><span class="rvol-badge ${rvolClass}">${m.relative_volume}x ${rvolLabel}</span></span></div>
        <div class="stat-row"><span class="stat-label" data-tip="当前市值 = 股价 × 总流通股数">Market Cap</span><span class="stat-value">${fmtNum(m.market_cap)}</span></div>
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
        <div class="stat-row"><span class="stat-label" data-tip="今日开盘价（美东时间 9:30 第一笔成交价）">Open</span><span class="stat-value">$${Number(m.open).toFixed(2)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="昨日收盘价（用于计算今日涨跌幅基准）">Prev Close</span><span class="stat-value">$${Number(m.prev_close).toFixed(2)}</span></div>
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
        <div class="stat-row"><span class="stat-label" data-tip="估算买入量：5分钟K线中收盘价 > 开盘价（阳线）的蜡烛成交量合计">Buy Volume (est.)</span><span class="stat-value" style="color:var(--green)">${fmtNum(m.buy_volume)}</span></div>
        <div class="stat-row"><span class="stat-label" data-tip="估算卖出量：5分钟K线中收盘价 < 开盘价（阴线）的蜡烛成交量合计">Sell Volume (est.)</span><span class="stat-value" style="color:var(--red)">${fmtNum(m.sell_volume)}</span></div>
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
            <th data-tip="同业竞争对手股票代码（FUFU 以琥珀色高亮显示）">Symbol</th>
            <th class="num" data-tip="当前股价（美元）">Price</th>
            <th class="num" data-tip="今日涨跌幅（相对昨日收盘价）">Change</th>
            <th class="num" data-tip="今日成交量（股数）">Volume</th>
            <th class="num" data-tip="相对成交量 = 今日量 / 历史均量。HIGH(>2x) = 异常活跃">RVol</th>
            <th class="num" data-tip="买卖价差占中间价的百分比（流动性指标，越小流动性越好）">Spread%</th>
            <th class="num" data-tip="买盘压力占比（估算）。>50% 表示买方占主导">Buy%</th>
            <th class="num" data-tip="市值 = 股价 × 流通股数（公司规模参考）">Mkt Cap</th>
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

// ─── Price Chart (Canvas) ────────────────────────────
function renderPriceChart() {
    const container = document.getElementById("chart-container");
    if (!container) return;

    const intraday = DATA.market?.intraday;
    if (!intraday?.length) {
        // Keep canvas but show message
        const canvas = document.getElementById("price-chart");
        if (canvas) canvas.style.display = "none";
        if (!container.querySelector(".empty")) {
            const msg = document.createElement("div");
            msg.className = "empty";
            msg.textContent = "盘中数据暂不可用（非交易时段）";
            container.appendChild(msg);
        }
        return;
    }

    // Remove any empty message
    const emptyMsg = container.querySelector(".empty");
    if (emptyMsg) emptyMsg.remove();

    const canvas = document.getElementById("price-chart");
    canvas.style.display = "block";

    const dpr = window.devicePixelRatio || 1;
    const w = container.clientWidth;
    const h = 320;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + "px";
    canvas.style.height = h + "px";

    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    // Layout
    const pad = { top: 24, right: 65, bottom: 32, left: 12 };
    const chartW = w - pad.left - pad.right;
    const priceH = (h - pad.top - pad.bottom) * 0.72;
    const gap = (h - pad.top - pad.bottom) * 0.06;
    const volH = (h - pad.top - pad.bottom) * 0.22;
    const volTop = pad.top + priceH + gap;

    // Data
    const closes = intraday.map(c => c.close);
    const opens = intraday.map(c => c.open);
    const highs = intraday.map(c => c.high);
    const lows = intraday.map(c => c.low);
    const volumes = intraday.map(c => c.volume);
    const times = intraday.map(c => c.time);
    const allPrices = intraday.flatMap(c => [c.high, c.low]);
    const minP = Math.min(...allPrices) * 0.998;
    const maxP = Math.max(...allPrices) * 1.002;
    const maxV = Math.max(...volumes, 1);
    const rangeP = maxP - minP || 1;

    // Trend color
    const isUp = closes[closes.length - 1] >= closes[0];
    const lineColor = isUp ? "#10b981" : "#ef4444";
    const fillTop = isUp ? "rgba(16,185,129,0.15)" : "rgba(239,68,68,0.15)";
    const fillBot = "rgba(0,0,0,0)";

    // Mappers
    const xMap = i => pad.left + (i / Math.max(closes.length - 1, 1)) * chartW;
    const yMap = p => pad.top + (1 - (p - minP) / rangeP) * priceH;

    // Clear
    ctx.clearRect(0, 0, w, h);

    // Horizontal grid + price labels
    ctx.textAlign = "left";
    ctx.font = "11px -apple-system, BlinkMacSystemFont, sans-serif";
    const gridN = 5;
    for (let i = 0; i <= gridN; i++) {
        const y = pad.top + (i / gridN) * priceH;
        const price = maxP - (i / gridN) * rangeP;
        ctx.strokeStyle = "rgba(30,41,59,0.4)";
        ctx.lineWidth = 0.5;
        ctx.beginPath();
        ctx.moveTo(pad.left, y);
        ctx.lineTo(w - pad.right, y);
        ctx.stroke();
        ctx.fillStyle = "#64748b";
        ctx.fillText("$" + price.toFixed(2), w - pad.right + 8, y + 4);
    }

    // Price area fill (gradient)
    const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + priceH);
    grad.addColorStop(0, fillTop);
    grad.addColorStop(1, fillBot);
    ctx.beginPath();
    ctx.moveTo(xMap(0), yMap(closes[0]));
    for (let i = 1; i < closes.length; i++) ctx.lineTo(xMap(i), yMap(closes[i]));
    ctx.lineTo(xMap(closes.length - 1), pad.top + priceH);
    ctx.lineTo(xMap(0), pad.top + priceH);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Price line
    ctx.beginPath();
    ctx.moveTo(xMap(0), yMap(closes[0]));
    for (let i = 1; i < closes.length; i++) ctx.lineTo(xMap(i), yMap(closes[i]));
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = 2;
    ctx.lineJoin = "round";
    ctx.stroke();

    // Current price dashed line
    const lastPrice = closes[closes.length - 1];
    const lastY = yMap(lastPrice);
    ctx.setLineDash([5, 4]);
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.left, lastY);
    ctx.lineTo(w - pad.right, lastY);
    ctx.stroke();
    ctx.setLineDash([]);

    // Current price badge
    ctx.fillStyle = lineColor;
    const badgeW = 58, badgeH = 20;
    const badgeX = w - pad.right + 2;
    const badgeY = lastY - badgeH / 2;
    ctx.beginPath();
    ctx.roundRect(badgeX, badgeY, badgeW, badgeH, 4);
    ctx.fill();
    ctx.fillStyle = "#fff";
    ctx.font = "bold 11px -apple-system, BlinkMacSystemFont, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("$" + lastPrice.toFixed(2), badgeX + badgeW / 2, badgeY + 14);

    // Volume bars
    const barW = Math.max(chartW / volumes.length * 0.7, 2);
    for (let i = 0; i < volumes.length; i++) {
        const barH = (volumes[i] / maxV) * volH;
        const x = xMap(i) - barW / 2;
        const y = volTop + volH - barH;
        const up = closes[i] >= opens[i];
        ctx.fillStyle = up ? "rgba(16,185,129,0.5)" : "rgba(239,68,68,0.5)";
        ctx.fillRect(x, y, barW, barH);
    }

    // Volume divider line
    ctx.strokeStyle = "rgba(30,41,59,0.3)";
    ctx.lineWidth = 0.5;
    ctx.beginPath();
    ctx.moveTo(pad.left, volTop - gap / 2);
    ctx.lineTo(w - pad.right, volTop - gap / 2);
    ctx.stroke();

    // Volume label
    ctx.fillStyle = "#475569";
    ctx.font = "10px -apple-system, BlinkMacSystemFont, sans-serif";
    ctx.textAlign = "left";
    ctx.fillText("VOL", w - pad.right + 8, volTop + 10);

    // Time labels
    ctx.fillStyle = "#64748b";
    ctx.font = "10px -apple-system, BlinkMacSystemFont, sans-serif";
    ctx.textAlign = "center";
    const step = Math.max(Math.ceil(times.length / 8), 1);
    for (let i = 0; i < times.length; i += step) {
        ctx.fillText(times[i], xMap(i), h - 6);
    }
    // Always show last time
    if (times.length > 1) {
        ctx.fillText(times[times.length - 1], xMap(times.length - 1), h - 6);
    }

    // Last dot
    ctx.beginPath();
    ctx.arc(xMap(closes.length - 1), lastY, 4, 0, Math.PI * 2);
    ctx.fillStyle = lineColor;
    ctx.fill();
    ctx.strokeStyle = "#0a0e17";
    ctx.lineWidth = 2;
    ctx.stroke();

    // ── Tooltip + crosshair on hover ──
    // Create tooltip element if not exists
    let tooltip = container.querySelector(".chart-tooltip");
    if (!tooltip) {
        tooltip = document.createElement("div");
        tooltip.className = "chart-tooltip";
        container.appendChild(tooltip);
    }
    let crossH = container.querySelector(".chart-crosshair-h");
    let crossV = container.querySelector(".chart-crosshair-v");
    if (!crossH) {
        crossH = document.createElement("div");
        crossH.className = "chart-crosshair-h";
        container.appendChild(crossH);
    }
    if (!crossV) {
        crossV = document.createElement("div");
        crossV.className = "chart-crosshair-v";
        container.appendChild(crossV);
    }

    // Store chart params for mouse handler
    canvas._chartData = { intraday, xMap, yMap, pad, w, h, priceH, volTop, volH, closes, times, volumes, opens, highs, lows };

    canvas.onmousemove = function(e) {
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const cd = canvas._chartData;

        if (mx < cd.pad.left || mx > cd.w - cd.pad.right || my < cd.pad.top || my > cd.h - 4) {
            tooltip.style.display = "none";
            crossH.style.display = "none";
            crossV.style.display = "none";
            return;
        }

        // Find closest candle index
        const ratio = (mx - cd.pad.left) / (cd.w - cd.pad.left - cd.pad.right);
        const idx = Math.round(ratio * (cd.closes.length - 1));
        if (idx < 0 || idx >= cd.closes.length) return;

        const c = cd.intraday[idx];
        const cx = cd.xMap(idx);
        const cy = cd.yMap(c.close);

        // Crosshair
        crossH.style.display = "block";
        crossH.style.top = cy + "px";
        crossV.style.display = "block";
        crossV.style.left = cx + "px";
        crossV.style.top = cd.pad.top + "px";
        crossV.style.height = (cd.priceH + cd.volH + (cd.volTop - cd.pad.top - cd.priceH)) + "px";

        // Tooltip content
        const chg = ((c.close - c.open) / c.open * 100).toFixed(2);
        const chgSign = chg >= 0 ? "+" : "";
        const color = c.close >= c.open ? "var(--green)" : "var(--red)";
        tooltip.innerHTML = `
            <div style="color:var(--text-muted);margin-bottom:2px">${c.time}</div>
            <div class="tt-price" style="color:${color}">$${c.close.toFixed(2)} <span style="font-size:12px">${chgSign}${chg}%</span></div>
            <div class="tt-vol">O:$${c.open.toFixed(2)} H:$${c.high.toFixed(2)} L:$${c.low.toFixed(2)}</div>
            <div class="tt-vol">Vol: ${fmtNum(c.volume)}</div>
        `;
        tooltip.style.display = "block";

        // Position tooltip
        let tx = cx + 14;
        if (tx + 160 > cd.w) tx = cx - 170;
        let ty = cy - 40;
        if (ty < 0) ty = cy + 14;
        tooltip.style.left = tx + "px";
        tooltip.style.top = ty + "px";
    };

    canvas.onmouseleave = function() {
        tooltip.style.display = "none";
        crossH.style.display = "none";
        crossV.style.display = "none";
    };
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
