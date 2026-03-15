# FUFU Intelligence — PRD

## Overview
Private stock intelligence dashboard for BitFuFu Inc (NASDAQ: FUFU), serving the company's CFO/IR team and secondary market trading desk.

- **Version**: v1.0316A
- **URL**: https://fufu.btcmine.info
- **Repo**: `tincomking/btcmine-fufu` (GitHub Pages)
- **Backend**: DataCenter API (`api.btcmine.info`)
- **Stack**: Vanilla HTML/CSS/JS, no framework
- **Auth**: Password-gated (SHA-256 hash)

## Code Stats

| File | Lines |
|------|-------|
| `js/app.js` | 1,115 |
| `js/report.js` | 1,147 |
| `css/style.css` | 1,177 |
| `index.html` | 244 |
| **Total** | **3,683** |

## Data Sources (Current)

| Source | Data | Update Freq |
|--------|------|-------------|
| yfinance (`fufu_market`) | L1 bid/ask, OHLCV, intraday 5m, VWAP, volume profile, peer comparison | 5 min (开盘30s) |
| Webull (`webull_market`) | Capital flow (inst/retail), after-hours, P/E/EPS/P/B, turnover, extended bars | 5 min (开盘30s) |
| yfinance (`analyst_data`) | Analyst ratings, price targets, upgrades/downgrades, EPS estimates | 1 hour |
| SEC EdgarTools | Form 4 insider trades, 13F institutions, 8-K events, SC 13G/13D | Daily |
| FINRA | Short interest, dark pool ATS volume | Bi-weekly / Weekly |
| TA library (`stock_ta`) | RSI, MACD, Bollinger, MAs, VWAP | 30 min (开盘30s) |
| BTC correlation | FUFU-BTC 7/30/90d rolling correlation + Beta | Daily |
| Corporate actions | Splits, dividends | Daily |

## Features (Live)

- Password-gated login
- 7-tab dashboard: Overview / Market Data / Insider / Institutions / Short Interest / Events / Technicals
- **Canvas 价格走势图** — 日内5分钟折线图 + 成交量柱 + 鼠标十字线 Tooltip
- **中文详细说明** — 每个卡片有 card-desc 段落说明 + 字段级 data-tip 悬浮提示
- **Daily Report** (`report.html`) — auto-generated 12-section market close summary
  - Executive Snapshot, Price Action, Capital Flow, After Hours, Technicals
  - Analyst Coverage (4 analysts, consensus Buy, mean target $6.13)
  - Peer Comparison, Valuation, Short/Dark Pool, Ownership, BTC Correlation
  - Rule-based Chinese commentary with scoring system
  - Print/PDF export via `@media print`
  - Hourly check on DC, generates after US market close (16:30 ET), idempotent
  - TG notification on generation
- BTC price header
- Auto-refresh 5 min
- **Market Hours Dynamic Scheduling** — 开盘期间自动提高采集频率至 30s，休市恢复 5min
- Cloudflare WAF bypass (aggregated `/api/equity/{sym}/dashboard`)
  - All frontend JS loads from dashboard endpoint (individual endpoints blocked by WAF)

## Data Persistence (DC SQLite)

| DB Table | Data | Rows (FUFU) |
|----------|------|-------------|
| `btc_predict_data.fufu_market` | 价格/盘口/K线 JSON | 20KB blob |
| `btc_predict_data.webull_market` | 资金流/盘后/估值 JSON | 41KB blob |
| `btc_predict_data.analyst_data` | 分析师评级 JSON | 11KB blob |
| `btc_predict_data.stock_btc_correlation` | BTC相关性 JSON | 168B blob |
| `stock_indicator` | RSI/MACD/BB/EMA/VWAP | 2,401 |
| `insider_trade` | Form 4 内部人交易 | 0 (近期无交易) |
| `institutional_holding` | 13F 机构持仓 | 3 |
| `sec_event` | 8-K/6-K 重大事件 | 18 |
| `sec_ownership` | 13G/13D 大股东 | 3 |
| `short_interest` | FINRA 做空数据 | 1 |
| `dark_pool_volume` | FINRA 暗池数据 | 1 |
| `corporate_action` | 拆股/分红 | 0 |
| `entity_master` | 公司信息 | 1 |
| `daily_report` | AI 日报 | 1 |
| `stock_alerts` | 价格预警 | 8 |
| `market_quote` | 历史行情 | 7,836 |

## API Endpoints (DC)

| Endpoint | Data |
|----------|------|
| `GET /api/equity/{sym}/dashboard` | Aggregated: all data below in single response |
| — includes: | market, webull, analyst, indicators, insider, institutions, events, ownership, short_interest, darkpool, actions, correlation, alerts, latest_report, report_history, entity, market_peers |
| `GET /api/equity/{sym}/report/latest` | Full daily report (DC-only, blocked by CF WAF) |
| `GET /api/equity/{sym}/report/history` | Report date list (DC-only) |
| `GET /api/equity/{sym}/report/{date}` | Specific date report (DC-only) |

## DC Collectors

| Collector | Config Key | Interval (closed) | Interval (open) |
|-----------|-----------|-------------------|-----------------|
| `fufu_market` | — | 300s | 30s |
| `webull_market` | `webull_market_interval` | 300s | 30s |
| `stock_ta` | — | 300s | 30s |
| `analyst_data` | `analyst_data_interval` | 3600s | 3600s |
| `daily_report` | `daily_report_interval` | 3600s | 3600s |
| `btcmine_prices` | — | 300s | 60s |
| `stock_correlation` | — | 1800s | 300s |
| `market_hours_monitor` | — | 60s | 60s |

## Out of Scope

- Real-time WebSocket streaming (Finnhub free tier 不支持小盘股 tick)
- L2 order book (pending FactSet entitlements — API auth works but market data subscription needed)
- Options flow / implied volatility (FUFU has NO listed options — too small cap ~$400M)
- Historical report date navigation (Cloudflare WAF blocks individual report endpoints)

## Technical Notes

- **Cloudflare WAF**: Blocks individual `/api/equity/{sym}/xxx` paths (insider, events, report, etc.). Only `/dashboard` aggregate endpoint passes. All frontend JS must use dashboard.
- **FactSet API**: Credentials stored in `.env` (FACTSET_USERNAME / FACTSET_API_KEY) — auth works but all price endpoints return 403. Need FactSet account manager to enable NASDAQ market data entitlements.
- **Webull L2 depth**: Returns `{}` when market closed. Should work during US market hours (9:30 PM - 4:00 AM SGT).
- **GitHub Pages SSL**: Custom domain `fufu.btcmine.info` — cert pending provisioning by GitHub.
- **FUFU Analyst Coverage**: HC Wainwright ($7 Buy), Roth Capital ($6 Buy), B.Riley ($7.31 Buy), Northland ($5.50 Hold)
- **Entity Master**: CUSIP/ISIN 为空 — FinanceDatabase 对外国私人发行人覆盖不完整
