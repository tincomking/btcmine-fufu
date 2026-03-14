# FUFU Intelligence — PRD

## Overview
Private stock intelligence dashboard for BitFuFu Inc (NASDAQ: FUFU), serving the company's CFO/IR team and secondary market trading desk.

- **URL**: https://fufu.btcmine.info
- **Repo**: `tincomking/btcmine-fufu` (GitHub Pages)
- **Backend**: DataCenter API (`api.btcmine.info`)
- **Stack**: Vanilla HTML/CSS/JS, no framework
- **Auth**: Password-gated (SHA-256 hash)

## Data Sources (Current)

| Source | Data | Update Freq |
|--------|------|-------------|
| yfinance (`fufu_market`) | L1 bid/ask, OHLCV, intraday 5m, VWAP, volume profile, peer comparison | 5 min |
| Webull (`webull_market`) | Capital flow (inst/retail), after-hours, P/E/EPS/P/B, turnover, shares | 5 min |
| yfinance (`analyst_data`) | Analyst ratings, price targets, upgrades/downgrades, EPS estimates | 1 hour |
| SEC EdgarTools | Form 4 insider trades, 13F institutions, 8-K events, SC 13G/13D | Daily |
| FINRA | Short interest, dark pool ATS volume | Bi-weekly |
| TA library (`stock_ta`) | RSI, MACD, Bollinger, MAs | 30 min |
| BTC correlation | FUFU-BTC 30d rolling correlation | Daily |
| Corporate actions | Splits, dividends | Daily |

## Features (Live)

- Password-gated login
- 7-tab dashboard: Overview / Market Data / Insider / Institutions / Short Interest / Events / Technicals
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
- Cloudflare WAF bypass (aggregated `/api/equity/{sym}/dashboard`)
  - All frontend JS loads from dashboard endpoint (individual endpoints blocked by WAF)

## API Endpoints (DC)

| Endpoint | Data |
|----------|------|
| `GET /api/equity/{sym}/dashboard` | Aggregated: all data below in single response |
| — includes: | market, webull, analyst, indicators, insider, institutions, events, ownership, short_interest, darkpool, actions, correlation, alerts, latest_report, report_history, entity, market_peers |
| `GET /api/equity/{sym}/report/latest` | Full daily report (DC-only, blocked by CF WAF) |
| `GET /api/equity/{sym}/report/history` | Report date list (DC-only) |
| `GET /api/equity/{sym}/report/{date}` | Specific date report (DC-only) |

## DC Collectors

| Collector | Config Key | Interval |
|-----------|-----------|----------|
| `webull_market` | `webull_market_interval` | 300s |
| `analyst_data` | `analyst_data_interval` | 3600s |
| `daily_report` | `daily_report_interval` | 3600s |

## Out of Scope

- Real-time WebSocket streaming
- L2 order book (pending FactSet entitlements — API auth works but market data subscription needed)
- Options flow / implied volatility (FUFU has NO listed options — too small cap ~$400M)
- Historical report date navigation (Cloudflare WAF blocks individual report endpoints)

## Technical Notes

- **Cloudflare WAF**: Blocks individual `/api/equity/{sym}/xxx` paths (insider, events, report, etc.). Only `/dashboard` aggregate endpoint passes. All frontend JS must use dashboard.
- **FactSet API**: Credentials stored in `.env` (FACTSET_USERNAME / FACTSET_API_KEY) — auth works but all price endpoints return 403. Need FactSet account manager to enable NASDAQ market data entitlements.
- **Webull L2 depth**: Returns `{}` when market closed. Should work during US market hours (9:30 PM - 4:00 AM SGT).
- **GitHub Pages SSL**: Custom domain `fufu.btcmine.info` — cert pending provisioning by GitHub.
- **FUFU Analyst Coverage**: HC Wainwright ($7 Buy), Roth Capital ($6 Buy), B.Riley ($7.31 Buy), Northland ($5.50 Hold)
