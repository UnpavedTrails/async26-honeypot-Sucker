# Demo attack script

Simulates scanner-style traffic against the honeypot so the pipeline has
something realistic to analyze. Run it only against your own deployment.

## Run it

Requires Node 18+. No install step.

```
node attack_demo.js https://<your-honeypot>.onrender.com
```

Run a single scenario instead of all three:

```
node attack_demo.js https://<your-honeypot>.onrender.com recon
node attack_demo.js https://<your-honeypot>.onrender.com stuffing
node attack_demo.js https://<your-honeypot>.onrender.com injection
```

## What it does

| Scenario | Looks like | User-Agent |
|---|---|---|
| warm-up | A normal browser visit (also wakes a sleeping Render instance) | Chrome |
| recon | Automated discovery of common admin/config paths | Nmap Scripting Engine |
| stuffing | About 18 rapid login attempts with common credentials | python-requests |
| injection | Textbook SQL/XSS/path-traversal strings in login fields and query params | sqlmap |

The honeypot groups sessions by IP + User-Agent, so each scenario appears as
its own session card on the dashboard.

## Before running

1. Honeypot deployed and reachable.
2. Analysis service running (`npm start` in `analysis-service/`).
3. Dashboard open in a browser.

Narration appears within one poll cycle (about 10 seconds) of each burst.
