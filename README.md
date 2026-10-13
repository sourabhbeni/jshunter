# jshunter

Harvest a target's JavaScript files for leaked secrets and hidden endpoints. Passive recon for web bug-bounty work.

Given a URL, jshunter fetches the page, discovers same-host `<script src>` files, downloads them, and reports:

- **Secrets** — AWS keys, Google API keys, GitHub/Slack/Stripe tokens, JWTs, Firebase URLs, private-key blocks, and entropy-gated generic API key/token assignments, each with a severity rating.
- **Endpoints** — API paths, fetch/XHR call targets, GraphQL endpoints, absolute URLs, and partial paths built by string concatenation.
- **Sourcemaps** — `sourceMappingURL` references, which often leak original source code.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m jshunter.cli https://target.example --i-am-authorized
python -m jshunter.cli https://target.example --i-am-authorized --json -o report.json
```

The `--i-am-authorized` flag is required. Only test your own assets, in-scope bug-bounty targets, or labs.

Options: `--max-js` (default 40), `--no-sourcemaps`, `--timeout`, `-o/--output`, `--json`.

## As a library

```python
from jshunter import hunt
report = hunt("https://target.example")
```

## Scope & ethics

jshunter makes plain GET requests only — no form submissions, no auth bypass, no exploitation. A matched pattern is a **lead, not a vulnerability**: verify every finding manually before reporting it, and never exfiltrate or use a discovered credential beyond the minimum proof needed for a report.

## Tests

```bash
python -m pytest tests/ -q
```
