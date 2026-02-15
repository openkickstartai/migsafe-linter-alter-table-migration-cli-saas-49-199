# 🛡️ MigSafe

**Catch dangerous database migrations before they lock your production tables.**

MigSafe is a CLI linter that statically analyzes SQL migration files and detects operations that will acquire heavy locks, rewrite tables, or destroy data — **before** you run them against production.

> *"squawk tells you it's bad. MigSafe tells you it'll hold an ACCESS EXCLUSIVE lock for 47 seconds on your 12M-row orders table."*

## 🚀 Quick Start

```bash
pip install typer rich
python migsafe.py lint migrations/
```

With row count estimation:
```bash
python migsafe.py lint migrations/0042_add_status.sql --rows 5000000
```

JSON output for CI:
```bash
python migsafe.py lint migrations/ --format json --fail-on high
```

SARIF for GitHub Code Scanning:
```bash
python migsafe.py lint migrations/ --format sarif > results.sarif
```

## 🔍 Rules

| Rule | Severity | What it catches |
|------|----------|----------------|
| BAN001 | 🔴 critical | `DROP TABLE` — permanent data loss |
| BAN002 | 🟠 high | `DROP COLUMN` — irreversible, breaks queries |
| BAN003 | 🟡 medium | `RENAME TABLE/COLUMN` — breaks app queries |
| LCK001 | 🔴 critical | `ADD COLUMN NOT NULL` without `DEFAULT` — full table rewrite |
| LCK002 | 🟠 high | `CREATE INDEX` without `CONCURRENTLY` — blocks writes |
| LCK003 | 🟠 high | `ADD FOREIGN KEY` without `NOT VALID` — full table scan under lock |
| LCK004 | 🔴 critical | `ALTER COLUMN TYPE` — full table rewrite |
| LCK005 | 🟠 high | `SET NOT NULL` — full table scan (use CHECK constraint) |

## 📊 Why Pay for MigSafe?

The free CLI catches dangerous patterns. But production databases need more:

- **Free CLI gives you rules.** Pro gives you **actual lock time estimates** by connecting to your database and reading `pg_class.reltuples`.
- **Free CLI runs locally.** Pro runs in CI with **SARIF upload to GitHub Security tab**.
- **Enterprise adds approval workflows** — no migration hits production without DBA sign-off, with full audit trail for SOC2.

Every hour of downtime costs $5k-$100k. MigSafe Pro pays for itself after preventing **one** bad migration.

## 💰 Pricing

| Feature | Free (CLI) | Pro ($49/mo) | Enterprise ($199/mo) |
|---------|:----------:|:------------:|:--------------------:|
| 8 built-in lint rules | ✅ | ✅ | ✅ |
| Text + JSON output | ✅ | ✅ | ✅ |
| Lock type detection | ✅ | ✅ | ✅ |
| Row-count lock estimation | CLI flag | 🔌 DB-connected | 🔌 DB-connected |
| SARIF output for GitHub | ❌ | ✅ | ✅ |
| Custom rules (YAML) | ❌ | ✅ | ✅ |
| GitHub Action / GitLab CI | ❌ | ✅ | ✅ |
| Slack / PagerDuty alerts | ❌ | ❌ | ✅ |
| DBA approval workflow | ❌ | ❌ | ✅ |
| SOC2 audit trail | ❌ | ❌ | ✅ |
| Support | Community | Email | Dedicated Slack |

## 🏗️ Supported Frameworks

MigSafe works on raw `.sql` files. Use it with any migration framework:
Django, Rails, Alembic, Flyway, Prisma, golang-migrate, Knex, Sequelize.

## License

MIT — Free CLI forever. Pro/Enterprise features via [migsafe.dev](https://migsafe.dev).
