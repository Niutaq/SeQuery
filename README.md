<p align="center">
  <img src="assets/logo.svg" alt="SeQuery" width="96" />
</p>

<div align="center">

## SeQuery

</div>

Local **Prompt Injection** demonstrator for Multi-Tenant Text-to-SQL (CRM) and defense-in-depth (**Sentinel -> AST `sqlglot` -> PostgreSQL RLS/CLS**).

<img width="1886" height="1011" alt="image" src="https://github.com/user-attachments/assets/74aab07b-5b4c-40b9-a268-a6a7b9cb53e4" />

## Stack

- PostgreSQL 16 (Docker, Row-Level Security and Column-Level Security)
- Ollama (local LLM inference, e.g. `qwen2.5-coder:7b`)
- Python 3.10+, FastAPI, `sqlglot`, `psycopg2`
- [Task](https://taskfile.dev)

## Architecture

| Component | Role |
|---|---|
| **SQL Generator** | Converts a natural-language question into a `SELECT` query (Ollama) |
| **Sentinel** | Detects Prompt Injection and Jailbreak attempts (lexical heuristics + LLM) |
| **AST Guard** | Validates and rewrites the SQL syntax tree with `sqlglot` (table/column allow-list, `SELECT` only) |
| **PostgreSQL RLS/CLS** | Isolates rows per tenant (`app.current_company_id`) and denies restricted columns (`SET ROLE`) |

Execution modes:
- `vulnerable`: gates disabled and `SET row_security = off`, showing the full impact of a successful Prompt Injection.
- `secure`: Sentinel + AST validation enabled and RLS/CLS enforced by PostgreSQL.
- `compare`: runs both modes side by side on the same prompt.

## Quick Start

```bash
task setup   # creates venv, installs dependencies, pulls Ollama model
task up      # starts PostgreSQL in Docker
task ui      # launches web UI at http://127.0.0.1:8000
```

CLI helpers:

```bash
task demo        # compares attack and benign scenarios in the terminal
task test-rls    # verifies RLS/CLS directly in PostgreSQL without LLM
task reset-db    # resets database container and volume
task doctor      # checks Docker, Ollama, and Python dependencies
```

## Seed Data

- **Alpha Tech Sp. z o.o.** (`company_id=1`): `anna_admin_alpha` (`admin`), `jan_sales_alpha` (`sales_rep`), `ewa_viewer_alpha` (`viewer`)
- **Beta Logistics S.A.** (`company_id=2`): `marek_admin_beta` (`admin`), `piotr_sales_beta` (`sales_rep`)
- Column `deals.secret_margin_notes` is granted exclusively to the `admin` role (CLS).

## Project Structure

```text
assets/logo.svg      project logo
assets/preview.jpg   web UI screenshot
app.py               FastAPI server and SSE endpoints
templates/           HTML template
static/              CSS styles and UI logic (JS)
agent_swarm.py       multi-agent pipeline, AST guard, and DB execution
init.sql             schema, seed data, and RLS/CLS policies
docker-compose.yml   PostgreSQL 16 setup
Taskfile.yml         task runner configuration
```
