<p align="center">
  <img src="assets/logo.svg" alt="SeQuery" width="96" />
</p>

# SeQuery

Lokalny demonstrator **Prompt Injection** w systemie Multi-Tenant Text-to-SQL (CRM) oraz obrony wielowarstwowej (**Sentinel -> AST `sqlglot` -> PostgreSQL RLS/CLS**).

Szczegóły architektury i lista zadań dla agentów: [AGENTS.md](AGENTS.md).

![SeQuery UI](assets/preview.jpg)

## Stack

- PostgreSQL 16 (Docker, polityki RLS oraz uprawnienia kolumnowe CLS)
- Ollama (`qwen2.5-coder:7b`)
- Python 3.10+, FastAPI, `sqlglot`, `psycopg2`
- [Task](https://taskfile.dev)

## Architektura

| Element | Opis |
|---|---|
| **SQL Generator** | Zamienia pytanie w języku naturalnym na zapytanie `SELECT` (Ollama) |
| **Sentinel** | Wykrywa próby Prompt Injection oraz Jailbreaku (heurystyka + LLM) |
| **AST Guard** | Waliduje drzewo zapytania w `sqlglot` (whitelist tabel i kolumn, tylko `SELECT`) |
| **PostgreSQL RLS/CLS** | Izoluje dane między firmami (`app.current_company_id`) i blokuje dostęp do tajnych kolumn (`SET ROLE`) |

Tryby pracy:
- `vulnerable`: brak bramek, wyłączone RLS (`SET row_security = off`), pozwala zobaczyć pełny skutek udanego ataku.
- `secure`: aktywne bramki Sentinel + AST oraz twarde egzekwowanie RLS/CLS w bazie.
- `compare`: wykonuje oba tryby obok siebie dla tego samego zapytania.

## Uruchomienie

```bash
task setup   # tworzy venv, instaluje zależności i pobiera model Ollama
task up      # uruchamia PostgreSQL w Dockerze
task ui      # startuje aplikację na http://127.0.0.1:8000
```

Komendy pomocnicze CLI:

```bash
task demo        # porównanie scenariuszy PI-01, PI-02 i BENIGN w terminalu
task test-rls    # test polityk RLS/CLS bezpośrednio w PostgreSQL (bez udziału LLM)
task reset-db    # reset kontenera i wolumenu bazy danych
task doctor      # sprawdzenie środowiska (Docker, Ollama, Python)
```

## Dane testowe w bazie

- **Firma Alpha** (`company_id=1`): `anna_admin_alpha` (`admin`), `jan_sales_alpha` (`sales_rep`), `ewa_viewer_alpha` (`viewer`)
- **Firma Beta** (`company_id=2`): `marek_admin_beta` (`admin`), `piotr_sales_beta` (`sales_rep`)
- Kolumna `deals.secret_margin_notes` jest dostępna wyłącznie dla roli `admin` (CLS).

## Struktura projektu

```text
assets/logo.svg      logo projektu
assets/preview.jpg   zrzut ekranu interfejsu
app.py               serwer FastAPI
templates/           szablon HTML
static/              style CSS i logika UI (JS)
agent_swarm.py       logika agentów, walidacja AST i obsługa bazy
init.sql             schemat bazy, dane początkowe, polityki RLS/CLS
docker-compose.yml   konfiguracja PostgreSQL 16
Taskfile.yml         automatyzacja zadań
```
