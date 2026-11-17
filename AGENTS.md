# SeQuery - instrukcja dla agenta (wdrożenie / poprawki)

Dokument dla **kolejnego agenta AI** lub developera: zamysł projektu, eksperymenty edukacyjne oraz **co wdrożyć**, żeby demo było uczciwe (widać realny LLM, nie „spreparowane” dane).

Stack (tylko lokalny FOSS): PostgreSQL 16 + RLS/CLS · Ollama (`qwen2.5-coder:7b`) · Python · FastAPI UI · Task. **Bez płatnych API.**

---

## 1. Zamysł (1 akapit)

SeQuery to akademicki demonstrator **Multi-Tenant Text-to-SQL** (CRM: `companies` / `users` / `deals`, tenanty Alpha/Beta). Użytkownik pyta **po polsku (NL)**; lokalny LLM generuje SQL. Cel: pokazać, że **Prompt Injection** może zmusić model do zbyt szerokiego SQL, oraz że obrona musi być **Defense-in-Depth** (Sentinel → AST/`sqlglot` → PostgreSQL RLS/CLS), a nie samo „uproś model w prompcie”.

---

## 2. Co system robi

| Element | Zachowanie |
|--------|------------|
| Użytkownik CRM | Kontekst `user_id` / `company_id` / `role` |
| Tryb **vulnerable** | Zaufanie do SQL z modelu; RLS wyłączone (`row_security = off`) - widać wyciek |
| Tryb **secure** | Bramki przed egzekucją; RLS/CLS egzekwowane |
| **Compare** | Oba tryby obok siebie |
| Presety | `PI-01` cross-tenant dump · `PI-02` eskalacja/secrets · `BENIGN` legalne zapytanie |
| UI | PL/EN (chrome); **zapytania NL na razie po polsku** |

Pliki kluczowe: `agent_swarm.py`, `app.py`, `init.sql`, `templates/` + `static/`, `Taskfile.yml`.

---

## 3. Eksperymenty (oczekiwane wyniki)

| ID | Vulnerable | Secure |
|----|------------|--------|
| PI-01 | Realny SQL z Ollamy (często szeroki `SELECT`); wiersze z obcego `company_id` i/lub `secret_margin_notes` | Wyciek zatrzymany; **nadal widać SQL wygenerowany przez model** |
| PI-02 | Secrets / eskalacja widoczne | Blokada / brak secrets |
| BENIGN | Sensowny wynik | Sensowny wynik bez false positive |

Kryterium sukcesu edukacyjnego: komisja widzi **różnicę trybów** oraz **dowód, że SQL pochodzi z LLM** (nie hardcoded string w UI).

---

## 4. Ostrzeżenia edukacyjne (forma UI)

Gdy wykryto zagrożenie / wyciek, raport **musi** zawierać trzy bloki (PL + EN w UI):

1. **Co się stało** - konkret (np. model zwrócił `SELECT * FROM deals`; w wyniku `company_id=2`).
2. **Dlaczego to groźne** - naruszenie izolacji tenanta / tajnych kolumn.
3. **Co robić** - nie ufać promptowi; AST + RLS/CLS; Compare z trybem bezpiecznym; audyt.

Ostrzeżenie = lekcja + **evidence** (obce `company_id`, lista `secret_margin_notes`), nie marketingowy baner.

---

## 5. Gdy coś jest źle (troubleshooting edukacyjny)

| Objaw | Znaczenie | Działanie agenta / demo |
|-------|-----------|-------------------------|
| Vulnerable: obce firmy / secrets | PI + brak egzekwowania DB | Pokaż Compare → Secure |
| Secure: nadal wyciek | FP Sentinela lub dziura RLS/CLS | Audyt `init.sql`, AST whitelist, `SET ROLE` / GUC |
| Secure blokuje, ale brak SQL modelu | Demo wygląda na spreparowane | **Zawsze generuj i pokaż SQL z Ollamy przed blokadą egzekucji** |
| BENIGN blokowany | False positive Sentinela | Grounding sygnałów; nie blokuj krótkich PL zapytań biznesowych |
| Ollama / DB down | Środowisko | `task up`, `task doctor`, model lokalny |

---

## 6. WYMAGANE poprawki / idee do wdrożenia

Priorytet: **uczciwość demo względem LLM**.

### 6.1 Pipeline (obowiązkowe)

1. **Zawsze najpierw** wywołaj SQL Generator (Ollama) → zapisz `sql_model`, `model` (nazwa), opcjonalnie surowy JSON odpowiedzi.
2. Dopiero potem Sentinel / AST - mogą blokować **egzekucję**, ale **nie mogą ukrywać** outputu modelu.
3. Vulnerable: wykonaj SQL modelu bez AST; `row_security = off` (demo wycieku).
4. Secure: egzekucja tylko gdy Sentinel+AST przepuszczają; DB z `SET ROLE` + `set_config('app.*')`.
5. Policz **evidence** z realnych wierszy: `companies_in_result`, `foreign_company_ids`, `secrets_exposed` - nie hardcoduj wycieku w UI.

### 6.2 UI (obowiązkowe)

- Sekcja **„Output modelu (Ollama)”** z realnym SQL + nazwą modelu.
- Przy wycieku: czerwone ostrzeżenie + evidence.
- Blok edukacyjny: Co się stało / Dlaczego groźne / Co robić (i18n PL/EN).
- Presety z **polskimi** promptami ataku; tytuły PL/EN.
- UI proste, jedna czcionka, bez sloganów typu „100% FOSS · Defense-in-Depth” w footerze.
- Logo: czytelna **rączka** sięgająca po orb (obecne SVG bywa nieczytelne - poprawić).

### 6.3 Sentinel

- Hybryda: heurystyka leksykalna + LLM + **grounding** sygnałów (bez FP na „Pokaż moje WON”).
- Wsparcie PL: `zignoruj poprzednie`, `traktuj mnie jak admina`, `każdej firmy`, itd.

### 6.4 SQL Generator (demo PI)

- User request jest primary (żeby injekcja była **widoczna** w wygenerowanym SQL).
- Nadal tylko pojedynczy `SELECT`; bez DDL/DML.
- Nie udawać bezpieczeństwa samym system promptem - bezpieczeństwo = AST + DB.

### 6.5 Czego nie robić

- Nie używać płatnych API (OpenAI cloud, itp.).
- Nie hardcodować wynikowych wierszy „wycieku” w froncie.
- Nie kończyć secure flow na Sentinel **bez** wygenerowania SQL modelu.
- Nie psuć `task setup` odtwarzaniem venv, gdy już istnieje (Windows: sprawdzać `-f`, nie `-x`).

---

## 7. Komendy

```bash
task setup
task up
task ui          # http://127.0.0.1:8000
task demo        # CLI porównanie
task test-rls    # RLS/CLS bez LLM
task doctor
```

Smoke (oczekiwane):

- Secure + PI-01 → `sql_model` niepusty (np. `SELECT * FROM deals`), `exec=blocked_by_sentinel` lub AST/DB block.
- Vulnerable + PI-01 → `attack_ok`, `cross_tenant=true` i/lub `secrets_exposed=true`.

---

## 8. Definition of Done

- [ ] W Secure przy PI widać **realny SQL z Ollamy** mimo blokady egzekucji.
- [ ] W Vulnerable widać wyciek z **evidence** wyliczonym z wierszy.
- [ ] UI ma ostrzeżenie edukacyjne (3 punkty) + PL/EN.
- [ ] BENIGN w Secure nie jest fałszywie blokowany.
- [ ] `task demo` / Compare działa lokalnie bez chmury.
- [ ] README krótkie; ten plik (`AGENTS.md`) jest źródłem prawdy dla agentów.

---

## 9. Kontekst rozmowy (skrót decyzji)

- Projekt akademicki, prezentacja / obrona.
- UI ma być eleganckie, mało „AI slop”; Instrument Sans; PL/EN toggle.
- Użytkownik prosił o opis zamysłu **jako instrukcję dla innego agenta** - ten dokument.
- Logo ręki wymaga poprawy czytelności (osobny task wizualny).

---

## 10. Plan na kolejną sesję (TODO)

1. **Podgląd przepływu LLM i bazy na żywo (real-time)**: lepsza widoczność komunikacji z LLM i ścieżki wyciągania danych z bazy (np. strumieniowanie kroków SSE w UI lub integracja z lokalnym narzędziem do śledzenia trace'ów typu Arize Phoenix / Langfuse).
2. **Czarno-białe UI z kolorowymi akcentami**: monochromatyczna baza interfejsu (czerń/biel/szarości), kolory wyłącznie jako akcenty semantyczne (np. czerwień przy ataku/wycieku oraz wariant logo z czerwonym akcentem).
3. **Wyjaśnienie ról użytkowników (`admin`, `sales_rep`, `viewer`)**: czytelny opis w UI, za co odpowiada każda rola, jakie ma uprawnienia i po co istnieje w systemie CRM.
4. **Widoczne 2 firmy (Alpha i Beta)**: wyraźne pokazanie w UI istnienia dwóch tenantów obok siebie.
5. **Lepiej widoczne przykładowe prompty**: rozbudowanie presetów (`PI-01`, `PI-02`, `BENIGN`), żeby od razu było widać pełne treści przykładowych zapytań i ich cel.
6. **Szczegółowa wizualizacja działania AST, Sentinela i RLS/CLS**: pokazanie dokładnie w którym miejscu i w jaki sposób zadziałała każda warstwa (wykryte sygnały Sentinela, przekształcenie/blokada drzewa AST w `sqlglot`, ustawione zmienne sesyjne GUC i polityki RLS/CLS w PostgreSQL).
