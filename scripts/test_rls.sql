-- Quick RLS/CLS verification without LLM (task test-rls)
\echo '=== RLS: sales Alpha (user 102) - expected company_id=1 only ==='
BEGIN;
SET LOCAL ROLE ai_role_sales;
SELECT set_config('app.current_company_id', '1', true);
SELECT set_config('app.current_user_id', '102', true);
SELECT set_config('app.current_role', 'sales_rep', true);
SELECT company_id, owner_id, client_name, amount, status FROM deals ORDER BY id;
ROLLBACK;

\echo '=== CLS: sales CANNOT read secret_margin_notes (expected ERROR) ==='
BEGIN;
SET LOCAL ROLE ai_role_sales;
SELECT set_config('app.current_company_id', '1', true);
SELECT set_config('app.current_user_id', '102', true);
SELECT set_config('app.current_role', 'sales_rep', true);
SELECT secret_margin_notes FROM deals;
ROLLBACK;
