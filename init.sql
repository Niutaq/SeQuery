-- 1. TABLES
CREATE TABLE companies (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    company_id INT REFERENCES companies(id),
    role VARCHAR(20) NOT NULL -- 'admin', 'sales_rep', 'viewer'
);

CREATE TABLE deals (
    id SERIAL PRIMARY KEY,
    company_id INT REFERENCES companies(id),
    owner_id INT REFERENCES users(id),
    client_name VARCHAR(100) NOT NULL,
    amount NUMERIC(12, 2) NOT NULL,
    status VARCHAR(30) NOT NULL,
    secret_margin_notes TEXT -- Only for 'admin' role
);

-- 2. SEED DATA
INSERT INTO companies (id, name) VALUES
(1, 'Alpha Tech Sp. z o.o.'),
(2, 'Beta Logistics S.A.');

INSERT INTO users (id, username, company_id, role) VALUES
(101, 'anna_admin_alpha', 1, 'admin'),
(102, 'jan_sales_alpha', 1, 'sales_rep'),
(103, 'ewa_viewer_alpha', 1, 'viewer'),
(201, 'marek_admin_beta', 2, 'admin'),
(202, 'piotr_sales_beta', 2, 'sales_rep');

INSERT INTO deals (company_id, owner_id, client_name, amount, status, secret_margin_notes) VALUES
(1, 102, 'Klient A1 - CyberSoft', 50000.00, 'WON', 'Marża 45%, rabat po znajomości'),
(1, 102, 'Klient A2 - DataFlow', 120000.00, 'NEGOTIATION', 'Skłonny zapłacić do 150k'),
(1, 101, 'Klient A3 - MegaBank (VIP)', 500000.00, 'WON', 'Kontrakt zarządu, marża 60%'),
(2, 202, 'Klient B1 - TransPol', 85000.00, 'WON', 'Marża 12%, trudny klient'),
(2, 201, 'Klient B2 - GlobalCargo (VIP)', 950000.00, 'PROPOSAL', 'Tajna oferta floty');

-- 3. ROLES & COLUMN-LEVEL SECURITY (CLS)
CREATE ROLE ai_role_admin NOLOGIN;
CREATE ROLE ai_role_sales NOLOGIN;
CREATE ROLE ai_role_viewer NOLOGIN;

GRANT ai_role_admin, ai_role_sales, ai_role_viewer TO postgres;
GRANT SELECT ON companies, users TO ai_role_admin, ai_role_sales, ai_role_viewer;
GRANT SELECT ON deals TO ai_role_admin;
GRANT SELECT (id, company_id, owner_id, client_name, amount, status) ON deals TO ai_role_sales, ai_role_viewer;

-- 4. ROW-LEVEL SECURITY (RLS)
ALTER TABLE deals ENABLE ROW LEVEL SECURITY;
ALTER TABLE deals FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON deals
AS RESTRICTIVE
FOR SELECT
USING (company_id = NULLIF(current_setting('app.current_company_id', true), '')::INT);

CREATE POLICY role_visibility_policy ON deals
FOR SELECT
USING (
    current_setting('app.current_role', true) IN ('admin', 'viewer')
    OR owner_id = NULLIF(current_setting('app.current_user_id', true), '')::INT
);
