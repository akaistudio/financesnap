# Varnam Suite — Baseline Interconnects Document
**Last Updated: March 2026 | Reference before every deploy**

---

## 1. App Registry & URLs

| App | Repo | Railway URL | Local Path |
|-----|------|-------------|------------|
| FinanceSnap (Hub) | akaistudio/financesnap | snapsuite.up.railway.app | /home/claude/financesnap |
| ExpenseSnap | akaistudio/expensesnap | expensesnap.up.railway.app | /home/claude/expensesnap |
| InvoiceSnap | akaistudio/invoicesnap | invoicesnap.up.railway.app | /home/claude/invoicesnap |
| ContractSnap | akaistudio/contractsnap | contractsnap-app.up.railway.app | /home/claude/contractsnap |
| PayslipSnap | akaistudio/payslipsnap | payslipsnap.up.railway.app | /home/claude/payslipsnap |
| ProposalSnap | akaistudio/proposalsnap | proposalsnap.up.railway.app | /home/claude/proposalsnap |
| SplitSnap | akaistudio/Splitsnap | splitsnap.up.railway.app | /home/claude/Splitsnap |

**FinanceSnap DEFAULT_URLS (env vars override):**
```
EXPENSESNAP_URL  → https://expensesnap.up.railway.app
INVOICESNAP_URL  → https://invoicesnap.up.railway.app
CONTRACTSNAP_URL → https://contractsnap-app.up.railway.app
PAYSLIPSNAP_URL  → https://payslipsnap.up.railway.app
PROPOSALSNAP_URL → https://proposalsnap.up.railway.app
SPLITSNAP_URL    → https://splitsnap.up.railway.app
```

---

## 2. Authentication System

### OTP Auth (all apps)
- Email → 6-digit OTP via Resend from noreply@usevarnam.com
- 5-minute expiry, on-screen fallback if email fails
- 90-day sessions, permanent Flask sessions
- First user in each app → auto superadmin

### SSO Auto-login (FinanceSnap → other apps)
- Route: `/auto-login?email=<email>&token=<token>`
- Token = `hmac(email, SECRET_KEY)`
- Sets `session['user_id']` and redirects to `/`
- **CRITICAL**: Do NOT call `conn.commit()` on autocommit connections. Always guard with `if not conn.autocommit: conn.commit()`

### Session Keys per App

| App | Session Keys Set at Login |
|-----|--------------------------|
| FinanceSnap | `user_id`, `last_company_id` |
| ExpenseSnap | `user_id`, `user_name`, `user_role`, `company_id`, `company_name` |
| InvoiceSnap | `user_id` only |
| ContractSnap | `user_id` only |
| PayslipSnap | `user_id` only |
| ProposalSnap | `user_id`, `company_name` |
| SplitSnap | `user_id` only |

### Demo Account
- Email: `demo@varnam.app`
- Password: `demo123`
- Company: `Bloom Studio`
- **Resets every 24h** via `demo_reset_at` column on users table
- All apps have `/demo` route — creates user + seeds data + logs in

---

## 3. ID Types — Critical Differences

| App | users.id | companies.id | FK type |
|-----|----------|--------------|---------|
| FinanceSnap | `SERIAL` (integer) | `SERIAL` (integer) | INTEGER |
| ExpenseSnap | `VARCHAR(36)` (UUID string) | `VARCHAR(36)` (UUID string) | VARCHAR(36) |
| InvoiceSnap | `SERIAL` (integer) | n/a (company_name in users) | INTEGER |
| ContractSnap | `SERIAL` (integer) | n/a (company_name in users) | INTEGER |
| PayslipSnap | `SERIAL` (integer) | n/a (company_name in users) | INTEGER |
| ProposalSnap | `SERIAL` (integer) | n/a (company_name in users) | INTEGER |
| SplitSnap | `SERIAL` (integer) | n/a | INTEGER |

**⚠️ ExpenseSnap is the ONLY app using UUID strings for IDs. All others use SERIAL integers.**

---

## 4. Company Model — Critical Differences

### FinanceSnap (hub model)
```
companies: id(SERIAL), name, currency, owner_email
company_users: company_id(→companies.id), user_id(→users.id), role
company_apps: company_id(→companies.id), app_name, app_company_name, app_url
```
- Company is central entity. Users join companies. Apps are linked per company.
- `company_name` in FinanceSnap = `companies.name` (used to match against other apps)

### InvoiceSnap, ContractSnap, PayslipSnap, ProposalSnap (user-owns-company model)
```
users: company_name (TEXT field in users table)
```
- No separate companies table. Each user has ONE company stored directly in `users.company_name`.
- All data filtered by `user_id`.

### ExpenseSnap (separate companies table + UUID model)
```
companies: id(VARCHAR(36)), name, home_currency
users: id(VARCHAR(36)), company_id(→companies.id), role
expenses: company_id(VARCHAR(36) →companies.id)
```
- Users belong to ONE company via `users.company_id`.
- ExpenseSnap demo company ID is hardcoded as `'bloom-demo'`.

### SplitSnap (no company concept)
- Trips belong to users via `trips.created_by → users.id`
- No company model at all.

---

## 5. Cross-App API Calls (FinanceSnap → Others)

### Authentication
FinanceSnap sends user's email as API key:
```python
api_key = selected.get('owner_email', user['email'])
# Header sent: 'X-API-Key': api_key
# Receiving apps: SELECT * FROM users WHERE email=%s (the api_key)
```

### FinanceSnap Fetches from Apps

| App | Endpoint | Company Matching |
|-----|----------|-----------------|
| ExpenseSnap | `GET /api/expenses/external?company_id=<id>` | First calls `/api/companies/external` to find company_id by name match |
| ExpenseSnap | `GET /api/companies/external` | Returns all companies for the user |
| InvoiceSnap | `GET /api/invoices` | Filtered by user (api_key = email) |
| ContractSnap | `GET /api/contracts?company_name=<name>` | Match by company_name param |
| PayslipSnap | `GET /api/payroll?company_name=<name>` | Match by company_name param |

### Company Name Matching Rule
FinanceSnap matches companies across apps by:
```python
ec['name'].lower().strip() == selected['name'].lower().strip()
```
**The company name "Bloom Studio" must be EXACTLY the same across all apps.**

### ExpenseSnap External API Response Format
```json
GET /api/expenses/external
→ { "expenses": [{ "id", "date", "vendor", "category", "total", "amount", "currency" }] }

GET /api/companies/external  
→ { "companies": [{ "id", "name" }] }
```

### InvoiceSnap API Response Format
```json
GET /api/invoices
→ { "invoices": [{ "id", "total", "status", "date", "paid_at", "client_name" }] }
```

### ContractSnap API Response Format
```json
GET /api/contracts
→ { "contracts": [{ "id", "total_value", "status", "title", "client_id" }] }
```

### PayslipSnap API Response Format
```json
GET /api/payroll
→ { "payslips": [{ "id", "gross_earnings", "net_pay", "pf_employer", "esi_employer", "month", "year" }] }
```

---

## 6. Bank Reconciliation (FinanceSnap-local)

### Tables
```sql
bank_statements:
  id(SERIAL), user_id(→users.id), company_name, filename, 
  uploaded_at, row_count, matched_count, currency

bank_transactions:
  id(SERIAL), statement_id(→bank_statements.id CASCADE),
  txn_date, description, amount, txn_type('debit'/'credit'),
  status('unmatched'/'matched'/'ignored'/'new_expense'),
  matched_type, matched_id, expense_snap_id, created_at
```

### Status Values for bank_transactions.status
- `unmatched` — not matched to anything yet
- `matched` — matched to invoice/expense/payroll
- `ignored` — user marked as personal/ignore
- `new_expense` — user confirmed as business expense

### Dashboard reads bank expenses
```python
# In dashboard route — reads new_expense debits as expenses
SELECT bt.* FROM bank_transactions bt
JOIN bank_statements bs ON bt.statement_id = bs.id
WHERE bs.user_id=%s AND bs.company_name=%s
AND bt.txn_type='debit' AND bt.status='new_expense'
AND bt.created_at > NOW() - INTERVAL '365 days'
```

### Reconcile confirm saves locally — no push to ExpenseSnap
- `category` column does NOT exist in bank_transactions (pending addition)
- All bank recon data stays in FinanceSnap DB

---

## 7. Full Schema Reference

### FinanceSnap

**users:** `id`(SERIAL), `email`, `password_hash`, `name`, `currency`(default INR), `is_superadmin`, `created_at`, `demo_reset_at`

**companies:** `id`(SERIAL), `name`, `currency`(default INR), `owner_email`, `created_at`

**company_apps:** `id`(SERIAL), `company_id`(→companies), `app_name`, `app_company_name`, `app_url`, `registered_at`

**company_users:** `id`(SERIAL), `company_id`(→companies), `user_id`(→users), `role`(default owner), UNIQUE(company_id, user_id)

**bank_statements:** `id`(SERIAL), `user_id`(→users), `company_name`, `filename`, `uploaded_at`, `row_count`, `matched_count`, `currency`

**bank_transactions:** `id`(SERIAL), `statement_id`(→bank_statements CASCADE), `txn_date`, `description`, `amount`, `txn_type`, `status`, `matched_type`, `matched_id`, `expense_snap_id`, `created_at`

---

### ExpenseSnap

**companies:** `id`(VARCHAR(36)), `name`, `home_currency`(default USD), `created_at`

**users:** `id`(VARCHAR(36)), `name`, `email`, `password_hash`, `role`(default member), `company_id`(→companies VARCHAR(36)), `created_at`, `demo_reset_at`

**expenses:** `id`(VARCHAR(36)), `date`, `vendor`, `location`, `category`, `subtotal`, `tax`, `tip`, `total`, `total_home`, `total_usd`, `payment_method`, `currency`, `items`, `uploaded_by`, `company_id`(→companies VARCHAR(36)), `receipt_image`, `created_at`

> ⚠️ **No `source` column in expenses table** — do NOT INSERT source
> ⚠️ **No `currency` column in users table** — currency is `companies.home_currency`, join to get it
> ⚠️ **ALTER TABLE in init_db must be committed** — always add `conn.commit()` after ALTER TABLE blocks or columns won't exist at runtime — currency is `companies.home_currency`, join to get it

**invite_codes:** `code`(PK), `company_id`, `role`, `created_by`, `used_by`, `used_at`, `created_at`

**trips:** `id`(VARCHAR(36)), `name`, `currency`, `created_by`(INTEGER→users.id), `settled`, `created_at`

**trip_members:** `id`(SERIAL), `trip_id`(→trips CASCADE), `name`

**trip_expenses:** `id`(VARCHAR(36)), `trip_id`(→trips CASCADE), `description`, `amount`, `amount_base`, `currency`, `paid_by`, `split_among`(TEXT JSON array of member IDs), `date`, `category`

---

### InvoiceSnap

**users:** `id`(SERIAL), `email`, `password_hash`, `company_name`, `company_address`, `company_email`, `company_phone`, `logo_data`, `brand_color`, `currency`(default CAD), `tax_label`(default GST), `tax_rate`(default 5.0), `tax_label_2`, `tax_rate_2`, `invoice_prefix`, `next_invoice_num`, `bank_details`, `payment_terms`, `tax_reg_number`, `tax_reg_label`, `custom_template`, `footer_text`, `is_superadmin`, `created_at`, `demo_reset_at`

**invoices:** `id`(SERIAL), `user_id`(→users), `invoice_number`, `client_name`, `client_email`, `client_address`, `client_phone`, `client_tax_id`, `issue_date`, `due_date`, `status`(unpaid/paid/overdue), `subtotal`, `tax_1_label`, `tax_1_rate`, `tax_1_amount`, `tax_2_label`, `tax_2_rate`, `tax_2_amount`, `discount_percent`, `discount_amount`, `total`, `currency`, `notes`, `source`, `created_at`, `paid_at`, `company_name`

**invoice_items:** `id`(SERIAL), `invoice_id`(→invoices CASCADE), `description`, `quantity`, `unit_price`, `amount`

**clients:** `id`(SERIAL), `user_id`(→users), `name`, `email`, `address`, `phone`, `tax_id`, `created_at`

---

### ContractSnap

**users:** `id`(SERIAL), `email`, `password_hash`, `company_name`, `company_address`, `company_email`, `company_phone`, `logo_data`, `brand_color`, `currency`(default INR), `tax_reg_label`, `tax_reg_number`, `bank_details`, `is_superadmin`, `created_at`, `demo_reset_at`

**clients:** `id`(SERIAL), `user_id`(→users), `name`, `email`, `address`, `phone`, `contact_person`, `tax_id`, `created_at`

**contracts:** `id`(SERIAL), `user_id`(→users), `client_id`(→clients), `contract_number`, `title`, `contract_type`, `source`, `status`(draft/active/signed/completed), `start_date`, `end_date`, `total_value`, `currency`, `payment_terms`, `scope_of_work`, `terms_conditions`, `deliverables`, `po_number`, `po_file_data`, `notes`, `invoiced_amount`, `company_name`, `created_at`, `updated_at`

**contract_milestones:** `id`(SERIAL), `contract_id`(→contracts CASCADE), `title`, `description`, `amount`, `due_date`, `status`(pending/completed), `invoice_id`

---

### PayslipSnap

**users:** `id`(SERIAL), `email`, `password_hash`, `company_name`, `company_address`, `company_email`, `company_phone`, `logo_data`, `brand_color`, `pan_number`, `tan_number`, `pf_reg_number`, `esi_reg_number`, `is_superadmin`, `created_at`, `demo_reset_at`

**employees:** `id`(SERIAL), `user_id`(→users), `emp_code`, `name`, `email`, `phone`, `department`, `designation`, `date_of_joining`, `pan_number`, `uan_number`, `esi_number`, `bank_name`, `bank_account`, `bank_ifsc`, `ctc_annual`, `basic_percent`(default 40), `hra_percent`(default 50), `da_amount`, `special_allowance`, `pf_applicable`, `esi_applicable`, `pt_applicable`, `pt_state`, `tax_regime`, `status`(active/inactive), `payroll_country`(default IN), `created_at`

**payslips:** `id`(SERIAL), `user_id`(→users), `employee_id`(→employees), `month`, `year`, `days_in_month`, `days_worked`, `lop_days`, `basic`, `hra`, `da`, `special_allowance`, `other_earnings`, `other_earnings_desc`, `gross_earnings`, `pf_employee`, `pf_employer`, `esi_employee`, `esi_employer`, `professional_tax`, `tds`, `other_deductions`, `other_deductions_desc`, `total_deductions`, `net_pay`, `status`(draft/final), `company_name`, `generated_at`

---

### ProposalSnap

**users:** `id`(SERIAL), `email`, `password_hash`, `company_name`, `currency`(default USD), `is_superadmin`, `created_at`, `demo_reset_at`

**proposals:** `id`(SERIAL), `user_id`(→users CASCADE), `company_name`, `client_name`, `presentation_type`, `title`, `key_points`, `num_slides`, `status`, `download_url`, `created_at`

**usage_log:** `id`(SERIAL), `user_id`(→users), `action`, `title`, `slides`, `created_at`

---

### SplitSnap

**users:** `id`(SERIAL), `email`, `password_hash`, `name`, `currency`(default EUR), `is_superadmin`, `created_at`, `demo_reset_at`

**trips:** `id`(VARCHAR(36)), `name`, `currency`, `created_by`(INTEGER→users.id), `settled`, `created_at`

**trip_members:** `id`(SERIAL), `trip_id`(→trips CASCADE), `name`

**trip_expenses:** `id`(VARCHAR(36)), `trip_id`(→trips CASCADE), `description`, `amount`, `amount_base`, `currency`, `paid_by`(TEXT — member name), `split_among`(TEXT — comma-separated member IDs), `date`, `category`

**settled_payments:** `id`(SERIAL), `trip_id`(→trips CASCADE), `from_member`(TEXT), `to_member`(TEXT), `amount`, `settled_at`

---

## 8. Pre-Deploy Checklist

**Run these exact commands before every `git push`:**

```bash
# 1. Syntax check
python3 -m py_compile app.py && echo "OK syntax"

# 2. No undeclared JS globals (these are never declared anywhere — must return nothing)
grep -n "currentCompanyId\|currentTripId\|currentUserId" app.py

# 3. No source column in ExpenseSnap expenses INSERT (must return nothing)
grep -n "INSERT INTO expenses" app.py | grep "source"

# 4. All INSERT columns — compare against Section 7 schema
grep -n "INSERT INTO" app.py

# 5. conn.commit() present after every write
grep -n "conn.commit\|autocommit" app.py

# 6. Session keys used match Section 2
grep -n "session\['" app.py
```

**Checklist before pushing:**
- [ ] `python3 -m py_compile app.py` passes
- [ ] Check 2: no undeclared JS globals in fetch() bodies
- [ ] Check 3: no source column in ExpenseSnap expenses INSERT
- [ ] Check 4: every INSERT column exists in Section 7 schema
- [ ] Check 5: conn.commit() after every write, guarded with `if not conn.autocommit`
- [ ] Check 6: session keys match Section 2
- [ ] ExpenseSnap JS: use `selectedCompany || myCompanyId` not `currentCompanyId`
- [ ] `get_db()` must use `cursor_factory=psycopg2.extras.RealDictCursor` — without it, `row['id']` crashes with *tuple indices must be integers*
- [ ] Grep for any `conn.cursor()` calls NOT passing `cursor_factory` after a plain `get_db()`: `grep -n "conn.cursor()" app.py`
- [ ] New route function name doesn't clash: `grep -n "def <funcname>" app.py`
- [ ] Demo seed INSERT columns match schema
- [ ] Cross-app company name match uses `.lower().strip()` on both sides

## 9. Known Gotchas

1. **ExpenseSnap `source` column doesn't exist** — never INSERT it
2. **ExpenseSnap `currentCompanyId`** — JS variable doesn't exist, use `myCompanyId` instead
3. **autocommit guard** — `if not conn.autocommit: conn.commit()` always
4. **SSO auto-login** — never call `conn.commit()` — uses autocommit connection
5. **ExpenseSnap company lookup** — match by `LOWER(name)` only, no `created_by` column in companies
6. **FinanceSnap API key** = user's email sent as `X-API-Key` header
7. **Railway cold starts** — free tier sleeps after inactivity, causes 10-20s delays on cross-app calls
8. **company_name field** — InvoiceSnap/ContractSnap/PayslipSnap store it in `invoices.company_name` / `contracts.company_name` / `payslips.company_name` (not a companies table)
9. **SplitSnap trip_expenses.paid_by** — stores member NAME (TEXT), not member ID
10. **SplitSnap trip_expenses.split_among** — stores comma-separated member IDs (not names)
11. **InvoiceSnap default currency** — CAD (not INR) — set explicitly for Indian clients

---

## 10. FinanceSnap Dashboard Data Flow

```
User selects company (companies table)
  ↓
api_key = company.owner_email
  ↓
Parallel fetches:
  InvoiceSnap  → /api/invoices             (filter by user email = api_key)
  ContractSnap → /api/contracts            (filter by user email = api_key)
  PayslipSnap  → /api/payroll              (filter by user email = api_key)
  ExpenseSnap  → /api/companies/external   (find company_id by name match)
               → /api/expenses/external?company_id=<id>
  FinanceSnap  → bank_transactions table   (local, status='new_expense', txn_type='debit')
  ↓
Aggregated metrics:
  revenue     = sum(invoices where status='paid', total)
  expenses    = sum(expenses.total) + sum(bank_transactions.amount where new_expense)
  payroll     = sum(payslips.gross_earnings + pf_employer + esi_employer)
  profit      = revenue - expenses - payroll
```
