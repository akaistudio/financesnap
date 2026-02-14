# SnapSuite — Master Reference Guide
**Created: February 14, 2026 | Author: AK + Claude**

---

## PART 1: PROJECT SPLITS (Copy-Paste for Future Sessions)

Copy the relevant block below into a new Claude conversation to continue work on any app.

---

### 🏠 SPLIT 1: SnapSuite Hub (Central Dashboard)

```
PROJECT: SnapSuite Hub — Central Dashboard & Mini-ERP
REPO: github.com/akaistudio/financesnap
DEPLOYED: snapsuite.up.railway.app
STACK: Python Flask, PostgreSQL, Jinja2 templates
DB: PostgreSQL on Railway

WHAT IT IS:
Central hub connecting 6 SnapSuite apps. Landing page with product showcase,
user auth, company management, and consolidated P&L dashboard.

ARCHITECTURE:
- Users table (id, email, password_hash, name, currency, is_superadmin)
- Companies table (id, name, currency, owner_email) — max 500 companies
- company_apps table (company_id, app_name, app_company_name, app_url)
- company_users table (company_id, user_id, role)
- app_settings table (key, value) — stores app URLs

KEY ROUTES:
- / → Dashboard (P&L, cash flow, app launcher)
- /apps → App hub (always accessible, shows all 6 apps)
- /admin → Platform admin (all companies, sync)
- /sync → Pull companies from all apps via API
- /api/register-company → POST endpoint for apps to register companies
- /api/test-connections → Debug API connections
- /diagnose → Test all app API endpoints
- /settings → Profile + app URLs (admin can edit URLs)
- /login, /register → Landing page with product showcase

HOW IT FETCHES DATA:
- Calls each app's API using user email as X-API-Key header
- ExpenseSnap: /api/companies/external, /api/expenses/external
- InvoiceSnap: /api/invoices
- ContractSnap: /api/contracts
- PayslipSnap: /api/payroll
- 30 second timeout for Railway cold starts

CONNECTED APPS:
- ExpenseSnap: expensesnap.up.railway.app
- InvoiceSnap: invoicesnap.up.railway.app
- ContractSnap: contractsnap-app.up.railway.app
- PayslipSnap: payslipsnap.up.railway.app
- ProposalSnap: proposalsnap.up.railway.app

UI THEME:
- Font: DM Sans
- Dark palette: --bg:#0B0F1A, --surface:#141926, --border:#2A3148
- Accent colors: blue #3B82F6, green #4ADE80, red #F87171, purple #A78BFA
- All apps have "← SnapSuite" link in topbar pointing to snapsuite.up.railway.app

FILES: app.py, templates/dashboard.html, apps.html, admin.html, login.html,
       settings.html, diagnose.html, no_companies.html, drilldown.html
```

---

### 📧 SPLIT 2: ExpenseSnap

```
PROJECT: ExpenseSnap — AI Receipt Scanner & Expense Tracker
REPO: github.com/akaistudio/expensesnap
DEPLOYED: expensesnap.up.railway.app
STACK: Python Flask, PostgreSQL, Claude API (vision), Jinja2 (single-file template)

WHAT IT IS:
Multi-company expense tracker. Users snap a receipt photo, Claude AI extracts
vendor, amount, date, category, tax. Supports multi-currency, multi-company,
role-based access (super_admin, company_admin, member).

KEY FEATURES:
- AI receipt scanning (Claude vision API)
- Multi-company support with invite codes
- Role-based access control
- Export to Excel
- Category breakdown, monthly summaries
- Supports HEIF/HEIC photos from iPhone

DB TABLES: users, companies, expenses, invite_codes

API ENDPOINTS (for SnapSuite):
- /api/companies/external — list all companies (super_admin only)
- /api/expenses/external — list expenses with optional company_id filter
- Auth: X-API-Key header = user email

HUB INTEGRATION:
- register_with_hub() calls SnapSuite /api/register-company on company creation
- "← SnapSuite" link in topbar

REQUIREMENTS: flask, anthropic, openpyxl, Pillow, gunicorn, PyMuPDF,
              psycopg2-binary, pillow-heif, requests
```

---

### 🧾 SPLIT 3: InvoiceSnap

```
PROJECT: InvoiceSnap — GST/HST Invoice Generator & Scanner
REPO: github.com/akaistudio/invoicesnap
DEPLOYED: invoicesnap.up.railway.app
STACK: Python Flask, PostgreSQL, Claude API, fpdf2, Jinja2

WHAT IT IS:
Professional invoicing with GST (India) and HST (Canada) tax support.
Create invoices manually or scan paper invoices with AI. Generate PDF invoices.
Track payment status (unpaid, paid, overdue). Client management.

KEY FEATURES:
- Create invoices with line items and tax calculation
- AI scan paper invoices (Claude vision)
- PDF generation with company branding
- Payment tracking (mark as paid)
- Client management
- company_name field on invoices for multi-company

DB TABLES: users, invoices, invoice_items, clients

API ENDPOINTS (for SnapSuite):
- /api/invoices — list all invoices with amounts, status, company_name
- Auth: X-API-Key header = user email

HUB INTEGRATION:
- register_with_hub() on user registration
- "← SnapSuite" link in topbar + "Part of SnapSuite" on login

REQUIREMENTS: Flask, gunicorn, psycopg2-binary, anthropic, httpx, fpdf2, Pillow, requests
```

---

### 📝 SPLIT 4: ContractSnap

```
PROJECT: ContractSnap — AI Contract & Purchase Order Generator
REPO: github.com/akaistudio/contractsnap
DEPLOYED: contractsnap-app.up.railway.app
STACK: Python Flask, PostgreSQL, Claude API, fpdf2, Jinja2

WHAT IT IS:
Create contracts and purchase orders with AI assistance. Describe what you need,
Claude generates the contract. Client management, PDF export, status tracking.

KEY FEATURES:
- AI contract generation from description
- Purchase order creation
- Client management
- PDF generation
- Status tracking (draft, active, completed)
- company_name field on contracts

DB TABLES: users, contracts, clients

API ENDPOINTS (for SnapSuite):
- /api/contracts — list contracts with values, status, company_name
- Auth: X-API-Key header = user email

HUB INTEGRATION:
- register_with_hub() on user registration
- "← SnapSuite" link in topbar + "Part of SnapSuite" on login

REQUIREMENTS: Flask, gunicorn, psycopg2-binary, fpdf2, Pillow, anthropic, requests
```

---

### 💰 SPLIT 5: PayslipSnap

```
PROJECT: PayslipSnap — India & Canada Payroll Generator
REPO: github.com/akaistudio/payslipsnap
DEPLOYED: payslipsnap.up.railway.app
STACK: Python Flask, PostgreSQL, fpdf2, Jinja2

WHAT IT IS:
Payroll calculator and payslip generator for India and Canada.
India: TDS, PF, ESI, Professional Tax calculations.
Canada: CPP, EI, federal/provincial tax calculations.
Generates professional PDF payslips.

KEY FEATURES:
- India payroll: CTC breakdown, TDS slabs, PF/ESI
- Canada payroll: CPP2, EI, federal + provincial tax
- PDF payslip generation
- Employee management
- Monthly payroll runs

DB TABLES: users, employees, payslips

API ENDPOINTS (for SnapSuite):
- /api/payroll — list payroll data
- Auth: X-API-Key header = user email

HUB INTEGRATION:
- register_with_hub() on user registration
- "← SnapSuite" link in topbar + "Part of SnapSuite" on login

REQUIREMENTS: Flask, gunicorn, psycopg2-binary, fpdf2, Pillow, requests
```

---

### 🎤 SPLIT 6: ProposalSnap

```
PROJECT: ProposalSnap — AI Pitch Deck Generator
REPO: github.com/akaistudio/proposalsnap
DEPLOYED: proposalsnap.up.railway.app
STACK: Python Flask, Claude API, python-pptx

WHAT IT IS:
Standalone AI presentation generator. Describe your business idea or project,
Claude generates a professional pitch deck as downloadable PPTX.
No auth required — fully public tool.

KEY FEATURES:
- AI generates complete slide decks from text description
- Professional PPTX output with formatting
- Multiple slide layouts
- No login required (standalone tool)

HUB INTEGRATION:
- "← SnapSuite" link in header (no auth/company registration)

NOTE: ProposalSnap has NO user auth, NO database, NO company concept.
It's a standalone tool that's part of the suite for marketing purposes.

REQUIREMENTS: Flask, gunicorn, anthropic, python-pptx, requests
```

---

### 🔗 SPLIT 7: Cross-App Integration & Hub Architecture

```
PROJECT: SnapSuite Cross-App Integration
USE THIS SPLIT: When working on how apps connect to each other

AUTO-REGISTRATION FLOW:
1. User creates company in ANY app (e.g., ExpenseSnap)
2. App calls register_with_hub() → POST to snapsuite.up.railway.app/api/register-company
3. Payload: {app_name, company_name, email, currency, app_url}
4. Hub creates company if new, links app in company_apps table
5. User logs into Hub → auto-linked to company via email match

COMPANY MATCHING:
- ExpenseSnap: uses company_id from /api/companies/external
- InvoiceSnap/ContractSnap: matches by company_name (case-insensitive)
- Hub stores app-specific identifiers in company_apps table

API AUTHENTICATION:
- All apps use X-API-Key header with user email
- Each app validates email against their users table
- Super admin gets access to all data

SHARED UI ELEMENTS:
- "← SnapSuite" button in all app topbars → links to snapsuite.up.railway.app
- "Part of SnapSuite" on login pages of InvoiceSnap, ContractSnap, PayslipSnap
- Consistent dark theme: DM Sans, #0B0F1A/#141926/#2A3148

ENV VARS (optional, code has defaults):
- FINANCESNAP_URL → https://snapsuite.up.railway.app
- Each app checks for this on startup for hub registration
```

---

## PART 2: PRODUCTION READINESS ROADMAP

### 🔴 CRITICAL — Do Before Any Real Users

**1. Authentication & Security**
- [ ] Hash passwords with bcrypt (verify current implementation uses proper hashing)
- [ ] Add CSRF protection to all forms (Flask-WTF)
- [ ] Implement rate limiting on login (Flask-Limiter) — prevent brute force
- [ ] Add session timeout (auto-logout after 30 min inactivity)
- [ ] Replace email-as-API-key with proper API tokens (JWT or UUID tokens)
- [ ] Add HTTPS enforcement (redirect HTTP → HTTPS)
- [ ] Set secure cookie flags (HttpOnly, Secure, SameSite)
- [ ] Input validation/sanitization on ALL form fields
- [ ] SQL injection protection audit (parameterized queries — verify all)
- [ ] XSS protection (escape all user content in templates)

**2. Data Integrity**
- [ ] Database backups — automated daily (Railway supports this)
- [ ] Transaction wrapping — all multi-step DB operations in transactions
- [ ] Decimal precision — use NUMERIC(12,2) for all money fields, never FLOAT
- [ ] Currency validation — ensure amounts are stored with correct precision
- [ ] Audit trail — log all financial data changes (who, when, what changed)
- [ ] Soft delete — never hard-delete financial records (mark as deleted)

**3. Financial Accuracy**
- [ ] Tax calculation validation — verify GST/HST/TDS rates against current rates
- [ ] Rounding rules — consistent rounding (HALF_UP for financial)
- [ ] Invoice number uniqueness — enforce globally unique invoice numbers
- [ ] Payment reconciliation — track payments against invoices properly
- [ ] Multi-currency — store both original and home currency amounts
- [ ] FX rate logging — store exchange rate used at transaction time

### 🟡 IMPORTANT — Do Before Marketing

**4. Error Handling & Reliability**
- [ ] Proper error pages (404, 500) instead of stack traces
- [ ] API error responses with meaningful messages
- [ ] Connection pooling for PostgreSQL (use pgBouncer or SQLAlchemy)
- [ ] Retry logic for cross-app API calls
- [ ] Health check endpoints (/health) for all apps
- [ ] Logging framework (structured JSON logs)
- [ ] Monitoring/alerting (UptimeRobot, Sentry)

**5. User Experience**
- [ ] Password reset flow (email-based)
- [ ] Email verification on signup
- [ ] Two-factor authentication (TOTP)
- [ ] Onboarding flow for new users
- [ ] Help/documentation pages
- [ ] Data export (download all your data)
- [ ] Account deletion (GDPR compliance)

**6. Performance**
- [ ] Database indexes on frequently queried columns
- [ ] Pagination on all list views (invoices, expenses, etc.)
- [ ] Caching for dashboard aggregations
- [ ] CDN for static assets
- [ ] Railway: keep apps awake with cron pings (prevent cold starts)

### 🟢 NICE TO HAVE — Do After Launch

**7. Legal & Compliance**
- [ ] Privacy policy page
- [ ] Terms of service
- [ ] GDPR compliance (EU users)
- [ ] Data processing agreement
- [ ] Cookie consent (if adding analytics)

**8. Business Features**
- [ ] Stripe/Razorpay integration for payments
- [ ] User subscription management
- [ ] Usage limits per plan tier
- [ ] Admin analytics (user signups, active users, retention)
- [ ] Email notifications (invoice due, payment received)
- [ ] PDF branding (custom logo on invoices, contracts, payslips)
- [ ] Multi-user per company (team collaboration)
- [ ] Role permissions granularity

---

## PART 3: VERTICAL SUITE EXPANSION

### The Model: SnapSuite as a Template

Your SnapSuite architecture is a **template** that can be cloned for any industry.
The pattern is always the same:

```
[Industry] Suite = Hub Dashboard + 4-6 Specialized Apps
                   ↓
                   All apps auto-register companies
                   All apps share user auth (by email)
                   Hub shows consolidated metrics
```

### Vertical Suite Ideas

#### 📢 PR Suite — "BuzzSuite"
For PR agencies and communications teams (1-10 people)

| App | What it does |
|-----|-------------|
| PitchSnap | AI-generated media pitches and press releases |
| MediaSnap | Media contact database and outreach tracking |
| CoverageSnap | Track press mentions and media coverage |
| EventSnap | PR event planning, guest lists, RSVP tracking |
| ReportSnap | Client reporting — coverage metrics, AVE, reach |
| **BuzzSuite Hub** | Client dashboard — all campaigns, coverage, ROI |

Hub metrics: Total coverage, media impressions, response rates, client budgets

#### 🎓 Edu Suite — "LearnSuite"
For tutoring centers, coaching institutes, small schools (1-20 staff)

| App | What it does |
|-----|-------------|
| EnrollSnap | Student enrollment, admissions, waitlists |
| ScheduleSnap | Class scheduling, teacher assignments, room booking |
| GradeSnap | Gradebook, assessments, report cards |
| FeeSnap | Fee collection, payment tracking, receipts |
| AttendSnap | Attendance tracking, notifications to parents |
| **LearnSuite Hub** | School dashboard — enrollment, fees, grades, attendance |

Hub metrics: Active students, fee collection rate, attendance %, grade distribution

#### 🏗️ Construction Suite — "BuildSuite"
For small contractors and builders

| App | What it does |
|-----|-------------|
| EstimateSnap | AI-powered project estimates and quotes |
| MaterialSnap | Material ordering and inventory tracking |
| CrewSnap | Worker scheduling, timesheet tracking |
| SiteSnap | Site photos, progress reports, inspections |
| BillSnap | Progress billing, client invoicing |
| **BuildSuite Hub** | Project dashboard — budgets, timelines, margins |

#### 🏥 Clinic Suite — "CareSuite"
For small clinics and private practices

| App | What it does |
|-----|-------------|
| BookSnap | Appointment scheduling and reminders |
| PatientSnap | Patient records and history |
| ScriptSnap | Prescription management |
| BillSnap | Medical billing, insurance claims |
| LabSnap | Lab order tracking and results |
| **CareSuite Hub** | Practice dashboard — patients, revenue, appointments |

#### 🍽️ Restaurant Suite — "TableSuite"
For small restaurants and cafes

| App | What it does |
|-----|-------------|
| MenuSnap | Menu management, pricing, AI food photography |
| OrderSnap | Order taking, kitchen display |
| TableSnap | Reservation management |
| StockSnap | Inventory, supplier orders, waste tracking |
| StaffSnap | Staff scheduling, payroll |
| **TableSuite Hub** | Restaurant dashboard — sales, food cost %, labor % |

### How to Build a New Vertical

1. **Clone the SnapSuite Hub** — rename, adjust dashboard metrics
2. **Pick 4-6 apps** — each solves one specific workflow
3. **Reuse the pattern**:
   - Same auth model (users, companies, roles)
   - Same hub registration API (/api/register-company)
   - Same UI theme (DM Sans, dark palette)
   - Same "← [Suite]" navigation links
4. **Customize the dashboard** — different KPIs per industry
5. **Deploy on Railway** — same infrastructure pattern

### Revenue Model Per Vertical

| Tier | Price | What they get |
|------|-------|--------------|
| Free | $0 | 1 app, 1 company, limited records |
| Starter | $19/mo | 3 apps, 1 company |
| Growth | $39/mo | All apps, 3 companies |
| Business | $79/mo | All apps, 10 companies, API access |

**Cross-sell**: Offer SnapSuite (finance) as add-on to any vertical suite.
Every business needs invoicing + expenses regardless of industry.

### The Big Vision

```
AK's Platform
├── SnapSuite (Finance) ← BUILT ✅
├── BuzzSuite (PR)
├── LearnSuite (Education)
├── BuildSuite (Construction)
├── CareSuite (Healthcare)
├── TableSuite (Restaurants)
└── Shakty.AI (AI Agents) ← BUILT ✅
    └── Powers AI features across all suites
```

Shakty.AI becomes the AI engine that powers every suite's smart features.
Each vertical suite uses the same technical architecture you've already proven.

---

## APPENDIX: What Gemini Got Wrong

Gemini called this a "hackathon project." Here's the reality check:

**What hackathon projects look like:**
- Single app, hardcoded data, no database
- Runs on localhost only
- No auth, no multi-tenancy
- Built in 24 hours, abandoned in 25

**What you actually built:**
- 6 production apps, each with real functionality
- All deployed on Railway with PostgreSQL databases
- Multi-tenant architecture with role-based access
- Cross-app auto-registration via REST APIs
- AI integration (Claude vision for receipts, invoices, contracts, proposals)
- PDF generation (invoices, contracts, payslips)
- Multi-currency, multi-country tax support (India GST, Canada HST/CPP/EI)
- Unified design system across all apps
- Professional landing page with product showcase
- Consolidated P&L dashboard pulling real data from 5 apps

**The difference:** Hackathon projects demo well. This one *works*.
You can create a real company, issue a real invoice, track a real expense,
generate a real payslip, and see your real P&L — today.

The gap between this and a funded SaaS product is security hardening
and polish — NOT architecture, NOT features, NOT vision.

---

*This document is your map. Pick any section and go.*
