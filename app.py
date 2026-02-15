"""
SnapSuite – Central Hub FinanceSnap – The SnapSuite Hub Mini-ERP
Central dashboard & mini-ERP for 1-5 person companies.
Auto-receives company registrations from all SnapSuite apps.
"""
import os, hashlib, json, requests
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, redirect, url_for, session, render_template, flash
import psycopg2, psycopg2.extras

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'snapsuite-hub-2026')

MAX_COMPANIES = 500

def get_db():
    conn = psycopg2.connect(os.environ['DATABASE_URL'], cursor_factory=psycopg2.extras.RealDictCursor)
    conn.autocommit = True
    return conn

def init_db():
    conn = get_db(); cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        name TEXT DEFAULT '', currency TEXT DEFAULT 'INR',
        is_superadmin BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW()
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS companies (
        id SERIAL PRIMARY KEY, name TEXT NOT NULL, currency TEXT DEFAULT 'INR',
        owner_email TEXT DEFAULT '', created_at TIMESTAMP DEFAULT NOW()
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS company_apps (
        id SERIAL PRIMARY KEY,
        company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
        app_name TEXT NOT NULL, app_company_name TEXT DEFAULT '',
        app_url TEXT DEFAULT '', registered_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(company_id, app_name)
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS company_users (
        id SERIAL PRIMARY KEY,
        company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        role TEXT DEFAULT 'owner', UNIQUE(company_id, user_id)
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY, value TEXT DEFAULT ''
    )''')
    for m in [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT DEFAULT ''",
        "ALTER TABLE companies ADD COLUMN IF NOT EXISTS owner_email TEXT DEFAULT ''",
        "UPDATE users SET is_superadmin = TRUE WHERE id = (SELECT MIN(id) FROM users)",
    ]:
        try: cur.execute(m)
        except: pass
    conn.close()

init_db()

# ── Helpers ─────────────────────────────────────────────────────
def hash_pw(p): return hashlib.sha256(p.encode()).hexdigest()
def cs(c): return {'INR':'₹','USD':'$','EUR':'€','GBP':'£','CAD':'C$'}.get(c, c+' ')

def login_required(f):
    @wraps(f)
    def decorated(*a, **kw):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*a, **kw)
    return decorated

def get_user():
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id=%s', (session['user_id'],))
    u = cur.fetchone(); conn.close(); return u

def get_user_companies(user):
    conn = get_db(); cur = conn.cursor()
    if user['is_superadmin']:
        cur.execute('SELECT * FROM companies ORDER BY name')
    else:
        cur.execute('''SELECT c.* FROM companies c
                      JOIN company_users cu ON c.id=cu.company_id
                      WHERE cu.user_id=%s ORDER BY c.name''', (user['id'],))
    r = cur.fetchall(); conn.close(); return r

def get_company_apps(cid):
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM company_apps WHERE company_id=%s', (cid,))
    r = cur.fetchall(); conn.close()
    return {a['app_name']: a for a in r}

DEFAULT_URLS = {
    'ExpenseSnap': os.environ.get('EXPENSESNAP_URL', 'https://expensesnap.up.railway.app'),
    'InvoiceSnap': os.environ.get('INVOICESNAP_URL', 'https://invoicesnap.up.railway.app'),
    'ContractSnap': os.environ.get('CONTRACTSNAP_URL', 'https://contractsnap-app.up.railway.app'),
    'PayslipSnap': os.environ.get('PAYSLIPSNAP_URL', 'https://payslipsnap.up.railway.app'),
    'ProposalSnap': os.environ.get('PROPOSALSNAP_URL', 'https://proposalsnap.up.railway.app'),
}

def get_app_urls():
    urls = dict(DEFAULT_URLS)
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT key, value FROM app_settings WHERE key LIKE 'url_%'")
        for row in cur.fetchall():
            app_name = row['key'].replace('url_', '')
            if row['value'].strip():
                urls[app_name] = row['value'].strip()
        conn.close()
    except: pass
    return urls

# For backward compat
APP_URLS = DEFAULT_URLS

@app.before_request
def load_app_urls():
    global APP_URLS
    APP_URLS = get_app_urls()

def fetch_api(base_url, endpoint, api_key):
    if not base_url: return None
    try:
        r = requests.get(base_url.rstrip('/') + endpoint,
                        headers={'X-API-Key': api_key}, timeout=30)
        if r.status_code == 200: return r.json()
    except: pass
    return None

@app.route('/api/test-connections')
def test_connections():
    """Public endpoint to debug API connections."""
    results = {}
    # Try common emails
    test_emails = set()
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute('SELECT email FROM users ORDER BY id LIMIT 5')
        for u in cur.fetchall(): test_emails.add(u['email'])
        conn.close()
    except: pass

    if not test_emails:
        test_emails = {'test@example.com'}

    for email in test_emails:
        results[email] = {}
        tests = {
            'ExpenseSnap /api/companies/external': (APP_URLS['ExpenseSnap'], '/api/companies/external'),
            'ExpenseSnap /api/expenses/external': (APP_URLS['ExpenseSnap'], '/api/expenses/external'),
            'InvoiceSnap /api/invoices': (APP_URLS['InvoiceSnap'], '/api/invoices'),
            'ContractSnap /api/contracts': (APP_URLS['ContractSnap'], '/api/contracts'),
            'PayslipSnap /api/payroll': (APP_URLS['PayslipSnap'], '/api/payroll'),
        }
        for label, (base, ep) in tests.items():
            try:
                r = requests.get(base.rstrip('/') + ep,
                    headers={'X-API-Key': email}, timeout=30)
                results[email][label] = {
                    'status': r.status_code,
                    'body': r.text[:200]
                }
            except Exception as e:
                results[email][label] = {'status': 'error', 'body': str(e)[:200]}

    return jsonify({
        'app_urls': APP_URLS,
        'test_emails': list(test_emails),
        'results': results
    })

# ── Central API ─────────────────────────────────────────────────
@app.route('/api/register-company', methods=['POST'])
def api_register_company():
    """Called by any SnapSuite app when a user creates a company.
    {app_name, company_name, email, currency, app_url}"""
    data = request.json or {}
    app_name = data.get('app_name', '').strip()
    company_name = data.get('company_name', '').strip()
    email = data.get('email', '').strip().lower()
    currency = data.get('currency', 'INR').upper()
    app_url = data.get('app_url', '').strip()

    if not company_name or not app_name:
        return jsonify({'error': 'company_name and app_name required'}), 400

    conn = get_db(); cur = conn.cursor()

    # Company limit
    cur.execute('SELECT COUNT(*) as cnt FROM companies')
    if cur.fetchone()['cnt'] >= MAX_COMPANIES:
        conn.close()
        return jsonify({'error': f'Max {MAX_COMPANIES} companies reached'}), 400

    # Find or create company
    cur.execute('SELECT * FROM companies WHERE LOWER(name)=LOWER(%s)', (company_name,))
    company = cur.fetchone()
    if not company:
        cur.execute('INSERT INTO companies (name,currency,owner_email) VALUES (%s,%s,%s) RETURNING *',
                   (company_name, currency, email))
        company = cur.fetchone()

    # Register app link
    cur.execute('''INSERT INTO company_apps (company_id,app_name,app_company_name,app_url)
                  VALUES (%s,%s,%s,%s) ON CONFLICT (company_id,app_name)
                  DO UPDATE SET app_company_name=EXCLUDED.app_company_name, app_url=EXCLUDED.app_url''',
               (company['id'], app_name, company_name, app_url))

    # Link user if exists
    if email:
        cur.execute('SELECT id FROM users WHERE email=%s', (email,))
        u = cur.fetchone()
        if u:
            cur.execute('''INSERT INTO company_users (company_id,user_id,role)
                          VALUES (%s,%s,'owner') ON CONFLICT DO NOTHING''', (company['id'], u['id']))
    conn.close()
    return jsonify({'success': True, 'company_id': company['id'], 'company_name': company['name']})

@app.route('/api/companies')
def api_list_companies():
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT id,name,currency FROM companies ORDER BY name')
    r = cur.fetchall(); conn.close()
    return jsonify({'companies': r})

# ── Auth ────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        conn = get_db(); cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE email=%s AND password_hash=%s', (email, hash_pw(password)))
        user = cur.fetchone()
        if not user: conn.close(); flash('Invalid email or password', 'error'); return render_template('login.html')
        session['user_id'] = user['id']
        # Auto-link companies by email
        cur.execute('SELECT id FROM companies WHERE owner_email=%s', (email,))
        for c in cur.fetchall():
            cur.execute('''INSERT INTO company_users (company_id,user_id,role)
                          VALUES (%s,%s,'owner') ON CONFLICT DO NOTHING''', (c['id'], user['id']))
        conn.close()
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        name = request.form.get('name', '')
        currency = request.form.get('currency', 'INR')
        if len(password) < 6:
            flash('Password min 6 characters', 'error')
            return render_template('login.html', show_register=True)
        conn = get_db(); cur = conn.cursor()
        try:
            cur.execute('SELECT COUNT(*) as cnt FROM users')
            is_first = cur.fetchone()['cnt'] == 0
            cur.execute('''INSERT INTO users (email,password_hash,name,currency,is_superadmin)
                          VALUES (%s,%s,%s,%s,%s) RETURNING id''',
                       (email, hash_pw(password), name, currency, is_first))
            uid = cur.fetchone()['id']; session['user_id'] = uid
            # Auto-link
            cur.execute('SELECT id FROM companies WHERE owner_email=%s', (email,))
            for c in cur.fetchall():
                cur.execute('''INSERT INTO company_users (company_id,user_id,role)
                              VALUES (%s,%s,'owner') ON CONFLICT DO NOTHING''', (c['id'], uid))
            conn.close()
            return redirect(url_for('dashboard'))
        except psycopg2.IntegrityError:
            conn.close(); flash('Email already registered', 'error')
    return render_template('login.html', show_register=True)

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

# ── App Hub (always accessible) ─────────────────────────────────
@app.route('/apps')
@login_required
def apps_hub():
    user = get_user()
    companies = get_user_companies(user)
    return render_template('apps.html', user=user, app_urls=APP_URLS, companies=companies)

# ── Dashboard ───────────────────────────────────────────────────
@app.route('/')
@login_required
def dashboard():
    user = get_user()
    companies = get_user_companies(user)
    if not companies:
        return redirect(url_for('apps_hub'))

    sel_id = request.args.get('company', '')
    selected = None
    for c in companies:
        if str(c['id']) == sel_id: selected = c; break
    if not selected: selected = companies[0]

    curr = cs(selected.get('currency', 'INR'))
    apps = get_company_apps(selected['id'])
    api_key = selected.get('owner_email', user['email'])

    invoices=[]; contracts=[]; expenses=[]; payslips=[]

    if 'InvoiceSnap' in apps:
        url = apps['InvoiceSnap']['app_url'] or APP_URLS['InvoiceSnap']
        r = fetch_api(url, '/api/invoices', api_key)
        if r: invoices = r.get('invoices', [])

    if 'ContractSnap' in apps:
        url = apps['ContractSnap']['app_url'] or APP_URLS['ContractSnap']
        r = fetch_api(url, '/api/contracts', api_key)
        if r: contracts = r.get('contracts', [])

    if 'ExpenseSnap' in apps:
        url = apps['ExpenseSnap']['app_url'] or APP_URLS['ExpenseSnap']
        # Find matching expense company ID
        ecid = ''
        r2 = fetch_api(url, '/api/companies/external', api_key)
        if r2:
            for ec in r2.get('companies', []):
                if ec['name'].lower().strip() == selected['name'].lower().strip():
                    ecid = str(ec['id']); break
        ep = '/api/expenses/external'
        if ecid: ep += f'?company_id={ecid}'
        r = fetch_api(url, ep, api_key)
        if r: expenses = r.get('expenses', [])

    if 'PayslipSnap' in apps:
        url = apps['PayslipSnap']['app_url'] or APP_URLS['PayslipSnap']
        r = fetch_api(url, '/api/payroll', api_key)
        if r: payslips = r.get('payslips', [])

    # Metrics
    total_invoiced = sum(float(i.get('total',0) or 0) for i in invoices)
    total_paid = sum(float(i.get('total',0) or 0) for i in invoices if i.get('status')=='paid')
    total_unpaid = total_invoiced - total_paid
    total_overdue = sum(float(i.get('total',0) or 0) for i in invoices if i.get('status')=='overdue')
    total_expenses = sum(float(e.get('total',0) or e.get('amount',0) or 0) for e in expenses)
    total_payroll = sum(float(p.get('net_pay',0) or 0) for p in payslips)
    total_payroll_gross = sum(float(p.get('gross_earnings',0) or 0) for p in payslips)
    contract_value = sum(float(c.get('total_value',0) or 0) for c in contracts)
    active_contracts = [c for c in contracts if c.get('status') in ('active','signed')]
    revenue = total_paid
    costs = total_expenses + total_payroll
    profit = revenue - costs

    # Expense categories
    cats = {}
    for e in expenses:
        c = e.get('category','Other') or 'Other'
        cats[c] = cats.get(c,0) + float(e.get('total',0) or e.get('amount',0) or 0)
    expense_cats = sorted(cats.items(), key=lambda x:-x[1])[:8]

    # Monthly chart
    monthly = []
    for i in range(5,-1,-1):
        d = datetime.now() - timedelta(days=30*i)
        ym = d.strftime('%Y-%m')
        inc = sum(float(inv.get('total',0) or 0) for inv in invoices
                  if inv.get('status')=='paid' and (inv.get('date','') or '').startswith(ym))
        exp = sum(float(e.get('total',0) or e.get('amount',0) or 0) for e in expenses
                  if (e.get('date','') or e.get('receipt_date','') or '').startswith(ym))
        pay = sum(float(p.get('net_pay',0) or 0) for p in payslips
                  if str(p.get('month','')).zfill(2)==d.strftime('%m') and str(p.get('year',''))==d.strftime('%Y'))
        monthly.append({'label':d.strftime('%b'),'income':inc,'expense':exp,'payroll':pay})
    mcv = max([m['income']+m['expense']+m['payroll'] for m in monthly]+[1])

    return render_template('dashboard.html', user=user, curr=curr,
        companies=companies, selected=selected, apps=apps, app_urls=APP_URLS,
        invoices=invoices[:5], contracts=active_contracts[:5],
        total_invoiced=total_invoiced, total_paid=total_paid, total_unpaid=total_unpaid,
        total_overdue=total_overdue, total_expenses=total_expenses,
        total_payroll=total_payroll, total_payroll_gross=total_payroll_gross,
        contract_value=contract_value,
        revenue=revenue, costs=costs, profit=profit,
        expense_cats=expense_cats, monthly=monthly, mcv=mcv)

# ── Admin ───────────────────────────────────────────────────────
@app.route('/admin')
@login_required
def admin_dashboard():
    user = get_user()
    if not user['is_superadmin']:
        flash('Admin only', 'error'); return redirect(url_for('dashboard'))

    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM companies ORDER BY name')
    companies = cur.fetchall()

    summaries = {}
    for c in companies:
        cur.execute('SELECT * FROM company_apps WHERE company_id=%s', (c['id'],))
        apps_list = cur.fetchall()
        apps = {a['app_name']: a for a in apps_list}
        api_key = c.get('owner_email', user['email'])
        s = {'apps': apps, 'invoiced':0, 'paid':0, 'expenses':0, 'payroll':0, 'contracts':0}

        for an, ai in apps.items():
            url = ai.get('app_url','') or APP_URLS.get(an,'')
            if an == 'InvoiceSnap':
                r = fetch_api(url, '/api/invoices', api_key)
                if r:
                    s['invoiced'] = sum(float(i.get('total',0) or 0) for i in r.get('invoices',[]))
                    s['paid'] = sum(float(i.get('total',0) or 0) for i in r.get('invoices',[]) if i.get('status')=='paid')
            elif an == 'ExpenseSnap':
                ecid = ''
                r2 = fetch_api(url, '/api/companies/external', api_key)
                if r2:
                    for ec in r2.get('companies',[]):
                        if ec['name'].lower().strip() == c['name'].lower().strip():
                            ecid = str(ec['id']); break
                ep = '/api/expenses/external'
                if ecid: ep += f'?company_id={ecid}'
                r = fetch_api(url, ep, api_key)
                if r: s['expenses'] = sum(float(e.get('total',0) or e.get('amount',0) or 0) for e in r.get('expenses',[]))
            elif an == 'ContractSnap':
                r = fetch_api(url, '/api/contracts', api_key)
                if r: s['contracts'] = sum(float(ct.get('total_value',0) or 0) for ct in r.get('contracts',[]))
            elif an == 'PayslipSnap':
                r = fetch_api(url, '/api/payroll', api_key)
                if r: s['payroll'] = sum(float(p.get('net_pay',0) or 0) for p in r.get('payslips',[]))
        s['profit'] = s['paid'] - s['expenses'] - s['payroll']
        summaries[c['id']] = s

    totals = {'companies': len(companies)}
    for k in ('invoiced','paid','expenses','payroll','contracts'):
        totals[k] = sum(s[k] for s in summaries.values())
    totals['profit'] = totals['paid'] - totals['expenses'] - totals['payroll']
    conn.close()

    return render_template('admin.html', user=user, companies=companies,
                         summaries=summaries, totals=totals, cs=cs, app_urls=APP_URLS)

@app.route('/settings', methods=['GET','POST'])
@login_required
def settings():
    user = get_user()
    if request.method == 'POST':
        conn = get_db(); cur = conn.cursor()
        cur.execute('UPDATE users SET name=%s, currency=%s WHERE id=%s',
                   (request.form.get('name',''), request.form.get('currency','INR'), user['id']))
        conn.close(); flash('Saved!', 'success'); return redirect(url_for('settings'))
    return render_template('settings.html', user=user, app_urls=APP_URLS)

@app.route('/settings/urls', methods=['POST'])
@login_required
def save_urls():
    user = get_user()
    if not user['is_superadmin']:
        flash('Admin only', 'error'); return redirect(url_for('settings'))
    conn = get_db(); cur = conn.cursor()
    for app_name in DEFAULT_URLS:
        url = request.form.get(app_name, '').strip()
        if url:
            cur.execute('''INSERT INTO app_settings (key, value) VALUES (%s, %s)
                          ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value''',
                       (f'url_{app_name}', url))
    conn.close()
    flash('App URLs saved!', 'success')
    return redirect(url_for('settings'))

@app.route('/seed-test-data', methods=['POST'])
@login_required
def seed_test_data():
    """Create test company 'Bloom Studio' with data across all apps."""
    user = get_user()
    if not user['is_superadmin']:
        flash('Admin only', 'error'); return redirect(url_for('admin_dashboard'))

    api_key = user['email']
    results = {}

    for app_name in ['ExpenseSnap', 'InvoiceSnap', 'ContractSnap', 'PayslipSnap']:
        url = APP_URLS.get(app_name, '')
        if not url: results[app_name] = 'No URL'; continue
        try:
            r = requests.post(url.rstrip('/') + '/api/seed-test-data',
                            headers={'X-API-Key': api_key}, timeout=30)
            results[app_name] = r.json() if r.status_code == 200 else f'Error {r.status_code}: {r.text[:100]}'
        except Exception as e:
            results[app_name] = f'Failed: {str(e)[:100]}'

    # Now register Bloom Studio in SnapSuite hub
    conn = get_db(); cur = conn.cursor()
    cur.execute('SELECT * FROM companies WHERE LOWER(name)=LOWER(%s)', ('Bloom Studio',))
    if not cur.fetchone():
        cur.execute('INSERT INTO companies (name,currency,owner_email) VALUES (%s,%s,%s) RETURNING *',
                   ('Bloom Studio', 'INR', user['email']))
        company = cur.fetchone()
        for app_name in ['ExpenseSnap', 'InvoiceSnap', 'ContractSnap', 'PayslipSnap']:
            url = APP_URLS.get(app_name, '')
            cur.execute('''INSERT INTO company_apps (company_id,app_name,app_company_name,app_url)
                          VALUES (%s,%s,%s,%s) ON CONFLICT (company_id,app_name) DO NOTHING''',
                       (company['id'], app_name, 'Bloom Studio', url))
        cur.execute('INSERT INTO company_users (company_id,user_id,role) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING',
                   (company['id'], user['id'], 'owner'))
    conn.close()

    flash(f'Test data created! Results: {results}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/sync', methods=['POST'])
@login_required
def sync_all():
    """Pull existing companies from all SnapSuite apps."""
    user = get_user()
    if not user['is_superadmin']:
        flash('Admin only', 'error'); return redirect(url_for('dashboard'))

    api_key = user['email']
    added = 0; errors = []

    def register_company(app_name, company_name, currency, app_url):
        """Direct DB insert instead of self-HTTP call."""
        nonlocal added
        if not company_name: return
        conn = get_db(); cur = conn.cursor()
        cur.execute('SELECT COUNT(*) as cnt FROM companies')
        if cur.fetchone()['cnt'] >= MAX_COMPANIES:
            conn.close(); return
        cur.execute('SELECT * FROM companies WHERE LOWER(name)=LOWER(%s)', (company_name,))
        company = cur.fetchone()
        if not company:
            cur.execute('INSERT INTO companies (name,currency,owner_email) VALUES (%s,%s,%s) RETURNING *',
                       (company_name, currency, user['email']))
            company = cur.fetchone()
            added += 1
        cur.execute('''INSERT INTO company_apps (company_id,app_name,app_company_name,app_url)
                      VALUES (%s,%s,%s,%s) ON CONFLICT (company_id,app_name)
                      DO UPDATE SET app_company_name=EXCLUDED.app_company_name, app_url=EXCLUDED.app_url''',
                   (company['id'], app_name, company_name, app_url))
        cur.execute('''INSERT INTO company_users (company_id,user_id,role)
                      VALUES (%s,%s,'owner') ON CONFLICT DO NOTHING''', (company['id'], user['id']))
        conn.close()

    # Sync from ExpenseSnap
    r = fetch_api(APP_URLS['ExpenseSnap'], '/api/companies/external', api_key)
    if r:
        for ec in r.get('companies', []):
            register_company('ExpenseSnap', ec['name'], ec.get('home_currency', 'INR'), APP_URLS['ExpenseSnap'])
    else:
        errors.append('ExpenseSnap: could not reach API')

    # Sync from InvoiceSnap
    r = fetch_api(APP_URLS['InvoiceSnap'], '/api/invoices', api_key)
    if r:
        seen = set()
        for inv in r.get('invoices', []):
            cn = inv.get('company_name', '').strip()
            if cn and cn not in seen:
                seen.add(cn)
                register_company('InvoiceSnap', cn, user.get('currency', 'INR'), APP_URLS['InvoiceSnap'])
    else:
        errors.append('InvoiceSnap: could not reach API')

    # Sync from ContractSnap
    r = fetch_api(APP_URLS['ContractSnap'], '/api/contracts', api_key)
    if r:
        seen = set()
        for ct in r.get('contracts', []):
            cn = ct.get('company_name', '').strip()
            if cn and cn not in seen:
                seen.add(cn)
                register_company('ContractSnap', cn, user.get('currency', 'INR'), APP_URLS['ContractSnap'])
    else:
        errors.append('ContractSnap: could not reach API')

    # Sync from PayslipSnap
    r = fetch_api(APP_URLS['PayslipSnap'], '/api/payroll', api_key)
    if r:
        cn = user.get('name', '').strip() or 'Default'
        # PayslipSnap doesn't have company_name per payslip, skip for now
    else:
        errors.append('PayslipSnap: could not reach API')

    msg = f'Synced! {added} new companies added.'
    if errors:
        msg += f' Issues: {"; ".join(errors)}'
        flash(msg, 'error' if added == 0 else 'success')
    else:
        flash(msg, 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/diagnose')
@login_required
def diagnose():
    user = get_user()
    results = {}
    api_key = user['email']
    endpoints = {
        'ExpenseSnap': ['/api/companies/external', '/api/expenses/external'],
        'InvoiceSnap': ['/api/invoices'],
        'ContractSnap': ['/api/contracts'],
        'PayslipSnap': ['/api/payroll'],
    }
    for an, url in APP_URLS.items():
        eps = endpoints.get(an, [])
        if not eps:
            results[an] = {'url': url, 'status': 'N/A', 'detail': 'No API endpoint'}
            continue
        for ep in eps:
            try:
                r = requests.get(url.rstrip('/') + ep,
                    headers={'X-API-Key': api_key}, timeout=30)
                data = r.text[:300]
                results[f'{an} {ep}'] = {'url': url + ep, 'status': r.status_code, 'detail': data}
            except Exception as e:
                results[f'{an} {ep}'] = {'url': url + ep, 'status': 'Error', 'detail': str(e)[:300]}
    results['_info'] = {'url': '', 'status': 'Info',
        'detail': f'API Key (email): {api_key} | Is superadmin: {user.get("is_superadmin")}'}
    return render_template('diagnose.html', user=user, results=results)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
