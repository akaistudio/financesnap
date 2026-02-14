import os
import json
import base64
import hashlib
import secrets
import calendar
from datetime import datetime, date, timedelta
from functools import wraps
from io import BytesIO

import requests as http_requests
from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, jsonify)
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# --- Database ---
def get_db():
    db_url = os.environ.get('DATABASE_URL', '')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    conn = psycopg2.connect(db_url)
    conn.autocommit = True
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        company_name TEXT DEFAULT '',
        logo_data TEXT DEFAULT '',
        brand_color TEXT DEFAULT '#1e40af',
        currency TEXT DEFAULT 'INR',
        is_superadmin BOOLEAN DEFAULT FALSE,
        proposalsnap_url TEXT DEFAULT '',
        contractsnap_url TEXT DEFAULT '',
        invoicesnap_url TEXT DEFAULT '',
        expensesnap_url TEXT DEFAULT '',
        payslipsnap_url TEXT DEFAULT '',
        api_key TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
    )''')
    # Manual entries for cash transactions
    cur.execute('''CREATE TABLE IF NOT EXISTS manual_entries (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        entry_type TEXT DEFAULT 'income',
        category TEXT DEFAULT '',
        description TEXT DEFAULT '',
        amount REAL DEFAULT 0,
        entry_date DATE DEFAULT CURRENT_DATE,
        created_at TIMESTAMP DEFAULT NOW()
    )''')
    conn.close()
    # Migrations
    conn = get_db()
    cur = conn.cursor()
    for m in [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN DEFAULT FALSE",
        "UPDATE users SET is_superadmin = TRUE WHERE id = (SELECT MIN(id) FROM users)",
    ]:
        try:
            cur.execute(m)
        except:
            pass
    conn.close()

init_db()

# --- Auth ---
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def get_user():
    if 'user_id' not in session:
        return None
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users WHERE id=%s', (session['user_id'],))
    user = cur.fetchone()
    conn.close()
    return user

CURR_SYMBOLS = {'CAD': 'C$', 'INR': 'Rs.', 'EUR': 'EUR ', 'USD': '$', 'GBP': 'GBP '}
def cs(currency):
    return CURR_SYMBOLS.get(currency, '$')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM users WHERE email=%s', (email,))
        user = cur.fetchone()
        conn.close()
        if user and user['password_hash'] == hash_pw(password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        company = request.form.get('company_name', '')
        currency = request.form.get('currency', 'INR')
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('login.html', show_register=True)
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute('SELECT COUNT(*) FROM users')
            is_first = cur.fetchone()[0] == 0
            cur.execute('''INSERT INTO users (email, password_hash, company_name, currency, api_key, is_superadmin)
                          VALUES (%s,%s,%s,%s,%s,%s) RETURNING id''',
                       (email, hash_pw(password), company, currency, email, is_first))
            user_id = cur.fetchone()[0]
            session['user_id'] = user_id
            conn.close()
            return redirect(url_for('settings'))
        except psycopg2.IntegrityError:
            conn.close()
            flash('Email already registered', 'error')
    return render_template('login.html', show_register=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- API Data Fetcher ---
def fetch_api(base_url, endpoint, api_key):
    """Fetch data from a SnapSuite app API."""
    if not base_url:
        return None
    try:
        url = base_url.rstrip('/') + endpoint
        resp = http_requests.get(url, headers={'X-API-Key': api_key}, timeout=8)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"API fetch error ({base_url}{endpoint}): {e}")
    return None

def fetch_all_data(user):
    return fetch_all_data_filtered(user, '')

def fetch_all_data_filtered(user, company_id=''):
    """Fetch data from all connected SnapSuite apps, optionally filtered by company."""
    api_key = user.get('api_key', user['email'])
    data = {
        'proposals': [], 'contracts': [], 'invoices': [],
        'expenses': [], 'payslips': [],
    }

    # Proposals
    result = fetch_api(user.get('proposalsnap_url', ''), '/api/proposals', api_key)
    if result:
        data['proposals'] = result.get('proposals', [])

    # Contracts
    result = fetch_api(user.get('contractsnap_url', ''), '/api/contracts', api_key)
    if result:
        data['contracts'] = result.get('contracts', [])

    # Invoices
    result = fetch_api(user.get('invoicesnap_url', ''), '/api/invoices', api_key)
    if result:
        data['invoices'] = result.get('invoices', [])

    # Expenses
    expense_endpoint = '/api/expenses/external'
    if company_id:
        expense_endpoint += f'?company_id={company_id}'
    result = fetch_api(user.get('expensesnap_url', ''), expense_endpoint, api_key)
    if result:
        data['expenses'] = result.get('expenses', [])

    # Payroll
    result = fetch_api(user.get('payslipsnap_url', ''), '/api/payroll', api_key)
    if result:
        data['payslips'] = result.get('payslips', [])

    return data

# --- Dashboard ---
@app.route('/')
@login_required
def dashboard():
    user = get_user()
    curr = cs(user.get('currency', 'INR'))

    # Get selected company
    selected_company = request.args.get('company', '')
    selected_company_name = 'All Companies'

    # Pull companies from ExpenseSnap
    api_key = user.get('api_key', user['email'])
    companies_list = []
    result = fetch_api(user.get('expensesnap_url', ''), '/api/companies/external', api_key)
    if result:
        companies_list = result.get('companies', [])

    if selected_company:
        for c in companies_list:
            if str(c.get('id', '')) == str(selected_company):
                selected_company_name = c.get('name', 'Unknown')
                break

    data = fetch_all_data_filtered(user, selected_company)

    # Manual entries
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM manual_entries WHERE user_id=%s ORDER BY entry_date DESC', (user['id'],))
    manual = cur.fetchall()
    conn.close()

    # === REVENUE ===
    invoices = data['invoices']
    total_invoiced = sum(float(i.get('total', 0) or 0) for i in invoices)
    total_paid = sum(float(i.get('total', 0) or 0) for i in invoices if i.get('status') == 'paid')
    total_unpaid = sum(float(i.get('total', 0) or 0) for i in invoices if i.get('status') in ('sent', 'unpaid'))
    total_overdue = sum(float(i.get('total', 0) or 0) for i in invoices if i.get('status') == 'overdue')
    manual_income = sum(float(m.get('amount', 0)) for m in manual if m.get('entry_type') == 'income')

    # === EXPENSES ===
    expenses = data['expenses']
    total_expenses = sum(float(e.get('total', 0) or e.get('amount', 0) or 0) for e in expenses)
    manual_expense = sum(float(m.get('amount', 0)) for m in manual if m.get('entry_type') == 'expense')

    # Expense by currency
    expense_by_currency = {}
    for e in expenses:
        ecurr = e.get('currency', 'INR') or 'INR'
        expense_by_currency[ecurr] = expense_by_currency.get(ecurr, 0) + float(e.get('total', 0) or e.get('amount', 0) or 0)

    # Expense by category
    expense_cats = {}
    for e in expenses:
        cat = e.get('category', 'Other') or 'Other'
        expense_cats[cat] = expense_cats.get(cat, 0) + float(e.get('total', 0) or e.get('amount', 0) or 0)
    for m in manual:
        if m.get('entry_type') == 'expense':
            cat = m.get('category', 'Other') or 'Other'
            expense_cats[cat] = expense_cats.get(cat, 0) + float(m.get('amount', 0))
    expense_cats_sorted = sorted(expense_cats.items(), key=lambda x: -x[1])[:10]

    # === PAYROLL ===
    payslips = data['payslips']
    total_payroll_gross = sum(float(p.get('gross_earnings', 0) or 0) for p in payslips)
    total_payroll_net = sum(float(p.get('net_pay', 0) or 0) for p in payslips)
    total_payroll_tds = sum(float(p.get('tds', 0) or 0) for p in payslips)
    total_payroll_pf = sum(float(p.get('pf_employee', 0) or 0) + float(p.get('pf_employer', 0) or 0) for p in payslips)

    # === CONTRACTS ===
    contracts = data['contracts']
    total_contract_value = sum(float(c.get('total_value', 0) or 0) for c in contracts)
    active_contracts = [c for c in contracts if c.get('status') in ('active', 'signed')]
    active_contract_value = sum(float(c.get('total_value', 0) or 0) for c in active_contracts)
    total_contracted_invoiced = sum(float(c.get('invoiced_amount', 0) or 0) for c in contracts)

    # === PROPOSALS ===
    proposals = data['proposals']
    total_proposals = len(proposals)
    won_proposals = len([p for p in proposals if p.get('status') in ('won', 'accepted')])
    proposal_value = sum(float(p.get('total', 0) or p.get('amount', 0) or 0) for p in proposals)

    # === TAXES ===
    tax_collected = sum(float(i.get('tax_amount', 0) or 0) for i in invoices)
    tax_on_expenses = sum(float(e.get('tax_amount', 0) or 0) for e in expenses)

    # === P&L ===
    total_revenue = total_paid + manual_income
    if selected_company:
        # When viewing a specific company, only count that company's expenses
        total_costs = total_expenses + manual_expense
    else:
        total_costs = total_expenses + manual_expense + total_payroll_net
    net_profit = total_revenue - total_costs

    # === MONTHLY CASH FLOW (last 6 months) ===
    monthly_data = {}
    now = datetime.now()
    for i in range(5, -1, -1):
        d = now - timedelta(days=30 * i)
        key = f"{d.year}-{d.month:02d}"
        monthly_data[key] = {'label': d.strftime('%b %Y'), 'income': 0, 'expense': 0, 'payroll': 0}

    for inv in invoices:
        if inv.get('status') == 'paid' and inv.get('date'):
            try:
                dt = str(inv['date'])[:7]
                if dt in monthly_data:
                    monthly_data[dt]['income'] += float(inv.get('total', 0) or 0)
            except:
                pass

    for exp in expenses:
        dt_field = exp.get('date', exp.get('receipt_date', ''))
        if dt_field:
            try:
                dt = str(dt_field)[:7]
                if dt in monthly_data:
                    monthly_data[dt]['expense'] += float(exp.get('total', 0) or exp.get('amount', 0) or 0)
            except:
                pass

    for ps in payslips:
        try:
            key = f"{ps.get('year')}-{int(ps.get('month', 0)):02d}"
            if key in monthly_data:
                monthly_data[key]['payroll'] += float(ps.get('net_pay', 0) or 0)
        except:
            pass

    monthly_list = list(monthly_data.values())
    max_chart_val = max([max(m['income'], m['expense'], m['payroll'], 1) for m in monthly_list])

    # === PIPELINE ===
    pipeline = {
        'proposals': total_proposals,
        'won': won_proposals,
        'contracts': len(contracts),
        'active_contracts': len(active_contracts),
        'invoices': len(invoices),
        'paid_invoices': len([i for i in invoices if i.get('status') == 'paid']),
    }

    # Connection status
    connections = {
        'proposalsnap': bool(user.get('proposalsnap_url')),
        'contractsnap': bool(user.get('contractsnap_url')),
        'invoicesnap': bool(user.get('invoicesnap_url')),
        'expensesnap': bool(user.get('expensesnap_url')),
        'payslipsnap': bool(user.get('payslipsnap_url')),
    }

    return render_template('dashboard.html', user=user, curr=curr,
        total_invoiced=total_invoiced, total_paid=total_paid, total_unpaid=total_unpaid,
        total_overdue=total_overdue, total_expenses=total_expenses + manual_expense,
        total_payroll_gross=total_payroll_gross, total_payroll_net=total_payroll_net,
        total_payroll_tds=total_payroll_tds, total_payroll_pf=total_payroll_pf,
        total_contract_value=total_contract_value, active_contract_value=active_contract_value,
        total_contracted_invoiced=total_contracted_invoiced,
        proposal_value=proposal_value, total_proposals=total_proposals, won_proposals=won_proposals,
        tax_collected=tax_collected, tax_on_expenses=tax_on_expenses,
        total_revenue=total_revenue, total_costs=total_costs, net_profit=net_profit,
        expense_cats=expense_cats_sorted, monthly=monthly_list, pipeline=pipeline,
        contracts=active_contracts[:5], invoices=invoices[:5],
        connections=connections, manual_income=manual_income, manual_expense=manual_expense,
        max_chart_val=max_chart_val, expense_by_currency=expense_by_currency,
        companies=companies_list, selected_company=selected_company,
        selected_company_name=selected_company_name, is_filtered=bool(selected_company))

# --- Drilldowns ---
@app.route('/drilldown/<app_name>')
@login_required
def drilldown(app_name):
    user = get_user()
    api_key = user.get('api_key', user['email'])
    curr = cs(user.get('currency', 'INR'))
    data = []
    app_url = ''
    title = ''
    company_id = request.args.get('company', '')

    if app_name == 'invoices':
        app_url = user.get('invoicesnap_url', '')
        result = fetch_api(app_url, '/api/invoices', api_key)
        data = result.get('invoices', []) if result else []
        title = 'Invoices'
    elif app_name == 'contracts':
        app_url = user.get('contractsnap_url', '')
        result = fetch_api(app_url, '/api/contracts', api_key)
        data = result.get('contracts', []) if result else []
        title = 'Contracts'
    elif app_name == 'expenses':
        app_url = user.get('expensesnap_url', '')
        endpoint = '/api/expenses/external'
        if company_id:
            endpoint += f'?company_id={company_id}'
        result = fetch_api(app_url, endpoint, api_key)
        data = result.get('expenses', []) if result else []
        title = 'Expenses'
    elif app_name == 'payroll':
        app_url = user.get('payslipsnap_url', '')
        result = fetch_api(app_url, '/api/payroll', api_key)
        data = result.get('payslips', []) if result else []
        title = 'Payroll'

    return render_template('drilldown.html', user=user, data=data, app_name=app_name,
                         app_url=app_url, title=title, curr=curr)

# --- Manual Entries ---
@app.route('/entries')
@login_required
def entries():
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM manual_entries WHERE user_id=%s ORDER BY entry_date DESC', (user['id'],))
    entries_list = cur.fetchall()
    conn.close()
    return render_template('entries.html', user=user, entries=entries_list,
                         curr=cs(user.get('currency', 'INR')), today=date.today().isoformat())

@app.route('/entry/add', methods=['POST'])
@login_required
def add_entry():
    user = get_user()
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''INSERT INTO manual_entries (user_id, entry_type, category, description, amount, entry_date)
                  VALUES (%s,%s,%s,%s,%s,%s)''',
               (user['id'], request.form.get('entry_type', 'income'),
                request.form.get('category', ''), request.form.get('description', ''),
                float(request.form.get('amount', 0) or 0),
                request.form.get('entry_date') or date.today()))
    conn.close()
    flash('Entry added!', 'success')
    return redirect(url_for('entries'))

@app.route('/entry/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_entry(entry_id):
    user = get_user()
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM manual_entries WHERE id=%s AND user_id=%s', (entry_id, user['id']))
    conn.close()
    flash('Entry deleted', 'success')
    return redirect(url_for('entries'))

# --- Settings ---
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = get_user()
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()

        logo_data = user.get('logo_data', '')
        brand_color = request.form.get('brand_color', '#1e40af')
        logo_file = request.files.get('logo')
        if logo_file and logo_file.filename:
            img_data = logo_file.read()
            ext = logo_file.filename.rsplit('.', 1)[-1].lower()
            media_type = f"image/{'jpeg' if ext in ('jpg','jpeg') else ext}"
            logo_data = f"data:{media_type};base64,{base64.b64encode(img_data).decode()}"

        cur.execute('''UPDATE users SET company_name=%s, logo_data=%s, brand_color=%s,
                      currency=%s, proposalsnap_url=%s, contractsnap_url=%s,
                      invoicesnap_url=%s, expensesnap_url=%s, payslipsnap_url=%s,
                      api_key=%s WHERE id=%s''',
                   (request.form.get('company_name', ''),
                    logo_data, brand_color,
                    request.form.get('currency', 'INR'),
                    request.form.get('proposalsnap_url', '').rstrip('/'),
                    request.form.get('contractsnap_url', '').rstrip('/'),
                    request.form.get('invoicesnap_url', '').rstrip('/'),
                    request.form.get('expensesnap_url', '').rstrip('/'),
                    request.form.get('payslipsnap_url', '').rstrip('/'),
                    request.form.get('api_key', user['email']),
                    user['id']))
        conn.close()
        flash('Settings saved! Dashboard will now pull data from connected apps.', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', user=user)

# --- Admin ---
@app.route('/diagnose')
@login_required
def diagnose():
    """Show connection status for each app."""
    user = get_user()
    api_key = user.get('api_key', user['email'])
    results = {}

    apps = {
        'ProposalSnap': (user.get('proposalsnap_url', ''), '/api/proposals'),
        'ContractSnap': (user.get('contractsnap_url', ''), '/api/contracts'),
        'InvoiceSnap': (user.get('invoicesnap_url', ''), '/api/invoices'),
        'ExpenseSnap': (user.get('expensesnap_url', ''), '/api/expenses/external'),
        'PayslipSnap': (user.get('payslipsnap_url', ''), '/api/payroll'),
    }

    for name, (base_url, endpoint) in apps.items():
        if not base_url:
            results[name] = {'status': 'not configured', 'url': '', 'error': 'No URL set'}
            continue
        try:
            url = base_url.rstrip('/') + endpoint
            resp = http_requests.get(url, headers={'X-API-Key': api_key}, timeout=8)
            results[name] = {
                'status': resp.status_code,
                'url': url,
                'response': resp.text[:500],
                'error': '' if resp.status_code == 200 else f'HTTP {resp.status_code}'
            }
        except Exception as e:
            results[name] = {'status': 'error', 'url': base_url + endpoint, 'error': str(e)}

    return jsonify({
        'api_key_used': api_key,
        'results': results
    })
@app.route('/admin')
@login_required
def admin_dashboard():
    user = get_user()
    if not user.get('is_superadmin'):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users ORDER BY created_at DESC')
    users_list = cur.fetchall()
    conn.close()

    # Pull summaries from all apps for each user
    app_summaries = {}
    for u in users_list:
        api_key = u.get('api_key', u['email'])
        summary = {}

        # Invoices
        result = fetch_api(u.get('invoicesnap_url', ''), '/api/invoices', api_key)
        if result:
            invs = result.get('invoices', [])
            summary['invoices'] = len(invs)
            summary['invoice_total'] = sum(float(i.get('total', 0) or 0) for i in invs)
            summary['invoice_paid'] = sum(float(i.get('total', 0) or 0) for i in invs if i.get('status') == 'paid')
        else:
            summary['invoices'] = 0; summary['invoice_total'] = 0; summary['invoice_paid'] = 0

        # Contracts
        result = fetch_api(u.get('contractsnap_url', ''), '/api/contracts', api_key)
        if result:
            ctrs = result.get('contracts', [])
            summary['contracts'] = len(ctrs)
            summary['contract_value'] = sum(float(c.get('total_value', 0) or 0) for c in ctrs)
            summary['active_contracts'] = len([c for c in ctrs if c.get('status') in ('active', 'signed')])
        else:
            summary['contracts'] = 0; summary['contract_value'] = 0; summary['active_contracts'] = 0

        # Expenses
        result = fetch_api(u.get('expensesnap_url', ''), '/api/expenses/external', api_key)
        if result:
            exps = result.get('expenses', [])
            summary['expenses'] = len(exps)
            summary['expense_total'] = sum(float(e.get('total', 0) or e.get('amount', 0) or 0) for e in exps)
        else:
            summary['expenses'] = 0; summary['expense_total'] = 0

        # Payroll
        result = fetch_api(u.get('payslipsnap_url', ''), '/api/payroll', api_key)
        if result:
            slips = result.get('payslips', [])
            summary['payslips'] = len(slips)
            summary['payroll_total'] = sum(float(p.get('net_pay', 0) or 0) for p in slips)
        else:
            summary['payslips'] = 0; summary['payroll_total'] = 0

        # Connected apps count
        summary['connected'] = sum([
            bool(u.get('proposalsnap_url')),
            bool(u.get('contractsnap_url')),
            bool(u.get('invoicesnap_url')),
            bool(u.get('expensesnap_url')),
            bool(u.get('payslipsnap_url')),
        ])

        summary['revenue'] = summary['invoice_paid']
        summary['costs'] = summary['expense_total'] + summary['payroll_total']
        summary['profit'] = summary['revenue'] - summary['costs']

        app_summaries[u['id']] = summary

    # Platform totals
    totals = {
        'users': len(users_list),
        'total_contract_value': sum(s['contract_value'] for s in app_summaries.values()),
        'total_invoiced': sum(s['invoice_total'] for s in app_summaries.values()),
        'total_paid': sum(s['invoice_paid'] for s in app_summaries.values()),
        'total_expenses': sum(s['expense_total'] for s in app_summaries.values()),
        'total_payroll': sum(s['payroll_total'] for s in app_summaries.values()),
    }
    totals['total_revenue'] = totals['total_paid']
    totals['total_costs'] = totals['total_expenses'] + totals['total_payroll']
    totals['total_profit'] = totals['total_revenue'] - totals['total_costs']

    # Pull companies from ExpenseSnap
    expense_companies = []
    for u in users_list:
        api_key = u.get('api_key', u['email'])
        result = fetch_api(u.get('expensesnap_url', ''), '/api/companies/external', api_key)
        if result:
            expense_companies = result.get('companies', [])
            break  # Only need from one admin

    curr = cs(user.get('currency', 'INR'))
    return render_template('admin.html', user=user, users=users_list,
                         summaries=app_summaries, totals=totals, curr=curr,
                         expense_companies=expense_companies)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
