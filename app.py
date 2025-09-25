import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from datetime import datetime, timedelta
import io
import csv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')  # Fallback for local testing
bcrypt = Bcrypt(app)

# Environment-based user credentials
USERS = {
    os.getenv('ADMIN_USERNAME', 'admin_user'): {
        'password': os.getenv('ADMIN_PASSWORD_HASH'),
        'role': 'admin',
        'id': 1
    },
    os.getenv('VIEWER_USERNAME', 'wife_user'): {
        'password': os.getenv('VIEWER_PASSWORD_HASH'),
        'role': 'viewer',
        'id': 2
    }
}

# Database connection
D1_DATABASE_NAME = os.getenv('D1_DATABASE_NAME', 'dinner-budget-db')

def get_db_connection():
    if os.getenv('VERCEL_ENV') == 'production':
        # Vercel provides D1 binding via request.env in serverless functions
        # Handled in routes to access request.env
        return None
    else:
        # Local SQLite
        return sqlite3.connect('/tmp/database.db')

# Database setup
def init_db():
    conn = get_db_connection()
    if os.getenv('VERCEL_ENV') == 'production':
        # In production, database is initialized via Vercel CLI or dashboard
        # Ensure tables exist (run once via dashboard or CLI)
        pass
    else:
        # Local SQLite
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS budget (id INTEGER PRIMARY KEY, amount REAL NOT NULL)')
        cursor.execute('CREATE TABLE IF NOT EXISTS dinners (id INTEGER PRIMARY KEY AUTOINCREMENT, description TEXT NOT NULL, amount REAL NOT NULL, date TEXT NOT NULL)')
        cursor.execute('CREATE TABLE IF NOT EXISTS archived_dinners (id INTEGER PRIMARY KEY AUTOINCREMENT, description TEXT NOT NULL, amount REAL NOT NULL, date TEXT NOT NULL, archive_date TEXT NOT NULL)')
        cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, role TEXT NOT NULL)')
        cursor.execute('SELECT * FROM budget')
        if not cursor.fetchone():
            cursor.execute('INSERT INTO budget (amount) VALUES (0)')
        cursor.execute('SELECT * FROM users')
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (id, role) VALUES (?, ?)', (1, 'admin'))
            cursor.execute('INSERT INTO users (id, role) VALUES (?, ?)', (2, 'viewer'))
        conn.commit()
        conn.close()

init_db()

# Login required decorator
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access the app.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# Admin required decorator
def admin_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access the app.', 'warning')
            return redirect(url_for('login'))
        if os.getenv('VERCEL_ENV') == 'production':
            db = kwargs.get('env').get(D1_DATABASE_NAME)
            result = db.prepare('SELECT role FROM users WHERE id = ?').bind(session['user_id']).run()
            role = result.results[0] if result.results else None
        else:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
            role = cursor.fetchone()
            conn.close()
        if not role or role[0] != 'admin':
            flash('Access denied: Admin privileges required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = USERS.get(username)
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def index(env=None):
    if os.getenv('VERCEL_ENV') == 'production':
        db = env.get(D1_DATABASE_NAME)
        if request.method == 'POST':
            if 'set_budget' in request.form:
                if session.get('role') != 'admin':
                    flash('Access denied: Admin privileges required.', 'danger')
                else:
                    try:
                        budget = float(request.form['budget'])
                        if budget < 0:
                            flash('Budget cannot be negative.', 'danger')
                        else:
                            db.prepare('UPDATE budget SET amount = ?').bind(budget).run()
                            flash('Budget updated successfully.', 'success')
                    except ValueError:
                        flash('Invalid budget amount.', 'danger')
            elif 'add_dinner' in request.form:
                if session.get('role') != 'admin':
                    flash('Access denied: Admin privileges required.', 'danger')
                else:
                    description = request.form['description'].strip()
                    if len(description) > 100:
                        flash('Description cannot exceed 100 characters.', 'danger')
                    else:
                        try:
                            amount = float(request.form['amount'])
                            if amount <= 0:
                                flash('Dinner amount must be positive.', 'danger')
                            else:
                                date = request.form['date']
                                try:
                                    datetime.strptime(date, '%Y-%m-%d')
                                    db.prepare('INSERT INTO dinners (description, amount, date) VALUES (?, ?, ?)') \
                                      .bind(description, amount, date).run()
                                    flash('Dinner added successfully.', 'success')
                                except ValueError:
                                    flash('Invalid date format.', 'danger')
                        except ValueError:
                            flash('Invalid dinner amount.', 'danger')
            elif 'edit_dinner' in request.form:
                if session.get('role') != 'admin':
                    flash('Access denied: Admin privileges required.', 'danger')
                else:
                    dinner_id = request.form['dinner_id']
                    description = request.form['description'].strip()
                    if len(description) > 100:
                        flash('Description cannot exceed 100 characters.', 'danger')
                    else:
                        try:
                            amount = float(request.form['amount'])
                            if amount <= 0:
                                flash('Dinner amount must be positive.', 'danger')
                            else:
                                date = request.form['date']
                                try:
                                    datetime.strptime(date, '%Y-%m-%d')
                                    db.prepare('UPDATE dinners SET description = ?, amount = ?, date = ? WHERE id = ?') \
                                      .bind(description, amount, date, dinner_id).run()
                                    flash('Dinner updated successfully.', 'success')
                                except ValueError:
                                    flash('Invalid date format.', 'danger')
                        except ValueError:
                            flash('Invalid dinner amount.', 'danger')
            elif 'reset_budget' in request.form:
                if session.get('role') != 'admin':
                    flash('Access denied: Admin privileges required.', 'danger')
                else:
                    try:
                        new_budget = float(request.form['new_budget'])
                        if new_budget < 0:
                            flash('New budget cannot be negative.', 'danger')
                        else:
                            archive_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            db.prepare('INSERT INTO archived_dinners (description, amount, date, archive_date) ' +
                                      'SELECT description, amount, date, ? FROM dinners').bind(archive_date).run()
                            db.prepare('DELETE FROM dinners').run()
                            db.prepare('UPDATE budget SET amount = ?').bind(new_budget).run()
                            flash('Budget reset and dinners archived successfully.', 'success')
                    except ValueError:
                        flash('Invalid new budget amount.', 'danger')
        # Fetch data
        result = db.prepare('SELECT amount FROM budget').run()
        budget = result.results[0]['amount'] if result.results else 0
        result = db.prepare('SELECT id, description, amount, date FROM dinners ORDER BY date DESC LIMIT 1').run()
        latest_dinner = result.results[0] if result.results else None
        result = db.prepare('SELECT SUM(amount) as total FROM dinners').run()
        total_spent = result.results[0]['total'] if result.results and result.results[0]['total'] else 0
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        if request.method == 'POST':
            if 'set_budget' in request.form:
                if session.get('role') != 'admin':
                    flash('Access denied: Admin privileges required.', 'danger')
                else:
                    try:
                        budget = float(request.form['budget'])
                        if budget < 0:
                            flash('Budget cannot be negative.', 'danger')
                        else:
                            cursor.execute('UPDATE budget SET amount = ?', (budget,))
                            flash('Budget updated successfully.', 'success')
                    except ValueError:
                        flash('Invalid budget amount.', 'danger')
            elif 'add_dinner' in request.form:
                if session.get('role') != 'admin':
                    flash('Access denied: Admin privileges required.', 'danger')
                else:
                    description = request.form['description'].strip()
                    if len(description) > 100:
                        flash('Description cannot exceed 100 characters.', 'danger')
                    else:
                        try:
                            amount = float(request.form['amount'])
                            if amount <= 0:
                                flash('Dinner amount must be positive.', 'danger')
                            else:
                                date = request.form['date']
                                try:
                                    datetime.strptime(date, '%Y-%m-%d')
                                    cursor.execute('INSERT INTO dinners (description, amount, date) VALUES (?, ?, ?)', 
                                                  (description, amount, date))
                                    flash('Dinner added successfully.', 'success')
                                except ValueError:
                                    flash('Invalid date format.', 'danger')
                        except ValueError:
                            flash('Invalid dinner amount.', 'danger')
            elif 'edit_dinner' in request.form:
                if session.get('role') != 'admin':
                    flash('Access denied: Admin privileges required.', 'danger')
                else:
                    dinner_id = request.form['dinner_id']
                    description = request.form['description'].strip()
                    if len(description) > 100:
                        flash('Description cannot exceed 100 characters.', 'danger')
                    else:
                        try:
                            amount = float(request.form['amount'])
                            if amount <= 0:
                                flash('Dinner amount must be positive.', 'danger')
                            else:
                                date = request.form['date']
                                try:
                                    datetime.strptime(date, '%Y-%m-%d')
                                    cursor.execute('UPDATE dinners SET description = ?, amount = ?, date = ? WHERE id = ?', 
                                                  (description, amount, date, dinner_id))
                                    flash('Dinner updated successfully.', 'success')
                                except ValueError:
                                    flash('Invalid date format.', 'danger')
                        except ValueError:
                            flash('Invalid dinner amount.', 'danger')
            elif 'reset_budget' in request.form:
                if session.get('role') != 'admin':
                    flash('Access denied: Admin privileges required.', 'danger')
                else:
                    try:
                        new_budget = float(request.form['new_budget'])
                        if new_budget < 0:
                            flash('New budget cannot be negative.', 'danger')
                        else:
                            archive_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            cursor.execute('INSERT INTO archived_dinners (description, amount, date, archive_date) '
                                          'SELECT description, amount, date, ? FROM dinners', (archive_date,))
                            cursor.execute('DELETE FROM dinners')
                            cursor.execute('UPDATE budget SET amount = ?', (new_budget,))
                            flash('Budget reset and dinners archived successfully.', 'success')
                    except ValueError:
                        flash('Invalid new budget amount.', 'danger')
            conn.commit()
        # Fetch data
        cursor.execute('SELECT amount FROM budget')
        budget = cursor.fetchone()[0]
        cursor.execute('SELECT id, description, amount, date FROM dinners ORDER BY date DESC LIMIT 1')
        latest_dinner = cursor.fetchone()
        cursor.execute('SELECT SUM(amount) FROM dinners')
        total_spent = cursor.fetchone()[0] or 0
        conn.close()
    remaining = budget - total_spent
    return render_template('index.html', budget=budget, latest_dinner=latest_dinner, total_spent=total_spent, 
                         remaining=remaining, role=session.get('role'), today=datetime.now().strftime('%Y-%m-%d'))

@app.route('/records', methods=['GET', 'POST'])
def records(env=None):
    if os.getenv('VERCEL_ENV') == 'production':
        db = env.get(D1_DATABASE_NAME)
        # Initialize filters
        description_filter = request.form.get('description', '') if request.method == 'POST' else ''
        date_from = request.form.get('date_from', '') if request.method == 'POST' else ''
        date_to = request.form.get('date_to', '') if request.method == 'POST' else ''

        # Build query
        query = 'SELECT id, description, amount, date FROM dinners WHERE 1=1'
        params = []
        if description_filter:
            query += ' AND description LIKE ?'
            params.append(f'%{description_filter}%')
        if date_from:
            try:
                datetime.strptime(date_from, '%Y-%m-%d')
                query += ' AND date >= ?'
                params.append(date_from)
            except ValueError:
                flash('Invalid start date format.', 'danger')
        if date_to:
            try:
                datetime.strptime(date_to, '%Y-%m-%d')
                query += ' AND date <= ?'
                params.append(date_to)
            except ValueError:
                flash('Invalid end date format.', 'danger')
        query += ' ORDER BY date DESC'

        if request.method == 'POST' and 'edit_dinner' in request.form:
            if session.get('role') != 'admin':
                flash('Access denied: Admin privileges required.', 'danger')
            else:
                dinner_id = request.form['dinner_id']
                description = request.form['description'].strip()
                if len(description) > 100:
                    flash('Description cannot exceed 100 characters.', 'danger')
                else:
                    try:
                        amount = float(request.form['amount'])
                        if amount <= 0:
                            flash('Dinner amount must be positive.', 'danger')
                        else:
                            date = request.form['date']
                            try:
                                datetime.strptime(date, '%Y-%m-%d')
                                db.prepare('UPDATE dinners SET description = ?, amount = ?, date = ? WHERE id = ?') \
                                  .bind(description, amount, date, dinner_id).run()
                                flash('Dinner updated successfully.', 'success')
                            except ValueError:
                                flash('Invalid date format.', 'danger')
                    except ValueError:
                        flash('Invalid dinner amount.', 'danger')

        # Fetch dinners with filters
        result = db.prepare(query).bind(*params).run()
        dinners = result.results

        # Spending summary
        today = datetime.now()
        week_start = (today - timedelta(days=today.weekday())).strftime('%Y-%m-%d')
        month_start = today.replace(day=1).strftime('%Y-%m-%d')
        result = db.prepare('SELECT SUM(amount) as total FROM dinners WHERE date >= ?').bind(week_start).run()
        week_spent = result.results[0]['total'] if result.results and result.results[0]['total'] else 0
        result = db.prepare('SELECT SUM(amount) as total FROM dinners WHERE date >= ?').bind(month_start).run()
        month_spent = result.results[0]['total'] if result.results and result.results[0]['total'] else 0

        # Budget threshold check
        result = db.prepare('SELECT amount FROM budget').run()
        budget = result.results[0]['amount'] if result.results else 0
        result = db.prepare('SELECT SUM(amount) as total FROM dinners').run()
        total_spent = result.results[0]['total'] if result.results and result.results[0]['total'] else 0
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Initialize filters
        description_filter = request.form.get('description', '') if request.method == 'POST' else ''
        date_from = request.form.get('date_from', '') if request.method == 'POST' else ''
        date_to = request.form.get('date_to', '') if request.method == 'POST' else ''

        # Build query
        query = 'SELECT id, description, amount, date FROM dinners WHERE 1=1'
        params = []
        if description_filter:
            query += ' AND description LIKE ?'
            params.append(f'%{description_filter}%')
        if date_from:
            try:
                datetime.strptime(date_from, '%Y-%m-%d')
                query += ' AND date >= ?'
                params.append(date_from)
            except ValueError:
                flash('Invalid start date format.', 'danger')
        if date_to:
            try:
                datetime.strptime(date_to, '%Y-%m-%d')
                query += ' AND date <= ?'
                params.append(date_to)
            except ValueError:
                flash('Invalid end date format.', 'danger')
        query += ' ORDER BY date DESC'

        if request.method == 'POST' and 'edit_dinner' in request.form:
            if session.get('role') != 'admin':
                flash('Access denied: Admin privileges required.', 'danger')
            else:
                dinner_id = request.form['dinner_id']
                description = request.form['description'].strip()
                if len(description) > 100:
                    flash('Description cannot exceed 100 characters.', 'danger')
                else:
                    try:
                        amount = float(request.form['amount'])
                        if amount <= 0:
                            flash('Dinner amount must be positive.', 'danger')
                        else:
                            date = request.form['date']
                            try:
                                datetime.strptime(date, '%Y-%m-%d')
                                cursor.execute('UPDATE dinners SET description = ?, amount = ?, date = ? WHERE id = ?', 
                                              (description, amount, date, dinner_id))
                                flash('Dinner updated successfully.', 'success')
                            except ValueError:
                                flash('Invalid date format.', 'danger')
                    except ValueError:
                        flash('Invalid dinner amount.', 'danger')
            conn.commit()

        # Fetch dinners with filters
        cursor.execute(query, params)
        dinners = cursor.fetchall()

        # Spending summary
        today = datetime.now()
        week_start = (today - timedelta(days=today.weekday())).strftime('%Y-%m-%d')
        month_start = today.replace(day=1).strftime('%Y-%m-%d')
        cursor.execute('SELECT SUM(amount) FROM dinners WHERE date >= ?', (week_start,))
        week_spent = cursor.fetchone()[0] or 0
        cursor.execute('SELECT SUM(amount) FROM dinners WHERE date >= ?', (month_start,))
        month_spent = cursor.fetchone()[0] or 0

        # Budget threshold check
        cursor.execute('SELECT amount FROM budget')
        budget = cursor.fetchone()[0]
        cursor.execute('SELECT SUM(amount) FROM dinners')
        total_spent = cursor.fetchone()[0] or 0
        conn.close()
    remaining = budget - total_spent
    threshold_alert = remaining < (budget * 0.2) and budget > 0
    return render_template('records.html', dinners=dinners, role=session.get('role'), 
                         week_spent=week_spent, month_spent=month_spent, threshold_alert=threshold_alert,
                         description_filter=description_filter, date_from=date_from, date_to=date_to)

@app.route('/delete/<int:dinner_id>', methods=['POST'])
@admin_required
def delete(dinner_id, env=None):
    if os.getenv('VERCEL_ENV') == 'production':
        db = env.get(D1_DATABASE_NAME)
        db.prepare('DELETE FROM dinners WHERE id = ?').bind(dinner_id).run()
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM dinners WHERE id = ?', (dinner_id,))
        conn.commit()
        conn.close()
    flash('Dinner deleted successfully.', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/export', methods=['GET'])
@admin_required
def export(env=None):
    if os.getenv('VERCEL_ENV') == 'production':
        db = env.get(D1_DATABASE_NAME)
        result = db.prepare('SELECT description, amount, date FROM dinners ORDER BY date DESC').run()
        dinners = result.results
    else:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT description, amount, date FROM dinners ORDER BY date DESC')
        dinners = cursor.fetchall()
        conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Description', 'Amount (RM)', 'Date'])
    for dinner in dinners:
        writer.writerow([dinner['description'] if os.getenv('VERCEL_ENV') == 'production' else dinner[0], 
                        f"{dinner['amount'] if os.getenv('VERCEL_ENV') == 'production' else dinner[1]:.2f}", 
                        dinner['date'] if os.getenv('VERCEL_ENV') == 'production' else dinner[2]])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'dinner_records_{datetime.now().strftime("%Y%m%d")}.csv'
    )

# Vercel serverless function handler
def handler(request):
    app.config['SERVER_NAME'] = request.headers.get('host')
    with app.request_context(request.environ):
        return app.full_dispatch_request()

if __name__ == "__main__":
    app.run(debug=True)
else:
    application = app  # For WSGI compatibility