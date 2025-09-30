from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_bcrypt import Bcrypt
import sqlite3
import logging
import os
from datetime import datetime
from dotenv import load_dotenv
import csv
import io
import psycopg2
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)
load_dotenv()

# Configure secret key
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    if os.getenv('VERCEL_ENV') == 'production':
        raise RuntimeError("SECRET_KEY is not set in production environment")
    else:
        app.secret_key = 'temporary-secret-key-for-local-debugging'
        logging.warning("Using temporary SECRET_KEY for local debugging. Set SECRET_KEY in .env for production.")

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database setup
def get_db_connection():
    if os.getenv('VERCEL_ENV'):
        conn = psycopg2.connect(os.getenv('POSTGRES_URL'))
    else:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
    return conn

# Custom Jinja2 filter for currency formatting
def currency_filter(value):
    try:
        return "{:0.2f}".format(float(value))
    except (ValueError, TypeError):
        return "0.00"

app.jinja_env.filters['currency'] = currency_filter

# Authentication decorator
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'danger')
            return redirect(url_for('login'))
        logger.debug(f"Index route: user_id={session['user_id']}, role={session.get('role')}")
        return f(*args, **kwargs)
    return wrap

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        logger.debug(f"Login attempt: username={username}")

        if username == os.getenv('ADMIN_USERNAME') and bcrypt.check_password_hash(os.getenv('ADMIN_PASSWORD_HASH'), password):
            session['user_id'] = 1
            session['role'] = 'admin'
            logger.info(f"Successful login for user: {username}, role=admin")
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        elif username == os.getenv('VIEWER_USERNAME') and bcrypt.check_password_hash(os.getenv('VIEWER_PASSWORD_HASH'), password):
            session['user_id'] = 2
            session['role'] = 'viewer'
            logger.info(f"Successful login for user: {username}, role=viewer")
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Handle form submissions
    if request.method == 'POST':
        logger.debug(f"POST request: {request.form}")
        if 'add_dinner' in request.form:
            description = request.form['description']
            amount = float(request.form['amount'])
            date = request.form['date']
            try:
                if session['role'] == 'admin':
                    cursor.execute('INSERT INTO dinners (description, amount, date, created_at) VALUES (?, ?, ?, ?)',
                                   (description, amount, date, datetime.now()))
                    conn.commit()
                    logger.info(f"Dinner added: {description}, {amount}, {date}")
                    flash('Dinner added successfully.', 'success')
                else:
                    logger.warning("Unauthorized attempt to add dinner by non-admin")
                    flash('Unauthorized action.', 'danger')
            except Exception as e:
                logger.error(f"Add dinner error: {str(e)}")
                flash('Error adding dinner.', 'danger')

        elif 'set_budget' in request.form and session['role'] == 'admin':
            budget = float(request.form['budget'])
            try:
                cursor.execute('UPDATE budget SET amount = ? WHERE id = 1', (budget,))
                if cursor.rowcount == 0:
                    cursor.execute('INSERT INTO budget (id, amount) VALUES (1, ?)', (budget,))
                conn.commit()
                logger.info(f"Budget updated to: {budget}")
                flash('Budget updated successfully.', 'success')
            except Exception as e:
                logger.error(f"Set budget error: {str(e)}")
                flash('Error updating budget.', 'danger')

        elif 'reset_budget' in request.form and session['role'] == 'admin':
            new_budget = float(request.form['new_budget'])
            try:
                cursor.execute('INSERT INTO budget_history (amount, reset_date) SELECT amount, ? FROM budget WHERE id = 1', (datetime.now(),))
                cursor.execute('DELETE FROM dinners')
                cursor.execute('UPDATE budget SET amount = ? WHERE id = 1', (new_budget,))
                if cursor.rowcount == 0:
                    cursor.execute('INSERT INTO budget (id, amount) VALUES (1, ?)', (new_budget,))
                conn.commit()
                logger.info(f"Budget reset to: {new_budget}")
                flash('Budget reset successfully.', 'success')
            except Exception as e:
                logger.error(f"Reset budget error: {str(e)}")
                flash('Error resetting budget.', 'danger')

    # Fetch budget and dinner data
    cursor.execute('SELECT amount FROM budget WHERE id = 1')
    budget = cursor.fetchone()
    budget = budget['amount'] if budget else 0.0

    cursor.execute('SELECT SUM(amount) as total FROM dinners')
    total_spent = cursor.fetchone()['total'] or 0.0
    remaining = budget - total_spent

    cursor.execute('SELECT id, description, amount, date FROM dinners ORDER BY created_at DESC LIMIT 1')
    latest_dinner = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template('index.html', budget=budget, latest_dinner=latest_dinner, total_spent=total_spent,
                           remaining=remaining, role=session['role'], today=datetime.now().strftime('%Y-%m-%d'))

@app.route('/records', methods=['GET', 'POST'])
@login_required
def records():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch budget
    cursor.execute('SELECT amount FROM budget WHERE id = 1')
    budget = cursor.fetchone()
    budget = budget['amount'] if budget else 0.0

    # Handle filtering
    description_filter = request.form.get('description', '')
    date_from = request.form.get('date_from', '')
    date_to = request.form.get('date_to', '')

    query = 'SELECT id, description, amount, date FROM dinners WHERE 1=1'
    params = []

    if description_filter:
        query += ' AND description LIKE ?'
        params.append(f'%{description_filter}%')
    if date_from:
        query += ' AND date >= ?'
        params.append(date_from)
    if date_to:
        query += ' AND date <= ?'
        params.append(date_to)

    query += ' ORDER BY date DESC, created_at DESC'
    cursor.execute(query, params)
    dinners = cursor.fetchall()

    # Calculate weekly and monthly spending
    cursor.execute('SELECT SUM(amount) as total FROM dinners WHERE date >= ?', (datetime.now().strftime('%Y-%m-%d'),))
    week_spent = cursor.fetchone()['total'] or 0.0

    cursor.execute('SELECT SUM(amount) as total FROM dinners WHERE date >= ?', ((datetime.now().replace(day=1)).strftime('%Y-%m-%d'),))
    month_spent = cursor.fetchone()['total'] or 0.0

    threshold_alert = (budget - month_spent) < (budget * 0.2) if budget > 0 else False

    cursor.close()
    conn.close()

    return render_template('records.html', dinners=dinners, week_spent=week_spent, month_spent=month_spent,
                           description_filter=description_filter, date_from=date_from, date_to=date_to,
                           threshold_alert=threshold_alert, role=session['role'])

@app.route('/delete/<int:dinner_id>', methods=['POST'])
@login_required
def delete(dinner_id):
    if session['role'] != 'admin':
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('DELETE FROM dinners WHERE id = ?', (dinner_id,))
        conn.commit()
        logger.info(f"Dinner deleted: id={dinner_id}")
        flash('Dinner deleted successfully.', 'success')
    except Exception as e:
        logger.error(f"Delete dinner error: {str(e)}")
        flash('Error deleting dinner.', 'danger')
    cursor.close()
    conn.close()
    return redirect(url_for('index'))

@app.route('/export')
@login_required
def export():
    if session['role'] != 'admin':
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT description, amount, date, created_at FROM dinners ORDER BY date DESC')
    dinners = cursor.fetchall()
    cursor.close()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Description', 'Amount', 'Date', 'Created At'])
    for dinner in dinners:
        writer.writerow([dinner['description'], dinner['amount'], dinner['date'], dinner['created_at']])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='dinner_records.csv'
    )

if __name__ == '__main__':
    app.run(debug=True)
