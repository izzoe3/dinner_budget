import os
import sqlite3
import psycopg2
from psycopg2 import pool
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from datetime import datetime, timedelta
import io
import csv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')  # Fallback for local testing
bcrypt = Bcrypt(app)

# Environment-based user credentials
try:
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
    if not all(USERS[key].get('password') for key in USERS):
        logger.error("Missing or invalid user credentials in environment variables")
        raise ValueError("User credentials are not properly configured")
except Exception as e:
    logger.error(f"Error initializing USERS: {e}")
    USERS = {}  # Fallback to prevent crashes

POSTGRES_URL = os.getenv('POSTGRES_URL')

# Connection pool for PostgreSQL
connection_pool = None
if os.getenv('VERCEL_ENV') == 'production' and POSTGRES_URL:
    try:
        connection_pool = psycopg2.pool.SimpleConnectionPool(
            1, 10, POSTGRES_URL  # Min 1, max 10 connections
        )
        logger.info("PostgreSQL connection pool initialized")
    except psycopg2.Error as e:
        logger.error(f"Failed to initialize connection pool: {e}")

def get_db_connection():
    if os.getenv('VERCEL_ENV') == 'production' and connection_pool:
        try:
            conn = connection_pool.getconn()
            conn.set_session(autocommit=False)
            return conn
        except psycopg2.Error as e:
            logger.error(f"Database connection error: {e}")
            raise
    else:
        try:
            conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'database.db'))
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            logger.error(f"SQLite connection error: {e}")
            raise

def release_db_connection(conn):
    if os.getenv('VERCEL_ENV') == 'production' and connection_pool:
        connection_pool.putconn(conn)
    else:
        conn.close()

# Database setup
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    if os.getenv('VERCEL_ENV') == 'production' and POSTGRES_URL:
        # Tables created in Supabase SQL Editor
        pass
    else:
        cursor.execute('CREATE TABLE IF NOT EXISTS budget (id INTEGER PRIMARY KEY, amount REAL NOT NULL)')
        cursor.execute('CREATE TABLE IF NOT EXISTS dinners (id INTEGER PRIMARY KEY AUTOINCREMENT, description TEXT NOT NULL, amount REAL NOT NULL, date TEXT NOT NULL)')
        cursor.execute('CREATE TABLE IF NOT EXISTS archived_dinners (id INTEGER PRIMARY KEY AUTOINCREMENT, description TEXT NOT NULL, amount REAL NOT NULL, date TEXT NOT NULL, archive_date TEXT NOT NULL)')
        cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, role TEXT NOT NULL)')
        cursor.execute('INSERT OR IGNORE INTO budget (id, amount) VALUES (1, 0)')
        conn.commit()
    release_db_connection(conn)

try:
    init_db()
except Exception as e:
    logger.error(f"Database initialization error: {e}")

def get_placeholder(conn):
    """Return appropriate placeholder for the database type."""
    if isinstance(conn, sqlite3.Connection):
        return '?'
    return '%s'

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
        conn = get_db_connection()
        cursor = conn.cursor()
        placeholder = get_placeholder(conn)
        try:
            cursor.execute(f'SELECT role FROM users WHERE id = {placeholder}', (session['user_id'],))
            role = cursor.fetchone()
            if not role or role[0] != 'admin':
                flash('Access denied: Admin privileges required.', 'danger')
                return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Admin check error: {e}")
            flash('Database error during authorization.', 'danger')
            return redirect(url_for('index'))
        finally:
            release_db_connection(conn)
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            if not username or not password:
                flash('Username and password are required.', 'danger')
                logger.warning("Empty username or password in login attempt")
                return render_template('login.html')
            
            user = USERS.get(username)
            if user and user.get('password') and bcrypt.check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['role'] = user['role']
                flash('Login successful!', 'success')
                logger.info(f"Successful login for user: {username}")
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password.', 'danger')
                logger.warning(f"Failed login attempt for username: {username}")
        return render_template('login.html')
    except Exception as e:
        logger.error(f"Login route error: {e}")
        flash('An error occurred during login. Please try again.', 'danger')
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('You have been logged out.', 'success')
    logger.info("User logged out")
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    conn = get_db_connection()
    cursor = conn.cursor()
    placeholder = get_placeholder(conn)

    try:
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
                            cursor.execute(f'UPDATE budget SET amount = {placeholder} WHERE id = 1', (budget,))
                            conn.commit()
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
                                    cursor.execute(f'INSERT INTO dinners (description, amount, date) VALUES ({placeholder}, {placeholder}, {placeholder})', 
                                                 (description, amount, date))
                                    conn.commit()
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
                                    cursor.execute(f'UPDATE dinners SET description = {placeholder}, amount = {placeholder}, date = {placeholder} WHERE id = {placeholder}', 
                                                 (description, amount, date, dinner_id))
                                    conn.commit()
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
                            cursor.execute(f'INSERT INTO archived_dinners (description, amount, date, archive_date) SELECT description, amount, date, {placeholder} FROM dinners', (archive_date,))
                            cursor.execute('DELETE FROM dinners')
                            cursor.execute(f'UPDATE budget SET amount = {placeholder} WHERE id = 1', (new_budget,))
                            conn.commit()
                            flash('Budget reset and dinners archived successfully.', 'success')
                    except ValueError:
                        flash('Invalid new budget amount.', 'danger')

        # Fetch data
        cursor.execute(f'SELECT amount FROM budget WHERE id = 1')
        budget_row = cursor.fetchone()
        budget = float(budget_row[0]) if budget_row else 0.0

        cursor.execute(f'SELECT id, description, amount, date FROM dinners ORDER BY date DESC LIMIT 1')
        latest_dinner = cursor.fetchone()

        cursor.execute(f'SELECT SUM(amount) as total FROM dinners')
        total_spent_row = cursor.fetchone()
        total_spent = float(total_spent_row[0]) if total_spent_row[0] is not None else 0.0

        remaining = budget - total_spent

    except Exception as e:
        logger.error(f"Index route error: {e}")
        flash('Database error occurred.', 'danger')
        budget = 0.0
        latest_dinner = None
        total_spent = 0.0
        remaining = 0.0
    finally:
        release_db_connection(conn)

    return render_template('index.html', budget=budget, latest_dinner=latest_dinner, total_spent=total_spent, 
                         remaining=remaining, role=session.get('role'), today=datetime.now().strftime('%Y-%m-%d'))

@app.route('/records', methods=['GET', 'POST'])
@login_required
def records():
    conn = get_db_connection()
    cursor = conn.cursor()
    placeholder = get_placeholder(conn)

    try:
        # Initialize filters
        description_filter = request.form.get('description', '') if request.method == 'POST' else ''
        date_from = request.form.get('date_from', '') if request.method == 'POST' else ''
        date_to = request.form.get('date_to', '') if request.method == 'POST' else ''

        # Build query
        query = 'SELECT id, description, amount, date FROM dinners WHERE 1=1'
        params = []
        if description_filter:
            query += f' AND description {"LIKE" if isinstance(conn, sqlite3.Connection) else "ILIKE"} {placeholder}'
            params.append(f'%{description_filter}%')
        if date_from:
            try:
                datetime.strptime(date_from, '%Y-%m-%d')
                query += f' AND date >= {placeholder}'
                params.append(date_from)
            except ValueError:
                flash('Invalid start date format.', 'danger')
        if date_to:
            try:
                datetime.strptime(date_to, '%Y-%m-%d')
                query += f' AND date <= {placeholder}'
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
                                cursor.execute(f'UPDATE dinners SET description = {placeholder}, amount = {placeholder}, date = {placeholder} WHERE id = {placeholder}', 
                                             (description, amount, date, dinner_id))
                                conn.commit()
                                flash('Dinner updated successfully.', 'success')
                            except ValueError:
                                flash('Invalid date format.', 'danger')
                    except ValueError:
                        flash('Invalid dinner amount.', 'danger')

        # Fetch dinners with filters
        cursor.execute(query, params)
        dinners = cursor.fetchall()

        # Spending summary
        today = datetime.now()
        week_start = (today - timedelta(days=today.weekday())).strftime('%Y-%m-%d')
        month_start = today.replace(day=1).strftime('%Y-%m-%d')
        cursor.execute(f'SELECT SUM(amount) as total FROM dinners WHERE date >= {placeholder}', (week_start,))
        week_spent_row = cursor.fetchone()
        week_spent = float(week_spent_row[0]) if week_spent_row[0] is not None else 0.0

        cursor.execute(f'SELECT SUM(amount) as total FROM dinners WHERE date >= {placeholder}', (month_start,))
        month_spent_row = cursor.fetchone()
        month_spent = float(month_spent_row[0]) if month_spent_row[0] is not None else 0.0

        # Budget threshold check
        cursor.execute(f'SELECT amount FROM budget WHERE id = 1')
        budget_row = cursor.fetchone()
        budget = float(budget_row[0]) if budget_row else 0.0

        cursor.execute(f'SELECT SUM(amount) as total FROM dinners')
        total_spent_row = cursor.fetchone()
        total_spent = float(total_spent_row[0]) if total_spent_row[0] is not None else 0.0

        remaining = budget - total_spent
        threshold_alert = remaining < (budget * 0.2) and budget > 0

    except Exception as e:
        logger.error(f"Records route error: {e}")
        flash('Database error occurred.', 'danger')
        dinners = []
        week_spent = 0.0
        month_spent = 0.0
        threshold_alert = False
    finally:
        release_db_connection(conn)

    return render_template('records.html', dinners=dinners, role=session.get('role'), 
                         week_spent=week_spent, month_spent=month_spent, threshold_alert=threshold_alert,
                         description_filter=description_filter, date_from=date_from, date_to=date_to)

@app.route('/delete/<int:dinner_id>', methods=['POST'])
@admin_required
def delete(dinner_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    placeholder = get_placeholder(conn)
    try:
        cursor.execute(f'DELETE FROM dinners WHERE id = {placeholder}', (dinner_id,))
        conn.commit()
        flash('Dinner deleted successfully.', 'success')
    except Exception as e:
        logger.error(f"Delete route error: {e}")
        flash('Error deleting dinner.', 'danger')
    finally:
        release_db_connection(conn)
    return redirect(request.referrer or url_for('index'))

@app.route('/export', methods=['GET'])
@admin_required
def export():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT description, amount, date FROM dinners ORDER BY date DESC')
        dinners = cursor.fetchall()
    except Exception as e:
        logger.error(f"Export route error: {e}")
        flash('Error exporting data.', 'danger')
        dinners = []
    finally:
        release_db_connection(conn)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Description', 'Amount (RM)', 'Date'])
    for dinner in dinners:
        writer.writerow([dinner[0], f"{float(dinner[1]):.2f}", dinner[2]])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'dinner_records_{datetime.now().strftime("%Y%m%d")}.csv'
    )

if __name__ == "__main__":
    app.run(debug=True)
else:
    application = app  # For WSGI compatibility
