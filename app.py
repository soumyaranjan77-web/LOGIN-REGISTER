from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
# A secret key is required to use sessions and flash messages in Flask
app.secret_key = 'super_secret_key_change_in_production'
DB_NAME = 'users.db'

def get_db_connection():
    """Creates and returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_NAME)
    # This allows us to access columns by name (e.g., user['email'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database table if it doesn't exist."""
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

# Initialize the database when the application starts
init_db()

@app.route('/')
def home():
    """Redirects to dashboard if logged in, otherwise to login page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Basic form validation
        if not email or not password:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        # Hash the password for basic security best practices
        hashed_password = generate_password_hash(password)

        # Attempt to insert into database
        try:
            with get_db_connection() as conn:
                conn.execute(
                    'INSERT INTO users (email, password) VALUES (?, ?)', 
                    (email, hashed_password)
                )
                conn.commit()
            
            # Show success message and redirect to login
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError:
            # IntegrityError occurs if the unique constraint on email is violated
            flash('Email already registered. Please login.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Ensure fields are not blank
        if not email or not password:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('login'))

        # Fetch the user matching the provided email from the database
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        # Check if user exists and the provided password matches the hashed password
        if user and check_password_hash(user['password'], password):
            # Create a session to keep the user logged in
            session['user_id'] = user['id']
            session['email'] = user['email']
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """Protected dashboard route."""
    # Ensure only logged-in users can reach here
    if 'user_id' not in session:
        flash('Please login to access the dashboard.', 'error')
        return redirect(url_for('login'))
    
    # Render dashboard template, passing the email stored in session
    return render_template('dashboard.html', email=session['email'])

@app.route('/logout')
def logout():
    """Logs out the user and clears the session."""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Run the Flask app on localhost (debug mode enables auto-reload)
    app.run(debug=True)
