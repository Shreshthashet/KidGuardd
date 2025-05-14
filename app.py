from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
socketio = SocketIO(app, async_mode='threading')

# --- Initialize Database ---
def init_db():
    conn = sqlite3.connect('kidguard.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('parent', 'child'))
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            activity TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# --- Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        conn = sqlite3.connect('kidguard.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND role = ?', (username, role))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user'] = username
            session['role'] = role
            if role == 'parent':
                return redirect(url_for('parent_dashboard'))
            else:
                return redirect(url_for('child_dashboard'))
        else:
            flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        if len(username) < 4:
            flash('Username must be at least 4 characters.')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('signup'))

        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"[0-9]", password) or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash('Password must include uppercase, lowercase, number, and symbol.')
            return redirect(url_for('signup'))

        try:
            hashed_password = generate_password_hash(password)
            conn = sqlite3.connect('kidguard.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))
            conn.commit()
            conn.close()
            flash('Signup successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/parent_dashboard')
def parent_dashboard():
    if 'user' not in session or session['role'] != 'parent':
        return redirect(url_for('login'))
    return render_template('parent_dashboard.html', username=session['user'])

@app.route('/child_dashboard')
def child_dashboard():
    if 'user' not in session or session['role'] != 'child':
        return redirect(url_for('login'))
    return render_template('child_dashboard.html', username=session['user'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# --- API to fetch past activities ---
@app.route('/fetch_activities')
def fetch_activities():
    if 'user' not in session or session['role'] != 'parent':
        return jsonify([])
    conn = sqlite3.connect('kidguard.db')
    c = conn.cursor()
    c.execute("SELECT username, activity, timestamp FROM activities ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    activities = [{'username': row[0], 'activity': row[1], 'timestamp': row[2]} for row in rows]
    return jsonify(activities)

# --- WebSocket Events ---
@socketio.on('send_alert')
def handle_send_alert(data):
    emit('alert', {'alert': 'Emergency alert from your child!'}, broadcast=True)

@socketio.on('activity')
def handle_activity(data):
    username = session.get('user', 'Unknown')
    activity = data.get('activity', 'Unknown')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save to database
    conn = sqlite3.connect('kidguard.db')
    c = conn.cursor()
    c.execute("INSERT INTO activities (username, activity, timestamp) VALUES (?, ?, ?)", (username, activity, timestamp))
    conn.commit()
    conn.close()

    # Send to all connected parents
    emit('activity', {'activity': f'{username} is browsing: {activity}', 'timestamp': timestamp}, broadcast=True)

# --- Start ---
if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)
