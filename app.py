from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from functools import wraps
import sqlite3
import threading
import logging
import subprocess
import os
import re
from datetime import datetime
from database_setup import init_db
from fpdf import FPDF
from scanner_engine import scan_target, get_system_info

# --- CONFIGURATION ---
app = Flask(__name__)
app.secret_key = "NETSENTRY_EXEC_KEY_V29"
DB_NAME = "netsentry.db"

# Silence Logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Global Config
DISCORD_WEBHOOK = ""

# Initialize DB
init_db()

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# --- AUTH DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'logged_in' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# --- PROFESSIONAL PDF CLASS ---
class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'NET-SENTRY | CONFIDENTIAL SECURITY ASSESSMENT', 0, 1, 'C')
        self.line(10, 20, 200, 20)
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(220, 220, 220) # Grey background
        self.cell(0, 8, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Courier', '', 9) # Monospace for technical logs
        # Clean text (FPDF doesn't support Emojis, so we strip them)
        clean_body = body.encode('latin-1', 'replace').decode('latin-1')
        self.multi_cell(0, 5, clean_body)
        self.ln()

# --- AUTH ROUTES ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        conn.close()
        if user and user['password'] == p:
            session['logged_in'] = True
            session['user'] = u
            return redirect(url_for('index'))
        return render_template('login.html', error="ACCESS DENIED")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    conn = get_db()
    conn.execute("UPDATE users SET password=? WHERE username=?", (data.get('new_password'), session.get('user','admin')))
    conn.commit()
    conn.close()
    return jsonify({'status': 'Password Updated'})

# --- SYSTEM ROUTES ---
@app.route('/')
@login_required
def index():
    return render_template('dashboard.html')

@app.route('/api/me')
def my_info():
    return jsonify(get_system_info())

@app.route('/factory_reset', methods=['POST'])
@login_required
def factory_reset():
    conn = get_db()
    conn.execute('DELETE FROM scans')
    conn.execute('DELETE FROM sqlite_sequence WHERE name="scans"')
    conn.commit()
    conn.close()
    return jsonify({'status': 'System Wipe Complete'})

# --- SYSTEM BRIDGE ---
@app.route('/execute', methods=['POST'])
@login_required
def execute_command():
    cmd = request.json.get('cmd')
    blacklist = ["rm -rf", "format c:", ":(){ :|:& };:"]
    if any(b in cmd for b in blacklist): return jsonify({'output': '[-] COMMAND BLOCKED'})
    try:
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        output = process.stdout + process.stderr or "[i] Executed."
        return jsonify({'output': output})
    except Exception as e: return jsonify({'output': f'[-] Error: {str(e)}'})

# --- SCANNING ---
def background_scan(scan_id, domain, mode, custom_flags):
    conn = get_db()
    last = conn.execute('SELECT result FROM scans WHERE domain=? AND status="Completed" AND id<? ORDER BY id DESC LIMIT 1', (domain, scan_id)).fetchone()
    prev_res = last['result'] if last else None
    conn.close()
    
    result = scan_target(domain, mode, custom_flags, previous_result=prev_res, webhook=DISCORD_WEBHOOK)
    
    conn = sqlite3.connect(DB_NAME)
    conn.execute("UPDATE scans SET status='Completed', result=? WHERE id=?", (result, scan_id))
    conn.commit()
    conn.close()

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    data = request.json
    domain = data.get('domain')
    mode = data.get('mode', 'basic')
    custom_flags = data.get('custom_flags', '')
    if not domain: return jsonify({'error': 'Target required'}), 400
    
    conn = get_db()
    cur = conn.execute("INSERT INTO scans (domain, status, result) VALUES (?, ?, ?)", (domain, 'Running...', 'Initializing...'))
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    threading.Thread(target=background_scan, args=(scan_id, domain, mode, custom_flags)).start()
    return jsonify({'msg': 'Scan Initiated'})

@app.route('/api/scans')
def get_scans():
    conn = get_db()
    scans = conn.execute('SELECT * FROM scans ORDER BY id DESC').fetchall()
    conn.close()
    return jsonify([dict(s) for s in scans])

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_scan(id):
    conn = get_db()
    conn.execute('DELETE FROM scans WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'deleted'})

# --- [NEW] ADVANCED PDF GENERATOR ---
@app.route('/download/<int:id>')
@login_required
def download(id):
    conn = get_db()
    scan = conn.execute('SELECT * FROM scans WHERE id=?', (id,)).fetchone()
    conn.close()
    
    if scan:
        try:
            pdf = PDFReport()
            pdf.add_page()
            
            # Extract Risk Score for Header
            raw_text = scan['result']
            score_match = re.search(r"RISK SCORE: (\d+)/100", raw_text)
            score = score_match.group(1) if score_match else "N/A"
            
            # 1. Executive Summary
            pdf.chapter_title(f"EXECUTIVE SUMMARY: {scan['domain']}")
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 6, f"Target: {scan['domain']}", 0, 1)
            pdf.cell(0, 6, f"Scan Date: {scan['timestamp']}", 0, 1)
            pdf.cell(0, 6, f"Risk Assessment Score: {score}/100", 0, 1)
            pdf.ln(10)
            
            # 2. Smart Parsing (Split by Modules)
            # Splits text whenever a new module starts with [*]
            sections = raw_text.split('\n[*]')
            
            # Print Introduction (First part before first [*])
            if sections[0].strip():
                pdf.chapter_body(sections[0])
            
            # Print Modules
            for section in sections[1:]:
                lines = section.split('\n')
                title = lines[0].strip().replace(':', '').replace(']', '') # Clean Title
                content = '\n'.join(lines[1:])
                
                # Add Chapter
                pdf.chapter_title(f"MODULE: {title}")
                pdf.chapter_body(content)
            
            filename = f"Report_{scan['id']}.pdf"
            pdf.output(filename)
            return send_file(filename, as_attachment=True)
            
        except Exception as e:
            return f"Report Generation Failed: {str(e)}", 500
            
    return "Scan not found", 404

if __name__ == "__main__":
    print("[+] Net-Sentry v29.0 Online.")
    app.run(debug=True, port=5000)