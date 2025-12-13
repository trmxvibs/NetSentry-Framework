import sqlite3

DB_NAME = "netsentry.db"

def init_db():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'Pending',
                result TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        ''')

        admin = cursor.execute("SELECT * FROM users WHERE username='admin'").fetchone()
        if not admin:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'password'))
            print("[+] Default User Created: admin / password")

        conn.commit()
        conn.close()
        print(f"[+] Database '{DB_NAME}' initialized successfully.")
    except Exception as e:
        print(f"[-] Database Error: {e}")

if __name__ == "__main__":
    init_db()