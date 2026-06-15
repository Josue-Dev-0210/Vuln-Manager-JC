import sqlite3, os

RUTA_BD = os.path.join(os.path.dirname(__file__), 'vulnerabilities.db')

def obtain_conection():
    conection = sqlite3.connect(RUTA_BD)
    conection.row_factory = sqlite3.Row
    return conection

def initialize_bd():
    conection = obtain_conection()
    cursor = conection.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve TEXT,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            score REAL,
            category TEXT,
            system TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            date_reg TEXT DEFAULT (datetime('now','localtime')),
            notes TEXT
        )
    ''')
    cursor.execute('SELECT COUNT(*) as total FROM vulnerabilities')
    total = cursor.fetchone()['total']
    if total == 0:
        cursor.execute('''
            INSERT INTO vulnerabilities
                (cve, title, description, severity, score, category, system, status, date_reg, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            'CVE-2026-0001',
            'Example SQL Injection vulnerability',
            'Una vulnerabilidad de ejemplo para probar la aplicación.',
            'high',
            9.1,
            'injection',
            'web-server-01',
            'pending',
            '2026-06-15',
            'Validar las entradas de usuario y parametrizar las consultas SQL.'
        ))
    conection.commit()
    conection.close()