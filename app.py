from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from Database import obtain_conection, initialize_bd
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
import io, datetime

app = Flask(__name__)
CORS(app)

initialize_bd()

@app.route('/')
def begin():
    return render_template('index.html')

@app.route('/api/vulnerabilities', methods=['GET'])
def obtain_vulnerabilities():
    conection = obtain_conection()
    cursor = conection.cursor()

    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    category = request.args.get('category', '')
    search = request.args.get('search', '')

    consult = 'SELECT * FROM vulnerabilities WHERE 1=1'
    parameters = []

    if severity:
        consult += ' AND severity = ?'
        parameters.append(severity)
    if status:
        consult += ' AND status = ?'
        parameters.append(status)
    if category:
        consult += ' AND category = ?'
        parameters.append(category)
    if search:
        consult += ' AND (title LIKE ? OR description LIKE ? OR system LIKE ?)'
        parameters.extend([f'%{search}%'] * 3)

    consult += ' ORDER BY date_reg DESC'

    cursor.execute(consult, parameters)
    rows = cursor.fetchall()
    conection.close()

    return jsonify([dict(f) for f in rows])


@app.route('/api/vulnerabilities', methods=['POST'])
def add_vulnerabilities():
    datas = request.json
    conection = obtain_conection()
    cursor = conection.cursor()

    cursor.execute('''
        INSERT INTO vulnerabilities
            (cve, title, description, severity, score, category, system, status, date_reg, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datas.get('cve', ''),
                datas.get('title'),
                datas.get('description', ''),
                datas.get('severity'),
                datas.get('score', 0),
                datas.get('category', ''),
                datas.get('system', ''),
                datas.get('status', 'pending'),
                datas.get('date_reg', ''),
                datas.get('notes', ''),
            ))
    
    conection.commit()
    nuevo_id = cursor.lastrowid
    conection.close()

    return jsonify({ 'id': nuevo_id, 'mensaje': 'Vulnerabilidad registrada'}), 201

@app.route('/api/vulnerabilities/<int:id>', methods=['PUT'])
def actualizar_vulnerabilidades(id): 
    datas = request.json
    conection = obtain_conection()
    cursor = conection.cursor()

    cursor.execute('''
        UPDATE vulnerabilities SET
            cve = ?, title = ?, description = ?, severity = ?,
            score = ?, category = ?, system = ?,
            status = ?, date_reg = ?, notes = ?
            WHERE id = ?
            ''', (
                datas.get('cve', ''),
                datas.get('title'),
                datas.get('description', ''),
                datas.get('severity'),
                datas.get('score', 0),
                datas.get('category', ''),
                datas.get('system', ''),
                datas.get('status', 'pending'),
                datas.get('date_reg', ''),
                datas.get('notes', ''),
                id,
            ))
    
    conection.commit()
    conection.close()
    return jsonify({ 'mensaje': 'Vulnerabilidad actualizada'})

@app.route('/api/vulnerabilities/<int:id>', methods=['DELETE'])
def eliminar_vulnerabilidad(id):
    conection = obtain_conection()
    cursor = conection.cursor()

    cursor.execute('DELETE FROM vulnerabilities WHERE id = ?', (id,))
    conection.commit()
    conection.close()

    return jsonify({ 'mensaje': 'Vulnerabilidad eliminada'})

@app.route('/api/stadistics', methods=['GET'])
def obtener_estadisticas():
    conection = obtain_conection()
    cursor = conection.cursor()

    cursor.execute('SELECT COUNT(*) as total FROM vulnerabilities')
    total = cursor.fetchone()['total']

    cursor.execute('SELECT severity, COUNT(*) as quantity FROM vulnerabilities GROUP BY severity')
    by_severity = { f['severity']: f['quantity'] for f in cursor.fetchall()}

    cursor.execute('SELECT status, COUNT(*) as quantity FROM vulnerabilities GROUP BY status')
    by_status = { f['status']: f['quantity'] for f in cursor.fetchall()}

    cursor.execute('SELECT category, COUNT(*) as quantity FROM vulnerabilities GROUP BY category ORDER BY quantity DESC LIMIT 5')
    by_category = [{ 'category': f['category'], 'quantity': f['quantity'] } for f in cursor.fetchall()]

    cursor.execute('SELECT AVG(score) as average FROM vulnerabilities WHERE score > 0')
    average = cursor.fetchone()['average'] or 0

    conection.close()

    return jsonify({
        'total': total,
        'by_severity': by_severity,
        'by_status': by_status,
        'by_category': by_category,
        'average_cvss': round(average, 1),
    })

@app.route('/api/export/pdf')
def export_pdf():
    conection = obtain_conection()
    cursor = conection.cursor()
    cursor.execute('SELECT * FROM vulnerabilities ORDER BY severity, date_reg DESC')
    vuln = [dict(f) for f in cursor.fetchall()]
    conection.close()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), topMargin=1.5*cm, bottomMargin=1.5*cm)
    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle('title', fontSize=16, textColor=colors.HexColor('#8b5cf6'), spaceAfter=6)
    sub_style = ParagraphStyle('sub', fontSize=9, textColor=colors.HexColor('#7c6f9a'), spaceAfter=16)

    elements.append(Paragraph('Vulnerabilities Report', title_style))
    elements.append(Paragraph(
        f'Generated: {datetime.datetime.now().strftime("%d/%m/%y %H:%M")} · Total: {len(vuln)} records',
        sub_style
    ))

    headers = ['CVE', 'Title', 'Severity', 'CVSS', 'Category', 'System', 'Status', 'Date']
    rows = [headers]

    colors_severity = {
        'critial': colors.HexColor('#ef4444'),
        'high': colors.HexColor('#f97316'),
        'medium': colors.HexColor('#f5930b'),
        'low': colors.HexColor('#10b981'),
    }

    for v in vuln:
        rows.append([
            v.get('cve') or '-',
            v.get('title', '')[:40],
            v.get('severity', '').upper(),
            str(v.get('score') or '-'),
            v.get('category') or '-',
            v.get('system') or '-',
            v.get('status', '').upper(),
            (v.get('date_reg') or '')[:10],
        ])

    table = Table(rows, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#211d2e')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#a78bfa')),
        ('FONTNAME', (0,0), (-1,-1), 'Courier'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('FONTSIZE', (0,1), (-1,-1), 8),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#17141f')),
        ('TEXTCOLOR', (0,1), (-1,-1), colors.HexColor('#ede9fe')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#17141f'), colors.HexColor('#1c1828')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#2e2840')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
    ]))


    elements.append(table)
    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'vulnerabilities_report_{datetime.datetime.now().strftime("%Y%m%d")}.pdf'
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)

    