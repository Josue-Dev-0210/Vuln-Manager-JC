# Vuln Manager JC

A lightweight vulnerability management platform built with Flask and SQLite for tracking, organizing, and reporting security vulnerabilities.

# Features

* Create, update and delete vulnerability records
* CVE tracking support
* CVSS score management
* Severity classification (Critical, High, Medium, Low)
* Status tracking (Pending, In Progress, Resolved)
* Category and system classification
* Advanced filtering and search
* Statistics dashboard
* PDF report generation
* SQLite database integration
* REST API endpoints
* 
# Tech Stack

# Backend

* Python 3
* Flask
* SQLite3
* Flask-CORS
* ReportLab

# Database

* SQLite

# Reporting

* PDF Export with ReportLab

## Project Structure

```text
Vuln-Manager-JC/
│
├── app.py
├── Database.py
├── vulnerabilities.db
│
├── templates/
│   └── index.html
│
├── static/
│   ├── css/
│   ├── js/
│   └── assets/
│
└── README.md
```

---

# Installation

# Clone the repository

```bash
git clone https://github.com/Josue-Dev-0210/Vuln-Manager-JC.git

cd Vuln-Manager-JC
```

# Create a virtual environment

Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

Windows

```bash
python -m venv venv

venv\Scripts\activate
```

# Install dependencies

```bash
pip install flask flask-cors reportlab
```

# Run the application

```bash
python app.py
```

# API Endpoints

# Get all vulnerabilities

```http
GET /api/vulnerabilities
```

Optional filters:

```http
?severity=high
&status=pending
&category=injection
&search=sql
```

---

# Create vulnerability

```http
POST /api/vulnerabilities
```

Example payload:

```json
{
  "cve": "CVE-2026-0002",
  "title": "Remote Code Execution",
  "description": "Critical RCE vulnerability",
  "severity": "critical",
  "score": 9.8,
  "category": "rce",
  "system": "production-server",
  "status": "pending",
  "notes": "Requires immediate patching"
}
```

---

# Update vulnerability

```http
PUT /api/vulnerabilities/{id}
```

---

# Delete vulnerability

```http
DELETE /api/vulnerabilities/{id}
```

---

# Statistics

```http
GET /api/stadistics
```

Returns:

* Total vulnerabilities
* Vulnerabilities by severity
* Vulnerabilities by status
* Top categories
* Average CVSS score

---

# Export PDF Report

```http
GET /api/export/pdf
```

Generates a downloadable PDF report containing all registered vulnerabilities.

---

## Vulnerability Model

| Field       | Description                 |
| ----------- | --------------------------- |
| id          | Unique identifier           |
| cve         | CVE reference               |
| title       | Vulnerability title         |
| description | Detailed description        |
| severity    | Critical, High, Medium, Low |
| score       | CVSS score                  |
| category    | Vulnerability category      |
| system      | Affected system             |
| status      | Current status              |
| date_reg    | Registration date           |
| notes       | Additional notes            |


# Future Improvements

* Authentication system
* User roles and permissions
* PostgreSQL support
* Vulnerability timeline
* CSV and Excel exports
* Dark mode
* Email notifications
* CVE API integration
* Docker deployment

---

# License

This project is licensed under the MIT License.

---

# Author

**Josué Cáceres**

Software Developer | Python | Flask | Web Development
