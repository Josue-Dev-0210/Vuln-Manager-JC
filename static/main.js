const URL_API = '/api';

let idEditing = null;
let filters = {
    search: '',
    severity: '',
    status: '',
    category: '',
};

const tableBody = document.getElementById('table-body');
const entrySearch = document.getElementById('entry-search');
const severityFilter = document.getElementById('severity-filter');
const statusFilter = document.getElementById('status-filter');
const categoryFilter = document.getElementById('category-filter');
const msgForm = document.getElementById('msg-form');
const titleForm = document.getElementById('title-form');

function showView(nameView) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
    const viewElement = document.getElementById(`${nameView}-view`);
    if (viewElement) {
        viewElement.classList.add('active');
    }
    const buttonElement = document.querySelector(`[data-view="${nameView}"]`);
    if (buttonElement) {
        buttonElement.classList.add('active');
    }
}

document.querySelectorAll('.view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        if (view == 'add') cleanForm();
        showView(view);
        if (view == 'list') chargeVulnerability();
        if (view == 'dashboard') chargeStadistics();
    });
});

async function chargeStadistics() {
    try {
        const answer = await fetch(`${URL_API}/stadistics`);
        const stadistics = await answer.json();

        document.getElementById('num-total').textContent = stadistics.total;
        document.getElementById('num-critical').textContent = stadistics.by_severity['critical'] || 0;
        document.getElementById('num-high').textContent = stadistics.by_severity['high'] || 0;
        document.getElementById('num-medium').textContent = stadistics.by_severity['medium'] || 0;
        document.getElementById('num-low').textContent = stadistics.by_severity['low'] || 0;
        document.getElementById('num-cvss').textContent = stadistics.average_cvss;

        renderGraphicStatus(stadistics.by_status, stadistics.total);
        renderGraphicCategory(stadistics.by_category);
    } catch (error) {
        console.error('Error charging statistics:', error);
    }
}

function renderGraphicStatus(byStatus, total) {
    const container = document.getElementById('graphic-status');
    container.innerHTML = '';
    const colors = {
        pending: '#7c6f9a',
        in_progress: '#818cf8',
        mitigated: '#10b981',
        accepted: '#f59e0b'
    };

    const labels = {
        pending: 'Pending',
        in_progress: 'In progress',
        mitigated: 'Mitigated',
        accepted: 'Accepted',
    };

    const wrap = document.createElement('div');
    wrap.className = 'graphic-wrap-bar';

    Object.entries(labels).forEach(([key, label]) => {
        const quantity = byStatus[key] || 0;
        const percentage = total > 0 ? (quantity / total) * 100 : 0;

        wrap.innerHTML += `
            <div class="graphic-item-bar">
                <span class="graphic-label-bar">${label}</span>
                <div class="graphic-track-bar">
                    <div class="graphic-fill-bar" style="width:${percentage}%;background:${colors[key]}"></div>
                </div>
                <span class="graphic-count-bar">${quantity}</span>
            </div>
            `;
    });
    container.appendChild(wrap);
}

function renderGraphicCategory(byCategory) {
    const container = document.getElementById('graphic-category');
    container.innerHTML = '';
    if (!byCategory.length) {
        container.innerHTML = '<p style="color:var(--gray);font-size:12px">no data</p>';
        return;
    }

    const max = byCategory[0].quantity;
    const wrap = document.createElement('div');
    wrap.className = 'graphic-wrap-bar';

    byCategory.forEach(item => {
        const percentage = (item.quantity / max) * 100;
        wrap.innerHTML += `
            <div class="graphic-item-bar">
                <span class="graphic-label-bar">${item.category || 'other'}</span>
                <div class="graphic-track-bar">
                    <div class="graphic-fill-bar" style="width:${percentage}%;background:var(--violet)"></div>
                </div>
                <span class="graphic-count-bar">${item.quantity}</span>
            </div>
            `;
    });
    container.appendChild(wrap);
}

async function chargeVulnerability() {
    const params = new URLSearchParams();
    if (filters.search) params.append('search', filters.search);
    if (filters.severity) params.append('severity', filters.severity);
    if (filters.status) params.append('status', filters.status);
    if (filters.category) params.append('category', filters.category);

    try {
        const answer = await fetch(`${URL_API}/vulnerabilities?${params}`);
        const list = await answer.json();
        renderTable(list);
    } catch (error) {
        console.error('Error loading vulnerabilities:', error);
    }
}

function renderTable(list) {
    tableBody.innerHTML = '';
    if (!list.length) {
        tableBody.innerHTML = `
        <tr>
            <td colspan="8" style="text-align:center;padding:32px;color:var(--gray)">
            no vulnerabilities reported
            </td>
        </tr>
        `;
        return;
    }

    list.forEach(vuln => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td style="color:var(--accent)">${vuln.cve || '-'}</td>
            <td style="color:var(--text);max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${vuln.title}">${vuln.title}</td>
            <td><span class="badge-severity ${vuln.severity}">${vuln.severity.toUpperCase()}</span></td>
            <td style="color:var(--text2)">${vuln.score || '-'}</td>
            <td style="color:var(--text2)">${vuln.category || '-'}</td>
            <td><span class="badge-status ${vuln.status}">${vuln.status.replace('_', ' ')}</span></td>
            <td style="color:var(--gray)">${(vuln.date_reg || '').slice(0, 10)}</td>
            <td>
                <div class="td-actions">
                    <button class="edit-btn" data-id="${vuln.id}">edit</button>
                    <button class="delete-btn" data-id="${vuln.id}">delete</button>
                </div>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

tableBody.addEventListener('click', async e => {
    const editBtn = e.target.closest('.edit-btn');
    const deleteBtn = e.target.closest('.delete-btn');

    if (editBtn) {
        const id = parseInt(editBtn.dataset.id);
        await uploadToEdit(id);
    }

    if (deleteBtn) {
        const id = parseInt(deleteBtn.dataset.id);
        if (confirm('Delete this vulnerability?')) {
            await deleteVulnerability(id);
        }
    }
})


async function uploadToEdit(id) {
    try {
        const answer = await fetch(`${URL_API}/vulnerabilities`);
        const list = await answer.json();
        const vuln = list.find(v => v.id === id);
        if (!vuln) return;

        idEditing = id;
        titleForm.textContent = 'Edit vulnerability';

        document.getElementById('cve-field').value = vuln.cve || '';
        document.getElementById('title-field').value = vuln.title || '';
        document.getElementById('severity-field').value = vuln.severity || '';
        document.getElementById('score-field').value = vuln.score || '';
        document.getElementById('category-field').value = vuln.category || '';
        document.getElementById('system-field').value = vuln.system || '';
        document.getElementById('status-field').value = vuln.status || 'pending';
        document.getElementById('date-field').value = vuln.date_reg || '';
        document.getElementById('description-field').value = vuln.description || '';
        document.getElementById('notes-field').value = vuln.notes || '';

        showView('add');
    } catch (error) {
        console.error('Error uploading to edit: ', error);
    }
}

async function deleteVulnerability(id) {
    try {
        await fetch(`${URL_API}/vulnerabilities/${id}`, { method: 'DELETE' });
        chargeVulnerability();
        chargeStadistics();
    } catch (error) {
        console.error('Error deleted:', error);
    }
}

function cleanForm() {
    idEditing = null;
    titleForm.textContent = 'Report vulnerabilities';
    ['cve-field','title-field','score-field','system-field','date-field','description-field','notes-field'].forEach(id => {
        document.getElementById(id).value = '';
    });
    document.getElementById('severity-field').value = '';
    document.getElementById('category-field').value = '';
    document.getElementById('status-field').value = 'pending';
    msgForm.className = 'hidden';
}

function showMsg(text, type) {
    msgForm.textContent = text;
    msgForm.className = type;
    setTimeout(() => { msgForm.className = 'hidden'; }, 3000);
}

document.getElementById('save-btn').addEventListener('click', async () => {
    const title = document.getElementById('title-field').value.trim();
    const severity = document.getElementById('severity-field').value;

    if (!title || !severity) {
        showMsg('Title and Severity are required.', 'error');
        return;
    }

    const datas = {
        cve: document.getElementById('cve-field').value.trim(),
        title, description: document.getElementById('description-field').value.trim(),
        severity, score: parseFloat(document.getElementById('score-field').value) || 0,
        category: document.getElementById('category-field').value,
        system: document.getElementById('system-field').value.trim(),
        status: document.getElementById('status-field').value,
        date_reg: document.getElementById('date-field').value,
        notes: document.getElementById('notes-field').value.trim(),
    };

    try {
        const method = idEditing ? 'PUT' : 'POST';
        const url = idEditing
            ? `${URL_API}/vulnerabilities/${idEditing}`
            : `${URL_API}/vulnerabilities`;
        await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(datas),
        });

        showMsg(
            idEditing ? 'Vulnerability updated.' : 'Vulnerability registered.',
            'success'
        );
        cleanForm();
        chargeStadistics();

    } catch (error) {
        console.error('Error saving vulnerability. verify the server', 'error');
    }
});

document.getElementById('cancel-btn').addEventListener('click', () => {
    cleanForm();
    showView('list');
    chargeVulnerability();
});

entrySearch.addEventListener('input', e => {
    filters.search = e.target.value;
    chargeVulnerability();
});

severityFilter.addEventListener('change', e => {
    filters.severity = e.target.value;
    chargeVulnerability();
});

statusFilter.addEventListener('change', e => {
    filters.status = e.target.value;
    chargeVulnerability();
});

categoryFilter.addEventListener('change', e => {
    filters.category = e.target.value;
    chargeVulnerability();
});

document.getElementById('export-pdf-btn').addEventListener('click', () => {
    window.open(`${URL_API}/export/pdf`, '_blank');
});

chargeStadistics();