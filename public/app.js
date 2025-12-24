const API_URL = 'http://localhost:3000/api';
let currentUser = null;

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('menu-btn')?.addEventListener('click', openMenu);
    document.getElementById('close-menu')?.addEventListener('click', closeMenu);
    document.getElementById('menu-overlay')?.addEventListener('click', closeMenu);
    document.getElementById('logout-btn')?.addEventListener('click', handleLogout);
    document.querySelectorAll('.menu-item[data-screen]').forEach(item => {
        item.addEventListener('click', () => { switchView(item.dataset.screen); closeMenu(); });
    });
});

function handleLogin(e) {
    e.preventDefault();
    currentUser = { name: 'Demo User', role: 'admin' };
    document.getElementById('login-screen').classList.remove('active');
    document.getElementById('dashboard-screen').classList.add('active');
    loadJobs();
}

function handleLogout() {
    document.getElementById('dashboard-screen').classList.remove('active');
    document.getElementById('login-screen').classList.add('active');
    closeMenu();
}

function openMenu() { document.getElementById('side-menu').classList.add('open'); document.getElementById('menu-overlay').classList.add('open'); }
function closeMenu() { document.getElementById('side-menu').classList.remove('open'); document.getElementById('menu-overlay').classList.remove('open'); }

function switchView(view) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(view + '-view')?.classList.add('active');
    document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
    document.querySelector('[data-screen="'+view+'"]')?.classList.add('active');
}

function loadJobs() {
    const jobs = [
        { id: 1, number: '4026', name: 'WASATCH ELECTRIC', location: '9000 S WEST JORDAN', color: 'orange' },
        { id: 2, number: '4011', name: 'SMITH RANCH', location: '1234 SMITH RANCH RD', color: 'green' },
        { id: 3, number: '4050', name: 'MIDTOWN VILLAGE', location: '5678 MIDTOWN BLVD', color: 'purple' }
    ];
    document.getElementById('jobs-list').innerHTML = jobs.map(j => 
        '<div class="job-card crew-'+j.color+'"><div class="job-number">#'+j.number+'</div><div class="job-name">'+j.name+'</div><div class="job-location">📍 '+j.location+'</div></div>'
    ).join('');
}
