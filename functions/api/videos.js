// videos.js

// 🚨 API Endpoints
// Backend Functions Folder Path (functions/api/auth.js) အရ မှန်ကန်သော Path
const API_BASE_URL = '/api/auth'; 

// မျက်နှာပြင်ပြောင်းလဲရန် Function
function showPage(pageId) {
    ['login-page', 'register-page', 'profile-page', 'home-page'].forEach(id => {
        const page = document.getElementById(id);
        if (page) page.style.display = 'none';
    });
    
    const targetPage = document.getElementById(pageId);
    if (targetPage) targetPage.style.display = 'block';

    if (pageId === 'profile-page') {
        loadUserProfile();
    }
}

// စာမျက်နှာကို စတင်ချိန်တွင် Login အခြေအနေကို စစ်ဆေးရန်
async function checkLoginState() {
    const token = localStorage.getItem('token');
    if (!token) {
        showPage('login-page');
        return;
    }

    try {
        // Path ကို API_BASE_URL + '/profile' ဖြင့် ခေါ်သည်
        const response = await fetch(`${API_BASE_URL}/profile`, { 
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            const user = await response.json();
            localStorage.setItem('currentUser', JSON.stringify(user));
            document.getElementById('username-display').textContent = user.username;
            showPage('home-page');
        } else {
            handleLogout();
        }
    } catch (error) {
        console.error('Login state check failed:', error);
        handleLogout();
    }
}

// မှတ်ပုံတင်ရန်
async function handleRegister() {
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const msgDiv = document.getElementById('register-message');
    msgDiv.textContent = '';

    if (!username || !password) {
        msgDiv.textContent = 'အသုံးပြုသူအမည်နှင့် လျှို့ဝှက်နံပါတ် ဖြည့်သွင်းပါ။';
        return;
    }

    try {
        // Path ကို API_BASE_URL + '/register' ဖြင့် ခေါ်သည်
        const response = await fetch(`${API_BASE_URL}/register`, { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            alert("မှတ်ပုံတင်ခြင်း အောင်မြင်ပါသည်။ ကျေးဇူးပြု၍ ဝင်ရောက်ပါ။");
            document.getElementById('login-username').value = username;
            document.getElementById('login-password').value = password;
            showPage('login-page');
        } else {
            msgDiv.textContent = data.error || 'API call failed.'; 
        }
    } catch (error) {
        msgDiv.textContent = 'API ခေါ်ဆိုမှု မအောင်မြင်ပါ။ (Backend/Network Error)';
    }
}

// Login ဝင်ရန်
async function handleLogin() {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const msgDiv = document.getElementById('login-message');
    msgDiv.textContent = '';

    try {
        // Path ကို API_BASE_URL + '/login' ဖြင့် ခေါ်သည်
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok && data.token) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('currentUser', JSON.stringify(data.user)); 
            document.getElementById('username-display').textContent = data.user.username;
            alert('ဝင်ရောက်ခြင်း အောင်မြင်ပါသည်။');
            showPage('home-page');
        } else {
            msgDiv.textContent = data.error || 'Login မအောင်မြင်ပါ။';
        }
    } catch (error) {
        msgDiv.textContent = 'API ခေါ်ဆိုမှု မအောင်မြင်ပါ။ (Backend/Network Error)';
    }
}

// ထွက်ရန် (Logout)
function handleLogout() {
    localStorage.removeItem('token');
    localStorage.removeItem('currentUser');
    showPage('login-page');
    alert("ထွက်ခွာခြင်း အောင်မြင်ပါသည်။");
}

// Profile Data ကို တင်ရန်
function loadUserProfile() {
    const userString = localStorage.getItem('currentUser');
    if (!userString) {
        handleLogout();
        return;
    }
    
    const user = JSON.parse(userString);
    
    document.getElementById('profile-username').textContent = user.username;
    document.getElementById('profile-last-login').textContent = user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'N/A';
    document.getElementById('profile-registered-date').textContent = user.registeredAt ? new Date(user.registeredAt).toLocaleDateString() : 'N/A';
}

// Global scope တွင် Functions များ အလုပ်လုပ်စေရန်
window.handleRegister = handleRegister;
window.handleLogin = handleLogin;
window.showPage = showPage;
window.handleLogout = handleLogout;
window.loadUserProfile = loadUserProfile;

// DOMContentLoaded တွင် စတင်ရန်
document.addEventListener('DOMContentLoaded', checkLoginState);
  
