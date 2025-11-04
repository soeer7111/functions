// functions/api/auth.js

// 🚨 Password Hashing 
// (Cloudflare Worker ၏ Built-in crypto ကိုအသုံးပြုထားသည်)
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    // SHA-256 Hashing ကို သုံးထားသည်
    const hashBuffer = await crypto.subtle.digest('SHA-256', data); 
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// 🚨 Register Logic (Path: /api/auth/register)
async function handleRegister(request, USERS) { 
    const { username, password } = await request.json();
    if (!username || !password) return new Response(JSON.stringify({ error: 'Username and password required.' }), { status: 400 });

    // Key များကို စာလုံးအသေးဖြင့် သိမ်းဆည်းခြင်း
    const userKey = `user:${username.toLowerCase()}`;
    // KV Database (USERS) တွင် ရှိမရှိ စစ်ဆေးခြင်း
    if (await USERS.get(userKey)) {
        return new Response(JSON.stringify({ error: 'Username already exists.' }), { status: 409 });
    }

    const hashedPassword = await hashPassword(password);
    const user = {
        username,
        password: hashedPassword, 
        registeredAt: new Date().toISOString(),
        lastLogin: null
    };

    // USERS KV Namespace တွင် သိမ်းဆည်းခြင်း
    await USERS.put(userKey, JSON.stringify(user));
    return new Response(JSON.stringify({ message: 'Registration successful.' }), { status: 201 });
}

// 🚨 Login Logic (Path: /api/auth/login)
async function handleLogin(request, USERS) {
    const { username, password } = await request.json();
    if (!username || !password) return new Response(JSON.stringify({ error: 'Username and password required.' }), { status: 400 });

    const userKey = `user:${username.toLowerCase()}`;
    const userString = await USERS.get(userKey);
    if (!userString) return new Response(JSON.stringify({ error: 'Invalid credentials.' }), { status: 401 });

    const user = JSON.parse(userString);
    const hashedPasswordAttempt = await hashPassword(password);

    if (user.password !== hashedPasswordAttempt) {
        return new Response(JSON.stringify({ error: 'Invalid credentials.' }), { status: 401 });
    }

    // JWT Token ကို အယောင်ပြ ထုတ်ပေးခြင်း (Production အတွက် တကယ့် JWT သုံးရမည်)
    const token = `fake-jwt-token-for-${username.toLowerCase()}-${Date.now()}`; 
    
    // Last Login ကို Update လုပ်ခြင်း
    user.lastLogin = new Date().toISOString();
    await USERS.put(userKey, JSON.stringify(user));
    
    // Response ပေးရန် Password ကို ဖယ်ထုတ်ခြင်း
    const { password: _, ...userWithoutPass } = user;
    return new Response(JSON.stringify({ token, user: userWithoutPass }), { status: 200 });
}

// 🚨 Profile Logic (Path: /api/auth/profile)
async function handleProfile(request, USERS) {
    const token = request.headers.get('Authorization')?.replace('Bearer ', '');
    if (!token) return new Response(JSON.stringify({ error: 'Unauthorized.' }), { status: 401 });

    // Token မှ username ကို ရယူခြင်း (Fake Token ကို ပြန်ဖော်ထုတ်ခြင်း)
    const usernameMatch = token.match(/fake-jwt-token-for-(.*?)-/);
    const username = usernameMatch ? usernameMatch[1] : null;

    if (!username) return new Response(JSON.stringify({ error: 'Invalid token.' }), { status: 401 });
    
    const userKey = `user:${username}`;
    const userString = await USERS.get(userKey);
    if (!userString) return new Response(JSON.stringify({ error: 'User not found.' }), { status: 404 });

    const user = JSON.parse(userString);
    const { password: _, ...userWithoutPass } = user;
    
    return new Response(JSON.stringify(userWithoutPass), { status: 200 });
}


// 🚨 Worker/Function ၏ Main Handler
// KV Binding (USERS) ကို ဤနေရာမှ env.USERS အနေဖြင့် ရယူသည်
export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);

    // KV Binding ကို env မှ ယူပြီး Helper functions များဆီ ပေးပို့
    const USERS = env.USERS; 

    // Cloudflare Pages Functions သည် /api/auth သို့ ရောက်ပြီးသော Path ကို စစ်သည်
    if (url.pathname.endsWith('/register')) { 
        return handleRegister(request, USERS); 
    } else if (url.pathname.endsWith('/login')) {
        return handleLogin(request, USERS); 
    } else if (url.pathname.endsWith('/profile')) {
        return handleProfile(request, USERS);
    }

    return new Response(JSON.stringify({ message: "Auth API not found" }), { status: 404 });
}
