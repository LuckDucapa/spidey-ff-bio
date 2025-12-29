import requests
import urllib3
import json
import base64
import time
from flask import Flask, request, jsonify, render_template_string, redirect
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

app = Flask(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 1. CONFIGURATION (ORIGINAL METHOD)
# ==========================================
KEY = b'Yg&tc%DEuh6%Zc^8'
IV = b'6oyZDr22E3ychjM%'
API_BASE = "https://raihan-access-to-jwt.vercel.app/token"

HEADERS_GAME = {
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)',
    'Connection': 'Keep-Alive',
    'Expect': '100-continue',
    'X-Unity-Version': '2018.4.11f1', 
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB53',
    'Content-Type': 'application/x-www-form-urlencoded',
}

SERVERS = {
    "IND": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
    "BD":  "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo",
    "SG":  "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo",
    "BR":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "US":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "EU":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
}

# ==========================================
# 2. PROTOBUF SETUP
# ==========================================
try:
    _sym_db = _symbol_database.Default()
    BIO_PROTO = b'\n\ndata.proto\"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage\"\x0e\n\x0c\x45mptyMessageb\x06proto3'
    _builder.BuildMessageAndEnumDescriptors(_descriptor_pool.Default().AddSerializedFile(BIO_PROTO), globals())
    _builder.BuildTopDescriptorsAndMessages(_descriptor_pool.Default().AddSerializedFile(BIO_PROTO), 'bio_pb2', globals())
    BioData = _sym_db.GetSymbol('Data')
    EmptyMessage = _sym_db.GetSymbol('EmptyMessage')
except:
    pass

# ==========================================
# 3. HELPERS
# ==========================================
def encrypt_aes(data_bytes):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)

def extract_info(token):
    try:
        if not token: return "Unknown", "Unknown"
        payload = token.split('.')[1]
        payload += '=' * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get('sub') or data.get('uid') or "Unknown", data.get('nickname') or data.get('name') or "Unknown Player"
    except:
        return "Unknown", "Unknown Player"

def get_jwt_from_api(uid=None, password=None, access_token=None):
    params = {}
    if uid and password: params = {'uid': uid, 'password': password}
    elif access_token: params = {'access_token': access_token}
    
    try:
        r = requests.get(API_BASE, params=params, timeout=15)
        data = r.json()
        if data.get('token'): return data['token'], None
        elif data.get('access_token'): return data['access_token'], None
        return None, "Invalid Credentials"
    except:
        return None, "Auth API Error"

# ==========================================
# 4. CORE LOGIC
# ==========================================
def update_bio_request(jwt_token, bio_text, region):
    url = SERVERS.get(region, SERVERS["IND"])
    try:
        data = BioData()
        data.field_2 = 17 
        data.field_5.CopyFrom(EmptyMessage())
        data.field_6.CopyFrom(EmptyMessage())
        data.field_8 = bio_text
        data.field_9 = 1
        data.field_11.CopyFrom(EmptyMessage())
        data.field_12.CopyFrom(EmptyMessage())

        encrypted = encrypt_aes(data.SerializeToString())
        headers = HEADERS_GAME.copy()
        headers['Authorization'] = f'Bearer {jwt_token}'
        
        r = requests.post(url, headers=headers, data=encrypted, verify=False, timeout=10)
        return r.status_code
    except:
        return 500

# ==========================================
# 5. ROUTES
# ==========================================

# MAIN PAGE -> REDIRECT TO TOOL
@app.route('/')
def root():
    return """<script>window.location.replace('/security');</script>"""

# TOOL UI
@app.route('/security')
def secure_app():
    return render_template_string(HTML_TOOL)

# API DOCS PAGE
@app.route('/api')
def api_docs():
    return render_template_string(HTML_API_DOCS)

# TOOL EXECUTION (UI POST)
@app.route('/exec', methods=['POST'])
def execute_web():
    try:
        mode = request.form.get('mode')
        region = request.form.get('region')
        bio = request.form.get('bio')
        
        jwt_token = None
        err_msg = ""
        
        if mode == 'jwt':
            jwt_token = request.form.get('jwt')
            if not jwt_token: err_msg = "Missing JWT"
        elif mode == 'uid':
            jwt_token, err_msg = get_jwt_from_api(uid=request.form.get('uid'), password=request.form.get('pass'))
        elif mode == 'token':
            jwt_token, err_msg = get_jwt_from_api(access_token=request.form.get('access_token'))
            
        if not jwt_token:
            return jsonify({"ok": False, "msg": err_msg or "Invalid Credentials"})

        code = update_bio_request(jwt_token, bio, region)
        
        if code == 200:
            uid, name = extract_info(jwt_token)
            return jsonify({
                "ok": True, 
                "msg": "Bio Updated Successfully", 
                "uid": uid, 
                "name": name,
                "credit": "@spidey_abd"
            })
        elif code == 401:
            return jsonify({"ok": False, "msg": "Session Expired"})
        else:
            return jsonify({"ok": False, "msg": "An Error Occurred"})
    except:
        return jsonify({"ok": False, "msg": "Server Error"})

# PUBLIC API ENDPOINT
@app.route('/long_bio', methods=['GET'])
def public_api():
    try:
        bio = request.args.get('bio')
        reg = request.args.get('region', 'IND')
        jwt = request.args.get('jwt')
        acc = request.args.get('access') or request.args.get('access_token')
        uid = request.args.get('uid')
        pwd = request.args.get('password')
        
        if not bio: return jsonify({"status":"error","message":"No Bio Provided"})
        
        final_jwt, err = None, None
        if jwt: final_jwt = jwt
        elif acc: final_jwt, err = get_jwt_from_api(access_token=acc)
        elif uid and pwd: final_jwt, err = get_jwt_from_api(uid=uid, password=pwd)
        
        if not final_jwt: return jsonify({"status":"error","message":err or "No Auth"})
        
        code = update_bio_request(final_jwt, bio, reg)
        if code == 200:
            uid_val, name_val = extract_info(final_jwt)
            return jsonify({
                "status": "success", 
                "message": "Bio Updated", 
                "uid": uid_val, 
                "name": name_val,
                "credit": "@spidey_abd"
            })
        else:
            return jsonify({"status": "error", "message": "Failed", "code": code})
    except:
        return jsonify({"status": "error", "message": "Server Error"})

# ==========================================
# UI: API DOCUMENTATION PAGE (/api)
# ==========================================
HTML_API_DOCS = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bio Injector API Docs</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #0D0F18; --glass: rgba(20, 22, 36, 0.6); --border: rgba(138, 116, 255, 0.2); --text: #E9E7F9; --accent: #4F46E5; }
        body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; margin: 0; padding: 20px; line-height: 1.6; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { background: linear-gradient(90deg, #4F46E5, #A78BFA); -webkit-background-clip: text; color: transparent; font-size: 32px; }
        .card { background: var(--glass); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; word-wrap: break-word; }
        .method { display: inline-block; background: #4F46E5; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; margin-right: 10px; }
        code { background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; color: #22D3EE; font-family: monospace; font-size: 13px; }
        pre { background: #050505; padding: 15px; border-radius: 8px; overflow-x: auto; border: 1px solid var(--border); color: #ccc; white-space: pre-wrap; word-wrap: break-word; }
        .param { color: #A78BFA; font-weight: bold; }
        .footer { margin-top: 40px; text-align: center; color: #666; font-size: 14px; border-top: 1px solid var(--border); padding-top: 20px; }
        .footer a { color: var(--accent); text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>API Documentation</h1>
        <p>Welcome to the Bio Injector Public API. Use the endpoint <code>/long_bio</code> to update Free Fire bios programmatically.</p>
        
        <div class="card">
            <h3>Method 1: Direct JWT</h3>
            <p><span class="method">GET</span> <code>/long_bio</code></p>
            <pre><span class="host-url"></span>/long_bio?bio={bio}&jwt={jwt_token}</pre>
        </div>

        <div class="card">
            <h3>Method 2: Access Token</h3>
            <p><span class="method">GET</span> <code>/long_bio</code></p>
            <pre><span class="host-url"></span>/long_bio?bio={bio}&access={access_token}</pre>
        </div>

        <div class="card">
            <h3>Method 3: UID & Password</h3>
            <p><span class="method">GET</span> <code>/long_bio</code></p>
            <pre><span class="host-url"></span>/long_bio?bio={bio}&uid={uid}&password={pass}</pre>
        </div>

        <div class="card">
            <h3>Response Example</h3>
            <pre>
{
  "status": "success",
  "message": "Bio Updated",
  "uid": "123456789",
  "name": "ProPlayer",
  "credit": "@spidey_abd"
}</pre>
        </div>
        
        <div class="footer">
            Owner: ƬᏞㅤSᴘɪᴅʏㅤꪶꫂ<br>
            Telegram: <a href="https://t.me/spidey_abd" target="_blank">@spidey_abd</a><br>
            Email: <a href="mailto:spidyabd07@gmail.com">spidyabd07@gmail.com</a>
        </div>
    </div>
    
    <script>
        // Automatically inject current host URL
        document.querySelectorAll('.host-url').forEach(el => {
            el.innerText = window.location.origin;
        });
    </script>
</body>
</html>
"""

# ==========================================
# UI: MAIN TOOL (/security)
# ==========================================
HTML_TOOL = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Free Fire - Bio Injector</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        :root {
            --base-bg: #0D0F18;
            --glass-bg: rgba(20, 22, 36, 0.4);
            --glass-border: rgba(138, 116, 255, 0.15);
            --text-primary: #E9E7F9;
            --text-secondary: #A09CB9;
            --accent-glow: #22D3EE;
            --accent-gradient-start: #4F46E5;
            --accent-gradient-end: #A78BFA;
            --danger-glow: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.1);
            --border-radius-md: 16px;
            --border-radius-sm: 12px;
            --safe-area-padding: 16px;
        }

        /* --- Layout --- */
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Inter', sans-serif; -webkit-tap-highlight-color: transparent; outline: none; }
        
        body {
            background-color: var(--base-bg); color: var(--text-primary);
            min-height: 100vh; width: 100vw; overflow-x: hidden; overflow-y: auto;
            position: relative; display: flex; flex-direction: column; align-items: center;
        }

        /* Background */
        body::before, body::after {
            content: ''; position: fixed; width: 60vmax; height: 60vmax; border-radius: 50%;
            background: radial-gradient(circle, var(--accent-gradient-start), transparent 60%);
            opacity: 0.15; filter: blur(100px); z-index: -2; animation: drift 25s infinite alternate ease-in-out;
        }
        body::after {
            background: radial-gradient(circle, var(--accent-gradient-end), transparent 60%);
            bottom: -20vmax; left: -20vmax; animation-delay: -5s;
        }
        @keyframes drift { 0% { transform: translate(-20%, -20%); } 100% { transform: translate(20%, 20%); } }

        /* Splash */
        #splash-screen {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: var(--base-bg); display: flex; justify-content: center; align-items: center;
            z-index: 9999; animation: fadeOutSplash 0.5s ease-out 1.5s forwards;
        }
        .splash-orb {
            width: 100px; height: 100px; border-radius: 50%;
            background: radial-gradient(circle, var(--accent-gradient-end), var(--accent-gradient-start));
            box-shadow: 0 0 20px var(--accent-gradient-end); animation: pulse 2s infinite ease-in-out;
        }
        @keyframes fadeOutSplash { to { opacity: 0; visibility: hidden; } }
        @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.1); } }

        /* Header */
        .header {
            position: fixed; top: 0; width: 100%; padding: 14px var(--safe-area-padding);
            display: flex; align-items: center; justify-content: center; z-index: 100;
            background: rgba(13, 15, 24, 0.6); backdrop-filter: blur(12px); border-bottom: 1px solid var(--glass-border);
        }
        .app-title {
            font-size: 22px; font-weight: 700; color: transparent;
            background-image: linear-gradient(45deg, var(--accent-gradient-end), var(--accent-gradient-start));
            background-clip: text; -webkit-background-clip: text;
        }

        /* Container */
        .main { width: 100%; display: flex; flex-direction: column; align-items: center; padding: 80px 16px 20px 16px; }

        .glass-panel {
            background: var(--glass-bg); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--glass-border); border-radius: var(--border-radius-md);
            box-shadow: 0 8px 32px 0 rgba(0,0,0,0.37); padding: 24px; width: 100%; max-width: 450px;
        }

        /* Tabs */
        .tabs { display: flex; background: rgba(0,0,0,0.2); padding: 4px; border-radius: 12px; margin-bottom: 20px; border: 1px solid var(--glass-border); }
        .tab { flex: 1; text-align: center; padding: 10px; font-size: 13px; font-weight: 600; color: var(--text-secondary); cursor: pointer; border-radius: 8px; transition: 0.3s; }
        .tab.active { background: rgba(255,255,255,0.1); color: var(--text-primary); box-shadow: 0 0 10px rgba(138, 116, 255, 0.2); }

        /* Inputs */
        input, select {
            width: 100%; background: rgba(0,0,0,0.3); border: 1px solid var(--glass-border);
            color: var(--text-primary); padding: 14px; border-radius: var(--border-radius-sm);
            margin-bottom: 10px; font-size: 14px; transition: 0.3s;
        }
        input:focus { border-color: var(--accent-glow); box-shadow: 0 0 10px rgba(34, 211, 238, 0.1); }

        /* Editor */
        .editor-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; padding: 0 4px; }
        .editor-label { font-size: 12px; font-weight: bold; color: var(--text-secondary); letter-spacing: 1px; }
        .clr-btn {
            background: var(--danger-bg); color: var(--danger-glow);
            border: 1px solid var(--danger-glow); padding: 4px 12px;
            border-radius: 6px; font-size: 11px; font-weight: 700;
            cursor: pointer; letter-spacing: 0.5px;
        }
        textarea {
            width: 100%; height: 90px; background: rgba(0,0,0,0.3);
            border: 1px solid var(--glass-border); color: var(--text-primary);
            padding: 14px; border-radius: var(--border-radius-sm);
            font-size: 15px; resize: none; display: block;
        }

        /* Preview */
        .preview-box {
            margin-top: 15px; margin-bottom: 20px;
            background: rgba(0,0,0,0.5); padding: 15px;
            border-radius: var(--border-radius-sm); border: 1px dashed var(--glass-border);
            min-height: 45px; font-weight: bold; font-size: 14px; word-wrap: break-word; color: #fff;
        }

        /* Toolbar */
        .toolbar { margin-bottom: 15px; }
        .colors { display: flex; gap: 8px; overflow-x: auto; padding-bottom: 5px; margin-bottom: 10px; scrollbar-width: none; }
        .c-dot { width: 32px; height: 32px; border-radius: 8px; flex-shrink: 0; cursor: pointer; border: 1px solid rgba(255,255,255,0.2); }
        .grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 6px; }
        .sym-btn {
            background: rgba(255,255,255,0.05); color: var(--text-secondary);
            border: 1px solid var(--glass-border); height: 38px;
            display: flex; align-items: center; justify-content: center;
            font-size: 14px; cursor: pointer; border-radius: 8px; transition: 0.2s;
        }
        .sym-btn:active { background: var(--accent-glow); color: #000; }

        /* Button */
        .glass-button {
            width: 100%; padding: 16px; font-size: 16px; font-weight: 700;
            border: none; border-radius: var(--border-radius-sm); cursor: pointer;
            color: white; background-image: linear-gradient(45deg, var(--accent-gradient-start), var(--accent-gradient-end));
            box-shadow: 0 4px 15px rgba(79, 70, 229, 0.4); transition: 0.3s;
        }
        .glass-button:disabled { opacity: 0.7; cursor: not-allowed; }

        /* Footer */
        .footer { margin-top: 30px; text-align: center; color: var(--text-secondary); font-size: 13px; line-height: 1.8; padding-bottom: 20px; }
        .footer a { color: var(--accent-glow); text-decoration: none; font-weight: bold; }
        .footer a:hover { text-decoration: underline; }

        /* Overlay */
        #overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(13, 15, 24, 0.95); backdrop-filter: blur(20px);
            z-index: 2000; display: flex; flex-direction: column; justify-content: center; align-items: center;
            opacity: 0; visibility: hidden; transition: 0.3s;
        }
        #overlay.active { opacity: 1; visibility: visible; }
        .res-icon { font-size: 80px; margin-bottom: 20px; transform: scale(0); transition: 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275); }
        #overlay.active .res-icon { transform: scale(1); }
        .res-title { font-size: 28px; font-weight: 800; margin-bottom: 10px; }
        .res-body { text-align: center; color: var(--text-secondary); line-height: 1.6; }
        .res-body strong { color: white; font-size: 16px; }
        .credit { margin-top: 15px; font-size: 12px; color: #666; font-family: monospace; }

        .success .res-icon { color: var(--accent-glow); text-shadow: 0 0 30px var(--accent-glow); }
        .success .res-title { color: var(--accent-glow); }
        .error .res-icon { color: var(--danger-glow); text-shadow: 0 0 30px var(--danger-glow); }
        .error .res-title { color: var(--danger-glow); }
        
        .hidden { display: none !important; }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(() => document.getElementById('splash-screen').style.display = 'none', 1500);
        });

        function setMode(m) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById('t-'+m).classList.add('active');
            ['jwt','token','uid'].forEach(x => document.getElementById('i-'+x).classList.add('hidden'));
            document.getElementById('i-'+m).classList.remove('hidden');
        }

        function ins(txt) {
            const el = document.getElementById('bio');
            if(el.value.length + txt.length > 250) return;
            const [s, e] = [el.selectionStart, el.selectionEnd];
            el.value = el.value.substring(0, s) + txt + el.value.substring(e);
            el.focus(); el.selectionStart = el.selectionEnd = s + txt.length;
            render();
        }

        function render() {
            let t = document.getElementById('bio').value;
            t = t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            t = t.replace(/\[([0-9A-Fa-f]{6})\]/g, '</span><span style="color:#$1">');
            t = t.replace(/\[c\]/gi, '</span>'); 
            t = t.replace(/\[b\]/gi, '<b>').replace(/\[\/b\]/gi, '</b>');
            t = t.replace(/\[i\]/gi, '<i>').replace(/\[\/i\]/gi, '</i>');
            t = t.replace(/\[u\]/gi, '<u>').replace(/\[\/u\]/gi, '</u>');
            t = t.replace(/\[s\]/gi, '<s>').replace(/\[\/s\]/gi, '</s>');
            document.getElementById('prev').innerHTML = '<span>' + t + '</span>';
        }

        function clearBio() { document.getElementById('bio').value = ""; render(); }

        function showResult(type, title, html) {
            const ov = document.getElementById('overlay');
            ov.className = type + " active";
            document.getElementById('res-icon').className = type === 'success' ? "fas fa-check-circle res-icon" : "fas fa-times-circle res-icon";
            document.getElementById('res-title').innerText = title;
            document.getElementById('res-body').innerHTML = html;
            setTimeout(() => { ov.className = ""; }, 3000);
        }

        async function run(e) {
            e.preventDefault();
            const btn = document.getElementById('btn');
            btn.disabled = true; btn.innerText = "Processing...";
            
            const fd = new FormData(document.getElementById('form'));
            let mode = 'token'; // Default
            if(!document.getElementById('i-jwt').classList.contains('hidden')) mode = 'jwt';
            if(!document.getElementById('i-uid').classList.contains('hidden')) mode = 'uid';
            fd.append('mode', mode);

            try {
                const r = await fetch('/exec', { method: 'POST', body: fd });
                const d = await r.json();
                
                if(d.ok) {
                    showResult('success', 'SUCCESS', `
                        Name: <strong>${d.name}</strong><br>
                        UID: <strong>${d.uid}</strong><br>
                        Status: Success<br>
                        Bio Updated Successfully!<br>
                        <div class="credit">Credit: ${d.credit}</div>
                    `);
                } else {
                    showResult('error', 'FAILED', `An Error Occurred<br>${d.msg}`);
                }
            } catch {
                showResult('error', 'ERROR', "Connection Failed");
            }
            btn.disabled = false; btn.innerText = "UPDATE BIO";
        }
    </script>
</head>
<body>
    <div id="splash-screen"><div class="splash-orb"></div></div>

    <!-- RESULT OVERLAY -->
    <div id="overlay">
        <i id="res-icon" class="fas fa-check-circle res-icon"></i>
        <div id="res-title" class="res-title">SUCCESS</div>
        <div id="res-body" class="res-body"></div>
    </div>

    <div class="header">
        <div class="app-title">BIO INJECTOR</div>
    </div>
    
    <div class="main">
        <div class="glass-panel">
            <div class="tabs">
                <div id="t-token" class="tab active" onclick="setMode('token')">TOKEN</div>
                <div id="t-jwt" class="tab" onclick="setMode('jwt')">JWT</div>
                <div id="t-uid" class="tab" onclick="setMode('uid')">UID</div>
            </div>

            <form id="form" onsubmit="run(event)">
                <select name="region">
                    <option value="IND" selected>INDIA (IND)</option>
                    <option value="BD">BANGLADESH (BD)</option>
                    <option value="SG">SINGAPORE (SG)</option>
                    <option value="BR">BRAZIL (BR)</option>
                    <option value="US">USA (NA)</option>
                    <option value="EU">EUROPE (EU)</option>
                </select>

                <div id="i-token"><input type="text" name="access_token" placeholder="Access Token"></div>
                <div id="i-jwt" class="hidden"><input type="text" name="jwt" placeholder="JWT String"></div>
                <div id="i-uid" class="hidden"><input type="text" name="uid" placeholder="UID"><input type="text" name="pass" placeholder="Password"></div>

                <div class="toolbar">
                    <div class="colors">
                        <div class="c-dot" style="background:#FF0000" onclick="ins('[FF0000]')"></div>
                        <div class="c-dot" style="background:#00FF00" onclick="ins('[00FF00]')"></div>
                        <div class="c-dot" style="background:#0000FF" onclick="ins('[0000FF]')"></div>
                        <div class="c-dot" style="background:#FFFF00" onclick="ins('[FFFF00]')"></div>
                        <div class="c-dot" style="background:#00FFFF" onclick="ins('[00FFFF]')"></div>
                        <div class="c-dot" style="background:#FF00FF" onclick="ins('[FF00FF]')"></div>
                        <div class="c-dot" style="background:#FFA500" onclick="ins('[FFA500]')"></div>
                        <div class="c-dot" style="background:#800080" onclick="ins('[800080]')"></div>
                        <div class="c-dot" style="background:#FFFFFF" onclick="ins('[FFFFFF]')"></div>
                    </div>
                    <div class="grid">
                        <div class="sym-btn" onclick="ins('Ⓥ')">Ⓥ</div>
                        <div class="sym-btn" onclick="ins('★')">★</div>
                        <div class="sym-btn" onclick="ins('♛')">♛</div>
                        <div class="sym-btn" onclick="ins('⚡')">⚡</div>
                        <div class="sym-btn" onclick="ins('✿')">✿</div>
                        <div class="sym-btn" onclick="ins('🔥')">🔥</div>
                        <div class="sym-btn" onclick="ins('ff')">ff</div>
                        <div class="sym-btn" onclick="ins('✈')">✈</div>
                        <div class="sym-btn" onclick="ins('☠')">☠</div>
                        <div class="sym-btn" onclick="ins('☂')">☂</div>
                        <div class="sym-btn" onclick="ins('☁')">☁</div>
                        <div class="sym-btn" onclick="ins('❄')">❄</div>
                        <div class="sym-btn" onclick="ins('☮')">☮</div>
                        <div class="sym-btn" onclick="ins('☯')">☯</div>
                        <div class="sym-btn" onclick="ins('♠')">♠</div>
                        <div class="sym-btn" onclick="ins('♣')">♣</div>
                        <div class="sym-btn" onclick="ins('♦')">♦</div>
                        <div class="sym-btn" onclick="ins('♪')">♪</div>
                        <div class="sym-btn" onclick="ins('♫')">♫</div>
                        <div class="sym-btn" onclick="ins('⚔')">⚔</div>
                        <div class="sym-btn" onclick="ins('⚓')">⚓</div>
                        <div class="sym-btn" onclick="ins('✓')">✓</div>
                        <div class="sym-btn" onclick="ins('❤')">❤</div>
                        <div class="sym-btn" onclick="ins('[b]')">[b]</div>
                    </div>
                </div>

                <div class="editor-header">
                    <span class="editor-label">BIO TEXT (Max 250)</span>
                    <button type="button" class="clr-btn" onclick="clearBio()">CLEAR</button>
                </div>
                
                <textarea id="bio" name="bio" placeholder="Type Bio Here..." maxlength="250" oninput="render()"></textarea>

                <div class="preview-box" id="prev"></div>

                <button id="btn" class="glass-button">UPDATE BIO</button>
            </form>
            
            <div class="footer">
                Owner: ƬᏞㅤSᴘɪᴅʏㅤꪶꫂ<br>
                Telegram: <a href="https://t.me/spidey_abd" target="_blank">@spidey_abd</a><br>
                Email: <a href="mailto:spidyabd07@gmail.com">spidyabd07@gmail.com</a>
            </div>
        </div>
    </div>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)