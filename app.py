import requests
import urllib3
import json
import base64
import time
import binascii
import jwt  # PyJWT
from flask import Flask, request, jsonify, render_template_string, redirect, make_response
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

# Try importing external protobufs if they exist (for Major Login)
try:
    import my_pb2
    import output_pb2
except ImportError:
    pass

app = Flask(__name__)
# Enable CORS for all routes
CORS(app)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# 1. CONFIGURATION & CONSTANTS
# ==========================================
KEY = b'Yg&tc%DEuh6%Zc^8'  # Same key in both scripts
IV = b'6oyZDr22E3ychjM%'   # Same IV in both scripts

# --- Legacy Config (For UI / long_bio) ---
API_BASE = "https://raihan-access-to-jwt.vercel.app/token"
HEADERS_GAME = {
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)',
    'Connection': 'Keep-Alive',
    'Expect': '100-continue',
    'X-Unity-Version': '2018.4.11f1', 
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB52',
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

# --- New Config (For /bio endpoint) ---
FREEFIRE_UPDATE_URL = "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo"
MAJOR_LOGIN_URL = "https://loginbp.ggblueshark.com/MajorLogin"
OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
FREEFIRE_VERSION = "OB52"

BIO_HEADERS = {
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

LOGIN_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION
}

# ==========================================
# 2. PROTOBUF SETUP
# ==========================================
# Dynamic BioData setup (Works for both legacy and new logic)
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
# 3. COMMON HELPERS
# ==========================================
def encrypt_aes(data_bytes):
    """Legacy helper"""
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)

def encrypt_data(data_bytes):
    """New helper (Identical logic)"""
    return encrypt_aes(data_bytes)

# ==========================================
# 4. LEGACY LOGIC (For UI & /long_bio)
# ==========================================
def extract_info_legacy(token):
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
# 5. NEW LOGIC (For /bio Endpoint)
# ==========================================
def get_name_region_from_reward(access_token):
    try:
        uid_url = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
        uid_headers ={
            "authority": "prod-api.reward.ff.garena.com",
            "method": "GET",
            "path": "/redemption/api/auth/inspect_token/",
            "scheme": "https",
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br",
            "access-token": access_token,
            "origin": "https://reward.ff.garena.com",
            "referer": "https://reward.ff.garena.com/",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
        uid_res = requests.get(uid_url, headers=uid_headers, verify=False)
        uid_data = uid_res.json()
        
        return uid_data.get("uid"), uid_data.get("name"), uid_data.get("region")
    except Exception as e:
        return None, None, None

def get_openid_from_shop2game(uid):
    if not uid: return None
    try:
        openid_url = "https://topup.pk/api/auth/player_id_login"
        openid_headers = { 
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://topup.pk",
            "Referer": "https://topup.pk/",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; RMX5070 Build/UKQ1.231108.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.157 Mobile Safari/537.36",
        }
        payload = {"app_id": 100067, "login_id": str(uid)}
        res = requests.post(openid_url, headers=openid_headers, json=payload, verify=False)
        data = res.json()
        return data.get("open_id")
    except Exception as e:
        return None

def decode_jwt_info(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        name = decoded.get("nickname")
        region = decoded.get("lock_region") 
        uid = decoded.get("account_id")
        return str(uid), name, region
    except:
        return None, None, None

def perform_major_login(access_token, open_id):
    # This requires my_pb2 and output_pb2 to be present in the directory
    try:
        import my_pb2
        import output_pb2
    except ImportError:
        print("Protobuf modules (my_pb2, output_pb2) not found. Major Login will fail.")
        return None

    platforms = [8, 3, 4, 6]
    for platform_type in platforms:
        try:
            game_data = my_pb2.GameData()
            game_data.timestamp = "2024-12-05 18:15:32"
            game_data.game_name = "free fire"
            game_data.game_version = 1
            game_data.version_code = "1.120.2"
            game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
            game_data.device_type = "Handheld"
            game_data.network_provider = "Verizon Wireless"
            game_data.connection_type = "WIFI"
            game_data.screen_width = 1280
            game_data.screen_height = 960
            game_data.dpi = "240"
            game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
            game_data.total_ram = 5951
            game_data.gpu_name = "Adreno (TM) 640"
            game_data.gpu_version = "OpenGL ES 3.0"
            game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
            game_data.ip_address = "172.190.111.97"
            game_data.language = "en"
            game_data.open_id = open_id
            game_data.access_token = access_token
            game_data.platform_type = platform_type
            game_data.field_99 = str(platform_type)
            game_data.field_100 = str(platform_type)

            serialized_data = game_data.SerializeToString()
            encrypted = encrypt_data(serialized_data)
            hex_encrypted = binascii.hexlify(encrypted).decode('utf-8')
            
            edata = bytes.fromhex(hex_encrypted)
            response = requests.post(MAJOR_LOGIN_URL, data=edata, headers=LOGIN_HEADERS, verify=False, timeout=10)

            if response.status_code == 200:
                data_dict = None
                try:
                    example_msg = output_pb2.Garena_420()
                    example_msg.ParseFromString(response.content)
                    data_dict = {field.name: getattr(example_msg, field.name) 
                                 for field in example_msg.DESCRIPTOR.fields 
                                 if field.name == "token"}
                except Exception:
                    pass
                if data_dict and "token" in data_dict:
                    return data_dict["token"]
        except Exception:
            continue
    return None

def perform_guest_login(uid, password):
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive"
    }
    try:
        resp = requests.post(OAUTH_URL, data=payload, headers=headers, timeout=10, verify=False)
        data = resp.json()
        if 'access_token' in data:
            return data['access_token'], data.get('open_id')
    except Exception as e:
        pass
    return None, None

def upload_bio_request_new(jwt_token, bio_text):
    try:
        data = BioData()
        data.field_2 = 17
        data.field_5.CopyFrom(EmptyMessage())
        data.field_6.CopyFrom(EmptyMessage())
        data.field_8 = bio_text
        data.field_9 = 1
        data.field_11.CopyFrom(EmptyMessage())
        data.field_12.CopyFrom(EmptyMessage())

        data_bytes = data.SerializeToString()
        encrypted = encrypt_data(data_bytes)

        headers = BIO_HEADERS.copy()
        headers["Authorization"] = f"Bearer {jwt_token}"

        resp = requests.post(FREEFIRE_UPDATE_URL, headers=headers, data=encrypted, timeout=20, verify=False)

        status_text = "Unknown"
        if resp.status_code == 200: status_text = "✅ Success"
        elif resp.status_code == 401: status_text = "❌ Unauthorized (Invalid JWT)"
        else: status_text = f"⚠️ Status {resp.status_code}"

        raw_hex = binascii.hexlify(resp.content).decode('utf-8')

        return {
            "status": status_text,
            "code": resp.status_code,
            "bio": bio_text,
            "server_response": raw_hex
        }
    except Exception as e:
        return {"status": f"Error: {str(e)}", "code": 500, "bio": bio_text, "server_response": "N/A"}

# ==========================================
# 6. ROUTES
# ==========================================

# --- MAIN PAGE -> REDIRECT TO TOOL ---
@app.route('/')
def root():
    return """<script>window.location.replace('/security');</script>"""

# --- TOOL UI ---
@app.route('/security')
def secure_app():
    return render_template_string(HTML_TOOL)

# --- API DOCS PAGE ---
@app.route('/api')
def api_docs():
    return render_template_string(HTML_API_DOCS)

# --- TOOL EXECUTION (UI POST - LEGACY) ---
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
            uid, name = extract_info_legacy(jwt_token)
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

# --- PUBLIC API ENDPOINT (LEGACY) ---
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
            uid_val, name_val = extract_info_legacy(final_jwt)
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

# --- NEW PUBLIC API ENDPOINT (/bio) ---
@app.route("/bio", methods=["GET", "POST"])
def combined_bio_upload():
    bio = request.args.get("bio") or request.form.get("bio")
    jwt_token = request.args.get("jwt") or request.form.get("jwt")
    uid = request.args.get("uid") or request.form.get("uid")
    password = request.args.get("pass") or request.form.get("pass")
    access_token = request.args.get("access") or request.form.get("access") or request.args.get("access_token")

    if not bio:
        return jsonify({"status": "❌ Error", "code": 400, "error": "Missing 'bio' parameter"}), 400

    final_jwt = None
    login_method = "Direct JWT"
    
    final_open_id = None
    final_access_token = None
    final_uid = None
    final_name = None
    final_region = None

    if jwt_token:
        final_jwt = jwt_token
        j_uid, j_name, j_region = decode_jwt_info(jwt_token)
        final_uid = j_uid
        final_name = j_name
        final_region = j_region
        
    elif uid and password:
        login_method = "UID/Pass Login"
        
        acc_token, login_openid = perform_guest_login(uid, password)
        
        if acc_token and login_openid:
            final_access_token = acc_token
            final_open_id = login_openid
            
            final_jwt = perform_major_login(final_access_token, final_open_id)
            
            if final_jwt:
                 j_uid, j_name, j_region = decode_jwt_info(final_jwt)
                 final_uid = j_uid
                 final_name = j_name
                 final_region = j_region
            else:
                 return jsonify({"status": "❌ JWT Generation Failed", "code": 500}), 500

        else:
            return jsonify({"status": "❌ Guest Login Failed (Check UID/Pass)", "code": 401}), 401

    elif access_token:
        login_method = "Access Token Login"
        final_access_token = access_token
        
        f_uid, f_name, f_region = get_name_region_from_reward(access_token)
        final_uid = f_uid
        final_name = f_name
        final_region = f_region

        if not final_uid:
            return jsonify({"status": "❌ Invalid Access Token", "code": 400}), 400

        final_open_id = get_openid_from_shop2game(final_uid)
        
        if final_open_id:
            final_jwt = perform_major_login(access_token, final_open_id)
        else:
            return jsonify({"status": "❌ Shop2Game OpenID Fetch Failed", "code": 400}), 400
    
    else:
        return jsonify({"status": "❌ Error", "code": 400, "error": "Provide JWT, or UID/Pass, or Access Token"}), 400

    if not final_jwt:
        return jsonify({"status": "❌ JWT Generation Failed", "code": 500}), 500

    result = upload_bio_request_new(final_jwt, bio)
    
    response_data = {
        "Credit": "@spidey_abd",
        "Join For More": "Telegram: @TubeGroww",
        "status": result["status"],
        "login_method": login_method,
        "code": result["code"],
        "bio": result["bio"],
        "uid": str(final_uid) if final_uid else None,
        "name": final_name,
        "region": final_region,
        "open_id": final_open_id,
        "access_token": final_access_token,
        "server_response": result["server_response"],
        "generated_jwt": final_jwt
    }

    response = make_response(jsonify(response_data))
    response.headers["Content-Type"] = "application/json"
    return response

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
        <p>Welcome to the Bio Injector Public API.</p>
        
        <h2>Standard API (Legacy)</h2>
        <div class="card">
            <p><span class="method">GET</span> <code>/long_bio</code></p>
            <pre><span class="host-url"></span>/long_bio?bio={bio}&jwt={jwt_token}</pre>
            <p>Also supports: <code>&access={token}</code> or <code>&uid={uid}&password={pass}</code></p>
        </div>

        <h2>Advanced API (New)</h2>
        <div class="card">
            <p><span class="method">GET/POST</span> <code>/bio</code></p>
            <p>Supports robust login methods (Reward, Major Login, Shop2Game).</p>
            <pre><span class="host-url"></span>/bio?bio={bio}&access_token={token}</pre>
        </div>

        <div class="footer">
            Owner: ƬᏞㅤSᴘɪᴅʏㅤꪶꫂ<br>
            Telegram: <a href="https://t.me/spidey_abd" target="_blank">@spidey_abd</a><br>
        </div>
    </div>
    
    <script>
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
            setTimeout(() => { ov.className = ""; }, 4000);
        }

        async function run(e) {
            e.preventDefault();
            const btn = document.getElementById('btn');
            btn.disabled = true; btn.innerText = "Processing...";
            
            // Gather data
            const fd = new FormData(document.getElementById('form'));
            
            // Using the /bio endpoint which supports auto-region & robust login
            try {
                // We use POST here to support your requirement:
                // It effectively sends data like: /bio?uid=...&pass=...&bio=... 
                // but via body to allow special characters and security.
                const r = await fetch('/bio', { method: 'POST', body: fd });
                const d = await r.json();
                
                // The new API returns 'code' (200 is success)
                if(d.code === 200) {
                    showResult('success', 'SUCCESS', `
                        Name: <strong>${d.name || 'Unknown'}</strong><br>
                        UID: <strong>${d.uid || 'Unknown'}</strong><br>
                        Region: <strong>${d.region || 'Auto-Detected'}</strong><br>
                        Login: <strong>${d.login_method || 'API'}</strong><br>
                        Status: Bio Updated<br>
                        <div class="credit">Credit: ${d.Credit || '@spidey_abd'}</div>
                    `);
                } else {
                    // Handle API errors
                    showResult('error', 'FAILED', `
                        Status: ${d.status}<br>
                        Code: ${d.code}<br>
                        ${d.error ? d.error : ''}
                    `);
                }
            } catch (err) {
                console.error(err);
                showResult('error', 'ERROR', "Connection Failed or Server Error");
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
                <!-- Region is auto-detected by the new API, but kept for UI consistency if needed later -->
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