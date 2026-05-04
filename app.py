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

try:
    import my_pb2
    import output_pb2
except ImportError:
    pass

app = Flask(__name__)
CORS(app)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

KEY = b'Yg&tc%DEuh6%Zc^8'
IV = b'6oyZDr22E3ychjM%'

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
    "BD":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "SG":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "BR":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "US":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "EU":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
}

FREEFIRE_UPDATE_URL = "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo"
MAJOR_LOGIN_URL = "https://loginbp.ggpolarbear.com/MajorLogin"
OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
FREEFIRE_VERSION = "OB53"

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

try:
    _sym_db = _symbol_database.Default()
    BIO_PROTO = b'\n\ndata.proto\"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage\"\x0e\n\x0c\x45mptyMessageb\x06proto3'
    _builder.BuildMessageAndEnumDescriptors(_descriptor_pool.Default().AddSerializedFile(BIO_PROTO), globals())
    _builder.BuildTopDescriptorsAndMessages(_descriptor_pool.Default().AddSerializedFile(BIO_PROTO), 'bio_pb2', globals())
    BioData = _sym_db.GetSymbol('Data')
    EmptyMessage = _sym_db.GetSymbol('EmptyMessage')
except:
    pass

def encrypt_aes(data_bytes):
    """Legacy helper"""
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)

def encrypt_data(data_bytes):
    """New helper (Identical logic)"""
    return encrypt_aes(data_bytes)

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
    def fetch_open_id(acc_token):
        try:
            uid_url = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
            uid_headers = {
                "access-token": acc_token,
                "origin": "https://reward.ff.garena.com",
                "referer": "https://reward.ff.garena.com/",
                "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
            }
            uid_res = requests.get(uid_url, headers=uid_headers, verify=False, timeout=10).json()
            extracted_uid = uid_res.get("uid")
            
            if not extracted_uid: 
                return None

            openid_url = "https://topup.pk/api/auth/player_id_login"
            openid_headers = { 
                "Content-Type": "application/json",
                "Origin": "https://topup.pk",
                "Referer": "https://topup.pk/",
                "User-Agent": "Mozilla/5.0 (Linux; Android 15; RMX5070 Build/UKQ1.231108.001) AppleWebKit/537.36 Chrome/138.0.7204.157 Mobile Safari/537.36"
            }
            payload = {"app_id": 100067, "login_id": str(extracted_uid)}
            openid_res = requests.post(openid_url, headers=openid_headers, json=payload, verify=False, timeout=10).json()
            return openid_res.get("open_id")
        except: 
            return None

    final_acc_token = None
    final_open_id = None

    if uid and password:
        try:
            oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
            payload = {
                'uid': uid, 'password': password, 'response_type': "token",
                'client_type': "2", 'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                'client_id': "100067"
            }
            headers = {'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)"}
            res = requests.post(oauth_url, data=payload, headers=headers, verify=False, timeout=10).json()
            
            final_acc_token = res.get('access_token')
            final_open_id = res.get('open_id')
            
            if not final_acc_token or not final_open_id:
                return None, "Invalid Guest Credentials"
        except:
            return None, "Auth API Error"
            
    elif access_token:
        final_acc_token = access_token
        final_open_id = fetch_open_id(access_token)
        if not final_open_id:
            return None, "Failed to extract Open ID from Access Token"
    else:
        return None, "No credentials provided"

    try:
        import my_pb2, output_pb2
        platforms =[8, 3, 4, 6]
        
        for p_type in platforms:
            try:
                game_data = my_pb2.GameData()
                game_data.timestamp = "2024-12-05 18:15:32"
                game_data.game_name = "free fire"
                game_data.game_version = 1
                game_data.version_code = "1.108.3"
                game_data.os_info = "Android OS 9 / API-28"
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
                game_data.open_id = final_open_id
                game_data.access_token = final_acc_token
                game_data.platform_type = p_type
                game_data.field_99 = str(p_type)
                game_data.field_100 = str(p_type)

                edata = encrypt_data(game_data.SerializeToString())
                
                url = "https://loginbp.ggpolarbear.com/MajorLogin"
                headers = {
                    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                    "Connection": "Keep-Alive",
                    "Accept-Encoding": "gzip",
                    "Content-Type": "application/octet-stream",
                    "Expect": "100-continue",
                    "X-Unity-Version": "2018.4.11f1",
                    "X-GA": "v1 1",
                    "ReleaseVersion": "OB53"
                }
                
                response = requests.post(url, data=edata, headers=headers, verify=False, timeout=5)
                if response.status_code == 200:
                    msg = output_pb2.Garena_420()
                    msg.ParseFromString(response.content)
                    token = getattr(msg, "token", None)
                    if token: return token, None
                    
            except Exception:
                continue
                
        return None, "Major Login Failed (Invalid Token or Setup)"
        
    except ImportError:
        return None, "Server Error: Protobuf files missing"


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

def upload_bio_request_new(jwt_token, bio_text, region=None):
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

        # Dynamically pick the right server URL based on the region
        url = SERVERS.get(region.upper(), SERVERS["IND"]) if region else SERVERS["IND"]

        resp = requests.post(url, headers=headers, data=encrypted, timeout=20, verify=False)

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

@app.route('/')
def secure_app():
    return render_template_string(HTML_TOOL)

@app.route('/api')
def api_docs():
    return render_template_string(HTML_API_DOCS)

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
                "credit": "@spideyabd"
            })
        elif code == 401:
            return jsonify({"ok": False, "msg": "Session Expired"})
        else:
            return jsonify({"ok": False, "msg": "An Error Occurred"})
    except:
        return jsonify({"ok": False, "msg": "Server Error"})


def fetch_open_id_cli(access_token):
    """Fetches Open ID using reward.ff and topup.pk (from CLI logic)"""
    try:
        uid_url = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
        uid_headers = {
            "authority": "prod-api.reward.ff.garena.com",
            "method": "GET",
            "path": "/redemption/api/auth/inspect_token/",
            "scheme": "https",
            "accept": "application/json, text/plain, */*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "access-token": access_token,
            "cookie": "_gid=GA1.2.444482899.1724033242; _ga_XB5PSHEQB4=GS1.1.1724040177.1.1.1724040732.0.0.0; token_session=cb73a97aaef2f1c7fd138757dc28a08f92904b1062e66c; _ga_KE3SY7MRSD=GS1.1.1724041788.0.0.1724041788.0; _ga_RF9R6YT614=GS1.1.1724041788.0.0.1724041788.0; _ga=GA1.1.1843180339.1724033241; apple_state_key=817771465df611ef8ab00ac8aa985783; _ga_G8QGMJPWWV=GS1.1.1724049483.1.1.1724049880.0.0; datadome=HBTqAUPVsbBJaOLirZCUkN3rXjf4gRnrZcNlw2WXTg7bn083SPey8X~ffVwr7qhtg8154634Ee9qq4bCkizBuiMZ3Qtqyf3Isxmsz6GTH_b6LMCKWF4Uea_HSPk;",
            "origin": "https://reward.ff.garena.com",
            "referer": "https://reward.ff.garena.com/",
            "sec-ch-ua": '"Not.A/Brand";v="99", "Chromium";v="124"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
        uid_res = requests.get(uid_url, headers=uid_headers, verify=False, timeout=10)
        uid_data = uid_res.json()
        uid = uid_data.get("uid")

        if not uid:
            return None

        openid_url = "https://topup.pk/api/auth/player_id_login"
        openid_headers = { 
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-MM,en-US;q=0.9,en;q=0.8",
            "Content-Type": "application/json",
            "Origin": "https://topup.pk",
            "Referer": "https://topup.pk/",
            "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Android WebView";v="138"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Linux; Android 15; RMX5070 Build/UKQ1.231108.001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.157 Mobile Safari/537.36",
            "X-Requested-With": "mark.via.gp",
            "Cookie": "source=mb; region=PK; mspid2=13c49fb51ece78886ebf7108a4907756; _fbp=fb.1.1753985808817.794945392376454660; language=en; datadome=WQaG3HalUB3PsGoSXY3TdcrSQextsSFwkOp1cqZtJ7Ax4YkiERHUgkgHlEAIccQO~w8dzTGM70D9SzaH7vymmEqOrVeX5pIsPVE22Uf3TDu6W3WG7j36ulnTg2DltRO7; session_key=hq02g63z3zjcumm76mafcooitj7nc79y",
        }
        payload = {"app_id": 100067, "login_id": str(uid)}
        openid_res = requests.post(openid_url, headers=openid_headers, json=payload, verify=False, timeout=10)
        return openid_res.json().get("open_id")

    except Exception as e:
        return None

@app.route("/bio", methods=["GET", "POST"])
def combined_bio_upload():
    bio = request.args.get("bio") or request.form.get("bio")
    jwt_token = request.args.get("jwt") or request.form.get("jwt")
    uid = request.args.get("uid") or request.form.get("uid")
    password = request.args.get("pass") or request.form.get("pass")
    access_token = request.form.get("access_token") or request.args.get("access_token") or request.form.get("access") or request.args.get("access")
    region_param = request.args.get("region") or request.form.get("region")
    
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
        
        try:
            final_open_id = fetch_open_id_cli(final_access_token)
            
            if not final_open_id:
                return jsonify({"status": "❌ Invalid Access Token or Extract Failed", "code": 400}), 400
            
            final_jwt = perform_major_login(final_access_token, final_open_id)
            
            if final_jwt:
                j_uid, j_name, j_region = decode_jwt_info(final_jwt)
                final_uid = j_uid
                final_name = j_name
                final_region = j_region
            else:
                return jsonify({"status": "❌ Major Login Failed using Access Token", "code": 500}), 500
                
        except Exception as e:
            return jsonify({"status": f"❌ Auth Error: {str(e)}", "code": 500}), 500
    
    else:
        return jsonify({"status": "❌ Error", "code": 400, "error": "Provide JWT, or UID/Pass, or Access Token"}), 400

    if not final_jwt:
        return jsonify({"status": "❌ JWT Generation Failed", "code": 500}), 500

    # Use the provided region parameter, or fallback to the region decoded from the JWT
    target_region = region_param or final_region

    result = upload_bio_request_new(final_jwt, bio, target_region)
    
    response_data = {
        "Credit": "@spideyabd",
        "Join For More": "Telegram: @SPIDEYFREEFILES",
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
        
        .method { display: inline-block; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; margin-right: 10px; }
        .method.get { background: #10B981; } /* Emerald Green */
        .method.post { background: #3B82F6; } /* Blue */
        
        code { background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; color: #22D3EE; font-family: 'Inter', sans-serif; font-size: 14px; }
        pre { background: #050505; padding: 15px; border-radius: 8px; overflow-x: auto; border: 1px solid var(--border); color: #ccc; white-space: pre-wrap; word-wrap: break-word; margin-top: 5px; margin-bottom: 15px; font-family: 'Inter', sans-serif; font-size: 13px; line-height: 1.5; }
        
        .param-title { color: #A78BFA; font-weight: 600; font-size: 14px; margin-top: 15px; display: block; }
        .footer { margin-top: 40px; text-align: center; color: #666; font-size: 14px; border-top: 1px solid var(--border); padding-top: 20px; }
        .footer a { color: var(--accent); text-decoration: none; }
        .region-box { background: rgba(34, 211, 238, 0.05); border: 1px dashed rgba(34, 211, 238, 0.3); padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>API Documentation</h1>
        <p>Welcome to the Free Fire Bio Injector Public API. The <code>/bio</code> endpoint supports robust login methods (Reward, Major Login, Shop2Game) and custom regions. It accepts both <b>GET</b> and <b>POST</b> requests.</p>

        <div class="region-box">
            <span style="color: #22D3EE; font-weight: 600;">🌍 Supported Regions (Optional param: region)</span><br>
            Use: <code>IND</code> (India), <code>BD</code> (Bangladesh), <code>SG</code> (Singapore), <code>BR</code> (Brazil), <code>US</code> (USA/NA), <code>EU</code> (Europe).<br>
            <span style="color: #A09CB9; font-size: 12px;">Note: If you don't pass a region, the API will try to auto-detect it from the token or default to IND.</span>
        </div>

        <!-- GET METHOD SECTION -->
        <h2>1. GET Method (URL Parameters)</h2>
        <div class="card">
            <p><span class="method get">GET</span> <code>/bio</code></p>
            <p style="font-size: 13px; color: #A09CB9;">Pass the parameters directly in the URL. Best for quick tests and simple integrations.</p>
            
            <span class="param-title">Using Access Token (Recommended)</span>
            <pre><span class="host-url"></span>/bio?bio={bio_text}&access_token={token}&region=IND</pre>

            <span class="param-title">Using UID & Password</span>
            <pre><span class="host-url"></span>/bio?bio={bio_text}&uid={uid}&pass={password}&region=BD</pre>

            <span class="param-title">Using Direct JWT</span>
            <pre><span class="host-url"></span>/bio?bio={bio_text}&jwt={jwt_token}&region=SG</pre>
        </div>

        <!-- POST METHOD SECTION -->
        <h2>2. POST Method (Form Data / Body)</h2>
        <div class="card">
            <p><span class="method post">POST</span> <code>/bio</code></p>
            <p style="font-size: 13px; color: #A09CB9;">Send data securely in the request body. Recommended to avoid URL length limits (especially for symbols/colors) and to keep credentials hidden.</p>
            
            <span class="param-title">Headers Required:</span>
            <pre>Content-Type: application/x-www-form-urlencoded</pre>
            
            <span class="param-title" style="margin-bottom: 15px;">Body Payload Options (Choose One):</span>
            
            <div style="margin-bottom: 15px;">
                <span style="font-size: 13px; color: #A09CB9; font-weight: 600;">Option 1: Access Token (Recommended)</span>
                <pre style="margin-top: 6px;">access_token={token}&bio={bio_text}&region=IND</pre>
            </div>

            <div style="margin-bottom: 15px;">
                <span style="font-size: 13px; color: #A09CB9; font-weight: 600;">Option 2: UID & Password</span>
                <pre style="margin-top: 6px;">uid={uid}&pass={password}&bio={bio_text}&region=BD</pre>
            </div>

            <div style="margin-bottom: 5px;">
                <span style="font-size: 13px; color: #A09CB9; font-weight: 600;">Option 3: Direct JWT</span>
                <pre style="margin-top: 6px;">jwt={jwt_token}&bio={bio_text}&region=SG</pre>
            </div>
            
            <span class="param-title">cURL Example:</span>
            <pre>curl -X POST <span class="host-url"></span>/bio \
     -d "bio=[b][FF0000]King Spidey" \
     -d "access_token=your_garena_access_token" \
     -d "region=IND"</pre>
        </div>

        <div class="footer">
            Owner: Ꮶɪɴɢ┇⁣ꨄᏚᴘɪᴅᴇʏ<br>
            Telegram: <a href="https://t.me/spideyabd" target="_blank">@spideyabd</a><br>
        </div>
    </div>
    
    <script>
        // Auto-fill the current domain into the code blocks
        document.querySelectorAll('.host-url').forEach(el => {
            el.innerText = window.location.origin;
        });
    </script>
</body>
</html>
"""

HTML_TOOL = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Free Fire - Bio Injector</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&display=swap" rel="stylesheet">
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
            position: fixed; top: 0; width: 100%; padding: 12px var(--safe-area-padding);
            display: flex; align-items: center; justify-content: center; z-index: 100;
            background: rgba(13, 15, 24, 0.6); backdrop-filter: blur(12px); border-bottom: 1px solid var(--glass-border);
        }
        .app-title {
            font-size: 20px; font-weight: 700; color: transparent;
            background-image: linear-gradient(45deg, var(--accent-gradient-end), var(--accent-gradient-start));
            background-clip: text; -webkit-background-clip: text;
        }

        /* Container */
        .main { width: 100%; display: flex; flex-direction: column; align-items: center; padding: 70px 10px 20px 10px; }

        .glass-panel {
            background: var(--glass-bg); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--glass-border); border-radius: var(--border-radius-md);
            box-shadow: 0 8px 32px 0 rgba(0,0,0,0.37); padding: 16px 12px; width: 100%; max-width: 650px;
        }

        /* Tabs */
        .tabs { display: flex; background: rgba(0,0,0,0.2); padding: 4px; border-radius: 12px; margin-bottom: 16px; border: 1px solid var(--glass-border); }
        .tab { flex: 1; text-align: center; padding: 8px; font-size: 12px; font-weight: 600; color: var(--text-secondary); cursor: pointer; border-radius: 8px; transition: 0.3s; }
        .tab.active { background: rgba(255,255,255,0.1); color: var(--text-primary); box-shadow: 0 0 10px rgba(138, 116, 255, 0.2); }

        /* Inputs */
        input, select {
            width: 100%; background: rgba(0,0,0,0.3); border: 1px solid var(--glass-border);
            color: var(--text-primary); padding: 12px; border-radius: var(--border-radius-sm);
            margin-bottom: 12px; font-size: 13px; transition: 0.3s;
        }
        input:focus { border-color: var(--accent-glow); box-shadow: 0 0 10px rgba(34, 211, 238, 0.1); }

        /* ---- TOOLBAR STYLING ---- */
        .toolbar-section { margin-bottom: 14px; }
        .toolbar-label { 
            font-size: 9px; font-weight: 800; color: var(--text-secondary); 
            letter-spacing: 1.5px; margin-bottom: 8px; margin-left: 2px;
        }
        
        .colors-ribbon { 
            display: flex; gap: 10px; overflow-x: auto; flex-wrap: nowrap; 
            padding-bottom: 8px; scrollbar-width: none; -webkit-overflow-scrolling: touch;
        }
        .colors-ribbon::-webkit-scrollbar { display: none; }
        
        .c-dot { 
            width: 30px; height: 30px; border-radius: 50%; flex-shrink: 0; 
            cursor: pointer; transition: 0.2s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            border: 2px solid rgba(255,255,255,0.15); box-shadow: 0 4px 8px rgba(0,0,0,0.4);
        }
        .c-dot:active { transform: scale(0.85); }
        
        .format-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 6px; }
        .format-btn {
            background: rgba(0,0,0,0.3); border: 1px solid var(--glass-border);
            border-radius: 10px; padding: 8px 2px; display: flex; flex-direction: column; 
            align-items: center; justify-content: center; cursor: pointer; transition: 0.2s;
        }
        .format-btn .icon { font-size: 15px; margin-bottom: 3px; color: var(--text-primary); font-family: serif; }
        .format-btn .lbl { font-size: 9px; color: var(--text-secondary); font-weight: 600; font-family: 'Inter', sans-serif; letter-spacing: 0.5px; }
        .format-btn:active { background: rgba(34, 211, 238, 0.15); border-color: var(--accent-glow); transform: scale(0.95); }
        .format-btn:active .icon, .format-btn:active .lbl { color: var(--accent-glow); }

        /* Editor */
        .editor-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; padding: 0 4px; }
        .editor-label { font-size: 11px; font-weight: bold; color: var(--text-secondary); letter-spacing: 1px; }
        .char-count {
            font-size: 9.5px; font-weight: 700;
            color: var(--accent-glow); letter-spacing: 0.5px;
            background: rgba(34, 211, 238, 0.1);
            padding: 4px 6px; border-radius: 6px; border: 1px solid rgba(34, 211, 238, 0.3);
            transition: 0.2s;
        }
        
        /* TEXTAREA - Big & Readable, Monospaced */
        textarea {
            width: 100%; height: 100px; background: rgba(0,0,0,0.3);
            border: 1px solid var(--glass-border); color: var(--text-primary);
            padding: 12px; border-radius: var(--border-radius-sm);
            font-size: 14px; 
            font-family: 'Courier New', Courier, monospace !important;
            resize: none; display: block;
            white-space: pre-wrap; word-wrap: break-word; overflow-x: hidden;
        }

        /* PREVIEW BOX - Big, Accurate, and exactly 39 characters */
        .preview-box {
            margin-top: 12px; margin-bottom: 16px;
            background: rgba(0,0,0,0.5); padding: 12px;
            border-radius: var(--border-radius-sm); border: 1px dashed var(--glass-border);
            min-height: 84px; display: flex; align-items: flex-start; justify-content: flex-start;
            overflow-x: auto; /* Adds scroll if mobile screen is too small, preserving shape */
        }

        #prev-inner {
            width: 39.5ch; /* .5 buffer fixes the 38-char pixel rounding bug */
            min-width: 39.5ch; /* Never shrinks below 39 characters */
            font-size: 14px; /* BIG FONT */
            letter-spacing: 0px; line-height: 20px;
            font-family: 'Courier New', Courier, monospace !important;
            color: #fff; margin: 0; padding: 0;
            white-space: pre-wrap; word-break: break-all; /* Forces break precisely at 39 characters */
        }
        
        #prev-inner * {
            font-family: inherit;
        }

        /* Custom subtle scrollbars */
        textarea::-webkit-scrollbar, .preview-box::-webkit-scrollbar { height: 4px; width: 4px; }
        textarea::-webkit-scrollbar-thumb, .preview-box::-webkit-scrollbar-thumb { background: rgba(138, 116, 255, 0.4); border-radius: 4px; }

        /* Button */
        .glass-button {
            width: 100%; padding: 14px; font-size: 15px; font-weight: 700;
            border: none; border-radius: var(--border-radius-sm); cursor: pointer;
            color: white; background-image: linear-gradient(45deg, var(--accent-gradient-start), var(--accent-gradient-end));
            box-shadow: 0 4px 15px rgba(79, 70, 229, 0.4); transition: 0.3s;
        }
        .glass-button:disabled { opacity: 0.7; cursor: not-allowed; }

        /* Footer */
        .footer { margin-top: 20px; text-align: center; color: var(--text-secondary); font-size: 12px; line-height: 1.8; padding-bottom: 20px; }
        .footer a { color: var(--accent-glow); text-decoration: none; font-weight: bold; }

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
        .res-body { text-align: center; color: var(--text-secondary); line-height: 1.6; max-width: 80%; }
        .res-body strong { color: white; font-size: 16px; }
        .credit { margin-top: 15px; font-size: 12px; color: #666; font-family: monospace; }
        
        .success .res-icon { color: var(--accent-glow); text-shadow: 0 0 30px var(--accent-glow); }
        .success .res-title { color: var(--accent-glow); }
        .error .res-icon { color: var(--danger-glow); text-shadow: 0 0 30px var(--danger-glow); }
        .error .res-title { color: var(--danger-glow); }
        
        .hidden { display: none !important; }
    </style>
    <script>
        let currentMode = 'token'; 
        let lastValidBio = '';

        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(() => document.getElementById('splash-screen').style.display = 'none', 1500);
        });

        function setMode(m) {
            currentMode = m; 
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById('t-'+m).classList.add('active');['jwt','token','uid'].forEach(x => document.getElementById('i-'+x).classList.add('hidden'));
            document.getElementById('i-'+m).classList.remove('hidden');
        }

        function renderPreviewHTML(t) {
            let prev = t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            prev = prev.replace(/\n/g, '<br>'); 
            prev = prev.replace(/\[([0-9A-Fa-f]{6})\]/gi, '</span><span style="color:#$1">');
            
            prev = prev.replace(/\[c\]/gi, '</span><span style="font-family: cursive !important;">');
            prev = prev.replace(/\[\/c\]/gi, '</span>');
            prev = prev.replace(/\[b\]/gi, '<b>').replace(/\[\/b\]/gi, '</b>');
            prev = prev.replace(/\[i\]/gi, '<i>').replace(/\[\/i\]/gi, '</i>');
            prev = prev.replace(/\[u\]/gi, '<u>').replace(/\[\/u\]/gi, '</u>');
            prev = prev.replace(/\[s\]/gi, '<s>').replace(/\[\/s\]/gi, '</s>');
            
            document.getElementById('prev-inner').innerHTML = '<span>' + prev + '</span>';
        }

        // Handle typing input natively using layout measurement
        function processInput() {
            const el = document.getElementById('bio');
            let text = el.value;

            if (text.length > 250) {
                text = text.substring(0, 250);
                el.value = text;
            }

            // Temporarily render to calculate visual lines
            renderPreviewHTML(text);

            const inner = document.getElementById('prev-inner');
            
            // 3 lines * 20px line-height = 60px. 
            // If the preview box text exceeds 65px (wraps to 4th line), it blocks the input!
            if (inner.offsetHeight > 65) {
                el.value = lastValidBio;
                renderPreviewHTML(lastValidBio);
            } else {
                lastValidBio = el.value;
            }

            updateStats();
        }

        function ins(txt) {
            const el = document.getElementById('bio');
            const[s, e] =[el.selectionStart, el.selectionEnd];
            const newVal = el.value.substring(0, s) + txt + el.value.substring(e);
            
            if (newVal.length > 250) {
                alert("Total limit of 250 characters reached!");
                return;
            }

            el.value = newVal;
            processInput(); 
            el.focus(); 
        }

        function updateStats() {
            let t = document.getElementById('bio').value;
            let counter = document.getElementById('char-count');
            let totalChars = t.length;
            
            const inner = document.getElementById('prev-inner');
            
            // Accurately count the visual lines based on pixel height (20px per line)
            let currentLines = Math.max(1, Math.round(inner.offsetHeight / 20));
            if(currentLines > 3) currentLines = 3;

            counter.innerText = `Lines: ${currentLines}/3 | Total: ${totalChars}/250`;

            if (totalChars >= 250 || currentLines === 3) {
                counter.style.color = "var(--danger-glow)";
                counter.style.borderColor = "var(--danger-glow)";
                counter.style.background = "var(--danger-bg)";
            } else {
                counter.style.color = "var(--accent-glow)";
                counter.style.borderColor = "rgba(34, 211, 238, 0.3)";
                counter.style.background = "rgba(34, 211, 238, 0.1)";
            }
        }

        function clearBio() { 
            document.getElementById('bio').value = ""; 
            lastValidBio = "";
            processInput(); 
        }

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
            
            const fd = new FormData();
            const bioText = document.getElementById('bio').value;
            fd.append('bio', bioText);
            fd.append('region', document.querySelector('select[name="region"]').value);

            if (currentMode === 'token') {
                fd.append('access_token', document.querySelector('input[name="access_token"]').value);
            } else if (currentMode === 'jwt') {
                fd.append('jwt', document.querySelector('input[name="jwt"]').value);
            } else if (currentMode === 'uid') {
                fd.append('uid', document.querySelector('input[name="uid"]').value);
                fd.append('pass', document.querySelector('input[name="pass"]').value);
            }
            
            try {
                const r = await fetch('/bio', { method: 'POST', body: fd });
                const d = await r.json();
                
                if(d.code === 200) {
                    showResult('success', 'SUCCESS', `
                        Name: <strong>${d.name || 'Unknown'}</strong><br>
                        UID: <strong>${d.uid || 'Unknown'}</strong><br>
                        Region: <strong>${d.region || 'Auto-Detected'}</strong><br>
                        Login: <strong>${d.login_method || 'API'}</strong><br>
                        Status: Bio Updated<br>
                        <div class="credit">Credit: ${d.Credit || '@spideyabd'}</div>
                    `);
                    
                    if (currentMode === 'token') document.querySelector('input[name="access_token"]').value = '';
                    else if (currentMode === 'jwt') document.querySelector('input[name="jwt"]').value = '';
                    else if (currentMode === 'uid') {
                        document.querySelector('input[name="uid"]').value = '';
                        document.querySelector('input[name="pass"]').value = '';
                    }
                    clearBio(); 
                    
                } else {
                    let exactError = d.error ? d.error : d.status;
                    
                    const hasEmoji = /[\p{Emoji_Presentation}\p{Extended_Pictographic}]/gu.test(bioText);
                    if ((d.code === 500 || d.code === 400) && hasEmoji) {
                        exactError = "Unsupported Characters/Invalid Characters<br><span style='font-size:12px;color:gray;'>(Emojis cause API rejection)</span>";
                    }

                    showResult('error', 'FAILED', `
                        Code: <strong>${d.code || r.status}</strong><br>
                        Reason: <strong>${exactError}</strong>
                    `);
                }
            } catch (err) {
                console.error(err);
                showResult('error', 'ERROR', `
                    Failed to execute.<br>
                    <strong>Details:</strong> ${err.message || err}
                `);
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
        <div class="app-title">FF BIO INJECTOR</div>
    </div>
    
    <div class="main">
        <div class="glass-panel">
            <div class="tabs">
                <div id="t-token" class="tab active" onclick="setMode('token')">ACCESS</div>
                <div id="t-jwt" class="tab" onclick="setMode('jwt')">JWT</div>
                <div id="t-uid" class="tab" onclick="setMode('uid')">UID-PASS</div>
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

                <!-- COLOR PALETTE SECTION -->
                <div class="toolbar-section">
                    <div class="toolbar-label">COLOR PALETTE</div>
                    <div class="colors-ribbon">
                        <div class="c-dot" style="background:#FF0000" onclick="ins('[FF0000]')"></div>
                        <div class="c-dot" style="background:#DC143C" onclick="ins('[DC143C]')"></div>
                        <div class="c-dot" style="background:#FFA500" onclick="ins('[FFA500]')"></div>
                        <div class="c-dot" style="background:#FFD700" onclick="ins('[FFD700]')"></div>
                        <div class="c-dot" style="background:#FFFF00" onclick="ins('[FFFF00]')"></div>
                        <div class="c-dot" style="background:#00FF00" onclick="ins('[00FF00]')"></div>
                        <div class="c-dot" style="background:#32CD32" onclick="ins('[32CD32]')"></div>
                        <div class="c-dot" style="background:#008000" onclick="ins('[008000]')"></div>
                        <div class="c-dot" style="background:#00FFFF" onclick="ins('[00FFFF]')"></div>
                        <div class="c-dot" style="background:#00BFFF" onclick="ins('[00BFFF]')"></div>
                        <div class="c-dot" style="background:#0000FF" onclick="ins('[0000FF]')"></div>
                        <div class="c-dot" style="background:#00008B" onclick="ins('[00008B]')"></div>
                        <div class="c-dot" style="background:#8A2BE2" onclick="ins('[8A2BE2]')"></div>
                        <div class="c-dot" style="background:#800080" onclick="ins('[800080]')"></div>
                        <div class="c-dot" style="background:#FF00FF" onclick="ins('[FF00FF]')"></div>
                        <div class="c-dot" style="background:#FF1493" onclick="ins('[FF1493]')"></div>
                        <div class="c-dot" style="background:#FFFFFF" onclick="ins('[FFFFFF]')"></div>
                        <div class="c-dot" style="background:#C0C0C0" onclick="ins('[C0C0C0]')"></div>
                        <div class="c-dot" style="background:#808080" onclick="ins('[808080]')"></div>
                        <div class="c-dot" style="background:#000000" onclick="ins('[000000]')"></div>
                        <div class="c-dot" style="background:#8B4513" onclick="ins('[8B4513]')"></div>
                    </div>
                </div>

                <!-- TEXT FORMATTING SECTION -->
                <div class="toolbar-section">
                    <div class="toolbar-label">TEXT FORMATTING</div>
                    <div class="format-grid">
                        <div class="format-btn" onclick="ins('[b]')">
                            <span class="icon" style="font-weight: 900;">B</span>
                            <span class="lbl">Bold</span>
                        </div>
                        <div class="format-btn" onclick="ins('[i]')">
                            <span class="icon" style="font-style: italic;">I</span>
                            <span class="lbl">Italic</span>
                        </div>
                        <div class="format-btn" onclick="ins('[u]')">
                            <span class="icon" style="text-decoration: underline;">U</span>
                            <span class="lbl">Under</span>
                        </div>
                        <div class="format-btn" onclick="ins('[s]')">
                            <span class="icon" style="text-decoration: line-through;">S</span>
                            <span class="lbl">Strike</span>
                        </div>
                        <div class="format-btn" onclick="ins('[c]')">
                            <span class="icon" style="font-family: cursive;">C</span>
                            <span class="lbl">Curved</span>
                        </div>
                    </div>
                </div>

                <div class="editor-header">
                    <span class="editor-label">BIO TEXT</span>
                    <span id="char-count" class="char-count">Lines: 1/3 | Total: 0/250</span>
                </div>
                
                <textarea id="bio" name="bio" placeholder="Type Bio Here..." maxlength="250" oninput="processInput()"></textarea>

                <div class="preview-box" id="prev">
                    <div id="prev-inner"></div>
                </div>

                <button id="btn" class="glass-button">UPDATE BIO</button>
            </form>
            
            <div class="footer">
                Owner: Ꮶɪɴɢ┇⁣ꨄᏚᴘɪᴅᴇʏ<br>
                Telegram: <a href="https://t.me/spideyabd" target="_blank">@spideyabd</a><br>
                Telegram Channel: <a href="https://t.me/SPIDEYFREEFILES">T10 SPIDEY FILES</a>
            </div>
        </div>
    </div>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)