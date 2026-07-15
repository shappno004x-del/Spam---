import requests
import json
import threading
import time
import base64
import struct
import tempfile
import os
import sys
import importlib.util
import random
import ipaddress
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, jsonify
import urllib3

try:
    from byte import Encrypt_ID, encrypt_api
except ImportError:
    def Encrypt_ID(uid: str) -> str:
        return uid.encode().hex()
    def encrypt_api(payload: str) -> str:
        return payload.encode().hex()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

API_KEY = "JMLB"

def require_api_key(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY:
            return jsonify({"error": "Unauthorized. Valid API key required."}), 401
        return f(*args, **kwargs)
    return decorated

# ==================== REGION MAP ====================
REGION_MAP = {
    "ind": "https://client.ind.freefiremobile.com",
    "me": "https://clientbp.ggpolarbear.com",
    "vn": "https://clientbp.ggpolarbear.com",
    "bd": "https://clientbp.ggpolarbear.com",
    "pk": "https://clientbp.ggpolarbear.com",
    "sg": "https://clientbp.ggpolarbear.com",
    "br": "https://client.us.freefiremobile.com",
    "na": "https://client.us.freefiremobile.com",
    "id": "https://clientbp.ggpolarbear.com",
    "ru": "https://clientbp.ggpolarbear.com",
    "th": "https://clientbp.ggpolarbear.com",
}

ALL_REGIONS = list(REGION_MAP.items())

# ==================== UPDATED URLs ====================
OAUTH_URL = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
MAJOR_LOGIN_URL = "https://loginbp.ggblueshark.com/MajorLogin"
CLIENT_ID = 100067
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

# ==================== PROTO KEYS ====================
PROTO_KEY = b'Yg&tc%DEuh6%Zc^8'
PROTO_IV = b'6oyZDr22E3ychjM%'

# ==================== HEADERS ====================
BASE_HEADERS = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB54"
}

# ==================== IP ROTATION ====================
class IPRotator:
    REGION_IP_CIDRS = {
        "BD": ["27.147.128.0/17", "37.111.192.0/19", "49.0.32.0/20", "59.152.96.0/20",
               "114.130.0.0/17", "115.127.0.0/17", "119.30.32.0/20", "123.49.0.0/18",
               "103.220.220.0/22", "103.108.140.0/22", "103.242.20.0/22"],
        "IND": ["1.6.0.0/15", "1.38.0.0/15", "14.96.0.0/15", "27.4.0.0/14", "27.56.0.0/13"],
        "ID": ["36.64.0.0/11", "101.255.0.0/16", "103.10.60.0/22", "114.120.0.0/13"],
        "TH": ["1.46.0.0/15", "27.55.0.0/16", "49.228.0.0/15", "101.108.0.0/15"],
        "VN": ["1.52.0.0/14", "14.160.0.0/11", "27.64.0.0/12", "113.160.0.0/12"],
        "PK": ["39.32.0.0/11", "111.68.96.0/19", "182.176.0.0/12"],
        "ME": ["2.88.0.0/13", "5.100.0.0/14", "31.166.0.0/15", "37.104.0.0/13"],
        "BR": ["177.0.0.0/13", "186.192.0.0/12", "189.0.0.0/11", "200.96.0.0/12"],
        "EU": ["2.16.0.0/12", "5.144.0.0/14", "31.40.0.0/14", "46.16.0.0/14"],
        "CIS": ["2.92.0.0/14", "5.136.0.0/13", "31.128.0.0/12", "46.0.0.0/12"],
        "NA": ["3.0.0.0/9", "8.0.0.0/12", "12.0.0.0/10", "24.0.0.0/10"],
        "SAC": ["186.0.0.0/10", "190.0.0.0/11", "200.0.0.0/11"],
        "TW": ["1.160.0.0/12", "36.224.0.0/12", "114.24.0.0/12", "118.160.0.0/12"]
    }

    @classmethod
    def get_random_ip_from_cidr(cls, cidr):
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            num = net.num_addresses
            if num > 2:
                offset = random.randint(1, num - 2)
            else:
                offset = 0
            return str(ipaddress.IPv4Address(int(net.network_address) + offset))
        except:
            return "103.220.220.10"

    @classmethod
    def get_rotating_ip(cls, region):
        region = region.upper()
        if region in cls.REGION_IP_CIDRS:
            cidr = random.choice(cls.REGION_IP_CIDRS[region])
        else:
            cidr = random.choice(random.choice(list(cls.REGION_IP_CIDRS.values())))
        return cls.get_random_ip_from_cidr(cidr)

    @classmethod
    def get_headers_with_ip_rotation(cls, base_headers, region):
        headers = base_headers.copy()
        ip = cls.get_rotating_ip(region)
        headers["X-Forwarded-For"] = ip
        headers["X-Real-IP"] = ip
        headers["Client-IP"] = ip
        headers["CF-Connecting-IP"] = ip
        headers["True-Client-IP"] = ip
        return headers

# ==================== PROTOBUF LOADER ====================
MAJOR_LOGIN_REQ_B64 = "ChNNYWpvckxvZ2luUmVxLnByb3RvIvoKCgpNYWpvckxvZ2luEhIKCmV2ZW50X3RpbWUYAyABKAkSEQoJZ2FtZV9uYW1lGAQgASgJEhMKC3BsYXRmb3JtX2lkGAUgASgFEhYKDmNsaWVudF92ZXJzaW9uGAcgASgJEhcKD3N5c3RlbV9zb2Z0d2FyZRgIIAEoCRIXCg9zeXN0ZW1faGFyZHdhcmUYCSABKAkSGAoQdGVsZWNvbV9vcGVyYXRvchgKIAEoCRIUCgxuZXR3b3JrX3R5cGUYCyABKAkSFAoMc2NyZWVuX3dpZHRoGAwgASgNEhUKDXNjcmVlbl9oZWlnaHQYDSABKA0SEgoKc2NyZWVuX2RwaRgOIAEoCRIZChFwcm9jZXNzb3JfZGV0YWlscxgPIAEoCRIOCgZtZW1vcnkYECABKA0SFAoMZ3B1X3JlbmRlcmVyGBEgASgJEhMKC2dwdV92ZXJzaW9uGBIgASgJEhgKEHVuaXF1ZV9kZXZpY2VfaWQYEyABKAkSEQoJY2xpZW50X2lwGBQgASgJEhAKCGxhbmd1YWdlGBUgASgJEg8KB29wZW5faWQYFiABKAkSFAoMb3Blbl9pZF90eXBlGBcgASgJEhMKC2RldmljZV90eXBlGBggASgJEicKEG1lbW9yeV9hdmFpbGFibGUYGSABKAsyDS5HYW1lU2VjdXJpdHkSFAoMYWNjZXNzX3Rva2VuGB0gASgJEhcKD3BsYXRmb3JtX3Nka19pZBgeIAEoBRIaChJuZXR3b3JrX29wZXJhdG9yX2EYKSABKAkSFgoObmV0d29ya190eXBlX2EYKiABKAkSHAoUY2xpZW50X3VzaW5nX3ZlcnNpb24YOSABKAkSHgoWZXh0ZXJuYWxfc3RvcmFnZV90b3RhbBg8IAEoBRIiChpleHRlcm5hbF9zdG9yYWdlX2F2YWlsYWJsZRg9IAEoBRIeChZpbnRlcm5hbF9zdG9yYWdlX3RvdGFsGD4gASgFEiIKGmludGVybmFsX3N0b3JhZ2VfYXZhaWxhYmxlGD8gASgFEiMKG2dhbWVfZGlza19zdG9yYWdlX2F2YWlsYWJsZRhAIAEoBRIfChdnYW1lX2Rpc2tfc3RvcmFnZV90b3RhbBhBIAEoBRIlCh1leHRlcm5hbF9zZGNhcmRfYXZhaWxfc3RvcmFnZRhCIAEoBRIlCh1leHRlcm5hbF9zZGNhcmRfdG90YWxfc3RvcmFnZRhDIAEoBRIQCghsb2dpbl9ieRhJIAEoBRIUCgxsaWJyYXJ5X3BhdGgYSiABKAkSEgoKcmVnX2F2YXRhchhMIAEoBRIVCg1saWJyYXJ5X3Rva2VuGE0gASgJEhQKDGNoYW5uZWxfdHlwZRhOIAEoBRIQCghjcHVfdHlwZRhPIAEoBRIYChBjcHVfYXJjaGl0ZWN0dXJlGFEgASgJEhsKE2NsaWVudF92ZXJzaW9uX2NvZGUYUyABKAkSFAoMZ3JhcGhpY3NfYXBpGFYgASgJEh0KFXN1cHBvcnRlZF9hc3RjX2JpdHNldBhXIAEoDRIaChJsb2dpbl9vcGVuX2lkX3R5cGUYWCABKAUSGAoQYW5hbHl0aWNzX2RldGFpbBhZIAEoDBIUCgxsb2FkaW5nX3RpbWUYXCABKA0SFwoPcmVsZWFzZV9jaGFubmVsGF0gASgJEhIKCmV4dHJhX2luZm8YXiABKAkSIAoYYW5kcm9pZF9lbmdpbmVfaW5pdF9mbGFnGF8gASgNEg8KB2lmX3B1c2gYYSABKAUSDgoGaXNfdnBuGGIgASgFEhwKFG9yaWdpbl9wbGF0Zm9ybV90eXBlGGMgASgJEh0KFXByaW1hcnlfcGxhdGZvcm1fdHlwZRhkIAEoCSI1CgxHYW1lU2VjdXJpdHkSDwoHdmVyc2lvbhgGIAEoBRIUCgxoaWRkZW5fdmFsdWUYCCABKARiBnByb3RvMw=="
MAJOR_LOGIN_RES_B64 = "ChNNYWpvckxvZ2luUmVzLnByb3RvInwKDU1ham9yTG9naW5SZXMSEwoLYWNjb3VudF91aWQYASABKAQSDgoGcmVnaW9uGAIgASgJEg0KBXRva2VuGAggASgJEgsKA3VybBgKIAEoCRIRCgl0aW1lc3RhbXAYFSABKAMSCwoDa2V5GBYgASgMEgoKAml2GBcgASgMYgZwcm90bzM="
GET_LOGIN_DATA_B64 = "ChVHZXRMb2dpbkRhdGFSZXMucHJvdG8ipAEKDEdldExvZ2luRGF0YRISCgpBY2NvdW50VUlEGAEgASgEEg4KBlJlZ2lvbhgDIAEoCRITCgtBY2NvdW50TmFtZRgEIAEoCRIWCg5PbmxpbmVfSVBfUG9ydBgOIAEoCRIPCgdDbGFuX0lEGBQgASgDEhYKDkFjY291bnRJUF9Qb3J0GCAgASgJEhoKEkNsYW5fQ29tcGlsZWRfRGF0YRg3IAEoCWIGcHJvdG8z"

def load_protobuf_classes():
    classes = {}
    temp_dir = tempfile.mkdtemp()
    req_code = f'''
# -*- coding: utf-8 -*-
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
import base64
_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(base64.b64decode("{MAJOR_LOGIN_REQ_B64}"))
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'MajorLoginReq_pb2', _globals)
'''
    res_code = f'''
# -*- coding: utf-8 -*-
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
import base64
_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(base64.b64decode("{MAJOR_LOGIN_RES_B64}"))
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'MajorLoginRes_pb2', _globals)
'''
    data_code = f'''
# -*- coding: utf-8 -*-
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
import base64
_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(base64.b64decode("{GET_LOGIN_DATA_B64}"))
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'GetLoginDataRes_pb2', _globals)
'''
    req_path = os.path.join(temp_dir, 'MajorLoginReq_pb2.py')
    with open(req_path, 'w') as f:
        f.write(req_code)
    spec = importlib.util.spec_from_file_location("MajorLoginReq_pb2", req_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["MajorLoginReq_pb2"] = module
    spec.loader.exec_module(module)
    classes['MajorLogin'] = module.MajorLogin
    classes['GameSecurity'] = module.GameSecurity
    res_path = os.path.join(temp_dir, 'MajorLoginRes_pb2.py')
    with open(res_path, 'w') as f:
        f.write(res_code)
    spec = importlib.util.spec_from_file_location("MajorLoginRes_pb2", res_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["MajorLoginRes_pb2"] = module
    spec.loader.exec_module(module)
    classes['MajorLoginRes'] = module.MajorLoginRes
    data_path = os.path.join(temp_dir, 'GetLoginDataRes_pb2.py')
    with open(data_path, 'w') as f:
        f.write(data_code)
    spec = importlib.util.spec_from_file_location("GetLoginDataRes_pb2", data_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["GetLoginDataRes_pb2"] = module
    spec.loader.exec_module(module)
    classes['GetLoginData'] = module.GetLoginData
    return classes

PB = load_protobuf_classes()
MajorLogin = PB['MajorLogin']
GameSecurity = PB['GameSecurity']
MajorLoginRes = PB['MajorLoginRes']
GetLoginData = PB['GetLoginData']

# ==================== CRYPTO HELPERS ====================
def encrypt_proto(payload_bytes):
    cipher = AES.new(PROTO_KEY, AES.MODE_CBC, PROTO_IV)
    padded = pad(payload_bytes, AES.block_size)
    return cipher.encrypt(padded)

def decrypt_proto(encrypted_bytes):
    cipher = AES.new(PROTO_KEY, AES.MODE_CBC, PROTO_IV)
    decrypted = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
    return decrypted

# ==================== TOKEN CACHE (5 HOURS) ====================
TOKEN_CACHE = {}
TOKEN_CACHE_LOCK = threading.Lock()
TOKEN_EXPIRY_SECONDS = 5 * 3600

def get_cached_token(uid, password, region=None):
    current_time = time.time()
    with TOKEN_CACHE_LOCK:
        if uid in TOKEN_CACHE:
            token, expiry = TOKEN_CACHE[uid]
            if current_time < expiry:
                return token, None
    token, err = get_jwt_token(uid, password, region)
    if token:
        with TOKEN_CACHE_LOCK:
            TOKEN_CACHE[uid] = (token, current_time + TOKEN_EXPIRY_SECONDS)
        return token, None
    else:
        return None, err

# ==================== TOKEN GENERATION (FIXED PARSING) ====================
def generate_access_token(uid, password, region=None):
    headers = {
        "User-Agent": "GarenaMSDK/5.5.2P3(SM-A515F;Android 12;en-US;IND;)",
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
        "Connection": "Keep-Alive",
        "X-Garena-Timestamp": str(int(time.time() * 1000)),
    }
    if region:
        headers = IPRotator.get_headers_with_ip_rotation(headers, region)
    
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "client_type": 2,
        "password": password,
        "response_type": "token",
        "uid": uid,
    }
    
    try:
        response = requests.post(OAUTH_URL, headers=headers, json=payload, timeout=30, verify=False)
        if response.status_code == 200:
            resp_data = response.json()
            # ✅ সঠিকভাবে data অবজেক্ট থেকে ফিল্ড নিচ্ছি
            data = resp_data.get("data", {})
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            if open_id and access_token:
                return open_id, access_token, None
            else:
                return None, None, f"Missing fields in data: {data}"
        else:
            return None, None, f"HTTP {response.status_code}: {response.text[:200]}"
    except Exception as e:
        return None, None, str(e)

def build_major_login_message(open_id, access_token):
    major_login = MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.123.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    major_login.memory_available.version = 55
    major_login.memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    return major_login.SerializeToString()

def major_login(open_id, access_token, region=None):
    proto_payload = build_major_login_message(open_id, access_token)
    encrypted_payload = encrypt_proto(proto_payload)
    headers = BASE_HEADERS.copy()
    if region:
        headers = IPRotator.get_headers_with_ip_rotation(headers, region)
    try:
        response = requests.post(MAJOR_LOGIN_URL, data=encrypted_payload, headers=headers, timeout=30, verify=False)
        if response.status_code == 200:
            response_data = response.content
            if len(response_data) % 16 == 0:
                decrypted = decrypt_proto(response_data)
                if decrypted:
                    res = MajorLoginRes()
                    res.ParseFromString(decrypted)
                    return True, {
                        'account_uid': res.account_uid,
                        'region': res.region,
                        'token': res.token,
                        'url': res.url,
                        'timestamp': res.timestamp,
                        'key': res.key.hex() if res.key else None,
                        'iv': res.iv.hex() if res.iv else None
                    }
            res = MajorLoginRes()
            res.ParseFromString(response_data)
            if res.token:
                return True, {
                    'account_uid': res.account_uid,
                    'region': res.region,
                    'token': res.token,
                    'url': res.url,
                    'timestamp': res.timestamp,
                    'key': res.key.hex() if res.key else None,
                    'iv': res.iv.hex() if res.iv else None
                }
            return False, "No token in response"
        else:
            return False, f"HTTP {response.status_code}"
    except Exception as e:
        return False, str(e)

def get_jwt_token(uid, password, region=None):
    open_id, access_token, err = generate_access_token(uid, password, region)
    if err:
        return None, err
    success, login_resp = major_login(open_id, access_token, region)
    if not success:
        return None, login_resp
    jwt_token = login_resp.get('token')
    if not jwt_token:
        return None, "No JWT token in MajorLogin response"
    return jwt_token, None

# ==================== FRIEND REQUEST ====================
def send_friend_request(target_uid, token, region_server_url, region=None):
    try:
        encrypted_id = Encrypt_ID(target_uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)
        url = f"{region_server_url}/RequestAddingFriend"
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB54",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(encrypted_payload)//2),
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate, br"
        }
        if region:
            headers = IPRotator.get_headers_with_ip_rotation(headers, region)
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), timeout=15)
        resp_text = response.text[:200]
        if response.status_code == 200:
            if "Invalid request body" in resp_text:
                return False, f"200 OK but body: {resp_text}", url
            return True, resp_text, url
        else:
            return False, f"HTTP {response.status_code}: {resp_text}", url
    except Exception as e:
        return False, str(e), region_server_url

# ==================== ACCOUNT LOADER ====================
def load_accounts(region):
    if not region:
        return []
    region_lower = region.lower()
    filename = f"accounts_{region_lower}.txt"
    accounts = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                uid, pwd = line.split(':', 1)
                accounts.append({"uid": uid, "password": pwd})
        return accounts
    except FileNotFoundError:
        return []
    except Exception:
        return []

# ==================== PROCESS ACCOUNT ====================
def process_account(account, target_uid, results, regions_to_try, delay=0):
    if delay > 0:
        time.sleep(delay)
    uid = account['uid']
    password = account['password']
    region = regions_to_try[0][0] if regions_to_try else None
    
    token, err = get_cached_token(uid, password, region)
    if not token:
        results['failed'] += 1
        err_key = f"Token error: {err}"
        results['response_counts'][err_key] = results['response_counts'].get(err_key, 0) + 1
        return
    
    success = False
    used_region_url = None
    final_response = None
    for region_name, server_url in regions_to_try:
        ok, resp_msg, used_url = send_friend_request(target_uid, token, server_url, region_name)
        if ok:
            success = True
            used_region_url = used_url
            final_response = resp_msg
            break
        else:
            final_response = resp_msg
    if success:
        results['success'] += 1
        results['region_urls_used'].add(used_region_url)
        results['response_counts'][final_response] = results['response_counts'].get(final_response, 0) + 1
    else:
        results['failed'] += 1
        results['response_counts'][final_response] = results['response_counts'].get(final_response, 0) + 1

# ==================== SPAM FUNCTION ====================
def spam_friend_requests(target_uid, count=None, region=None):
    if not region:
        return {"error": "Region parameter is required"}, 400

    accounts = load_accounts(region)
    if not accounts:
        return {"error": f"No accounts found for region: {region}"}, 404

    region_lower = region.lower()
    if region_lower not in REGION_MAP:
        return {"error": f"Invalid region: {region}"}, 400

    regions_to_try = [(region_lower, REGION_MAP[region_lower])]

    if count is not None:
        if count <= 0:
            return {"error": "Count must be positive"}, 400
        accounts_to_use = accounts[:min(count, len(accounts))]
    else:
        accounts_to_use = accounts

    results = {
        "success": 0,
        "failed": 0,
        "owner": " minister_69",
        "channel": "minister_6T9",
        "group": "minister_likes",
        "region_urls_used": set(),
        "response_counts": {}
    }

    threads = []
    thread_delay = 0.1
    for i, acc in enumerate(accounts_to_use):
        t = threading.Thread(target=process_account, args=(acc, target_uid, results, regions_to_try, i * thread_delay))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    results["region_urls_used"] = list(results["region_urls_used"])
    results["total_accounts_available"] = len(accounts)
    results["accounts_used"] = len(accounts_to_use)
    return results

# ==================== FLASK ENDPOINTS ====================
@app.route('/jakir', methods=['GET'])
@require_api_key
def jakir():
    target_uid = request.args.get('uid')
    if not target_uid:
        return jsonify({"error": "Missing 'uid' parameter"}), 400

    region = request.args.get('region')
    if not region:
        return jsonify({"error": "Missing 'region' parameter"}), 400

    region = region.strip()
    if region.lower() not in REGION_MAP:
        return jsonify({"error": f"Invalid region: {region}. Valid regions: {list(REGION_MAP.keys())}"}), 400

    count_param = request.args.get('count')
    count = None
    if count_param:
        try:
            count = int(count_param)
        except ValueError:
            return jsonify({"error": "Count must be an integer"}), 400

    result = spam_friend_requests(target_uid, count, region)
    if isinstance(result, tuple) and result[1] == 404:
        return jsonify(result[0]), 404
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)