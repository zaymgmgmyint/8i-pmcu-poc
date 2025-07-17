import requests
import hashlib
import base64
import json
import time
import ssl
import logging
import paho.mqtt.client as mqtt

# --- Configuration ---
USERNAME = "system"
PASSWORD = "ismart123456"
DSS_IP = "192.168.100.94"
DSS_PORT = 443
CLIENT_TYPE = "WINPC_V2"
BASE_URL = f"https://{DSS_IP}:{DSS_PORT}"

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Helper Functions ---
def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def login_get_realm():
    url = f"{BASE_URL}/brms/api/v1.0/accounts/authorize"
    payload = {"userName": USERNAME, "ipAddress": DSS_IP, "clientType": CLIENT_TYPE}
    r = requests.post(url, json=payload, verify=False)
    return r.json()

def login_second(realm, randomKey, encryptType, publicKey):
    temp1 = md5(PASSWORD)
    temp2 = md5(USERNAME + temp1)
    temp3 = md5(temp2)
    temp4 = md5(f"{USERNAME}:{realm}:{temp3}")
    signature = md5(f"{temp4}:{randomKey}")
    payload = {
        "signature": signature,
        "userName": USERNAME,
        "randomKey": randomKey,
        "encrytType": encryptType,
        "ipAddress": DSS_IP,
        "clientType": CLIENT_TYPE,
        "publicKey": publicKey,
        "userType": "0"
    }
    url = f"{BASE_URL}/brms/api/v1.0/accounts/authorize"
    r = requests.post(url, json=payload, verify=False)
    return r.json()

def get_token_and_login():
    step1 = login_get_realm()
    realm = step1['realm']
    randomKey = step1['randomKey']
    encryptType = step1.get('encryptType', 'MD5')
    publicKey = step1.get('publicKey') or step1.get('publickey')
    step2 = login_second(realm, randomKey, encryptType, publicKey)
    token = step2['token']
    secretKey = step2.get('secretKey')
    secretVector = step2.get('secretVector')
    return token, secretKey, secretVector

def test_api_call(token, endpoint, payload=None, method="POST", extra_headers=None):
    url = f"{BASE_URL}{endpoint}"
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "X-Subject-Token": token
    }
    if extra_headers:
        headers.update(extra_headers)
    logger.info(f"API CALL: {method} {url}")
    logger.info(f"Headers: {headers}")
    if payload:
        logger.info(f"Payload: {json.dumps(payload, indent=2, ensure_ascii=False)}")

    if method.upper() == "POST":
        r = requests.post(url, json=payload, headers=headers, verify=False)
    else:
        r = requests.get(url, params=payload, headers=headers, verify=False)

    logger.info(f"Status code: {r.status_code}")
    try:
        resp = r.json()
        logger.info("Response JSON:")
        logger.info(json.dumps(resp, indent=2, ensure_ascii=False))
        return resp
    except Exception as e:
        logger.error(f"Failed to decode response as JSON: {e}")
        logger.error(f"Raw response text: {r.text}")
        return None

def get_mq_config(token):
    """Get MQ configuration from DSS"""
    mq_endpoint = "/brms/api/v1.0/BRM/Config/GetMqConfig"
    mq_payload = {}
    logger.info(f"Calling MQ Config endpoint: {mq_endpoint}")
    mq_result = test_api_call(token, mq_endpoint, mq_payload, method="POST")
    return mq_result

def try_mqtt_connection(mq_config, username, password):
    """Attempt to connect to DSS MQTT broker (port 1883)"""
    mqtt_addr = mq_config.get('mqtt', f'{DSS_IP}:1883')
    host, port = mqtt_addr.split(':')
    port = int(port)
    client_id = f"dss_test_{int(time.time())}"
    client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
    client.username_pw_set(username, password)

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            logger.info("Connected to MQTT broker!")
            client.subscribe("mq.common.msg.topic")
        else:
            logger.error(f"MQTT connect failed, code: {rc}")
    client.on_connect = on_connect

    try:
        client.connect(host, port, 10)
        client.loop_start()
        time.sleep(5)
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        logger.error(f"MQTT connection error: {e}")

def main():
    """Main function to demonstrate DSS MQ integration"""
    logger.info("=== DSS MQ Integration Example ===")
    # 1. Login and get token/keys
    token, secretKey, secretVector = get_token_and_login()
    logger.info(f"Token: {token[:8]}... SecretKey/Vector: {bool(secretKey)}, {bool(secretVector)}")
    # 2. Get MQ config
    mq_response = get_mq_config(token)
    if not mq_response:
        logger.error("Failed to get MQ configuration")
        return

    # Extract MQ config from nested data structure
    mq_config = mq_response.get('data', {})
    if not mq_config:
        logger.error("No MQ configuration data found in response")
        logger.error("Full response:")
        logger.error(json.dumps(mq_response, indent=2, ensure_ascii=False))
        return

    logger.info("MQ Configuration:")
    logger.info(json.dumps(mq_config, indent=2, ensure_ascii=False))

    # 3. Try MQTT connection (using fallback password 'admin' if decryption fails)
    test_password = 'admin'  # Replace with decrypted password if available
    try_mqtt_connection(mq_config, mq_config.get('userName', 'admin'), test_password)

if __name__ == "__main__":
    main()
