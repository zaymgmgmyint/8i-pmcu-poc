import requests
import hashlib
import base64
import time
import urllib3
import json
import ssl
import socket
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import paho.mqtt.client as mqtt
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('face_scan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
USERNAME = "system"
PASSWORD = "ismart123456"
IP = "192.168.100.94"        # <-- Change to your actual DSS IP
PORT = 443                # Or 443 for HTTPS
CLIENT_TYPE = "WINPC_V2"

BASE_URL = f"https://{IP}:{PORT}"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def login_get_realm():
    """Step 1: Initial login to get challenge parameters"""
    url = f"{BASE_URL}/brms/api/v1.0/accounts/authorize"
    payload = {
        "userName": USERNAME,
        "ipAddress": IP,
        "clientType": CLIENT_TYPE
    }
    r = requests.post(url, json=payload, verify=False)
    logger.info(f"Step 1 status code: {r.status_code}")
    try:
        resp = r.json()
        logger.info("Step 1 JSON response:")
        logger.info(json.dumps(resp, indent=2, ensure_ascii=False))
    except Exception as e:
        logger.error(f"Step 1 failed to decode JSON: {e}")
        logger.error(f"Step 1 raw response text: {r.text}")
        resp = None
    return resp

def login_second(realm, randomKey, encryptType, publicKey):
    """Step 2: Login with signature"""
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
        "ipAddress": IP,
        "clientType": CLIENT_TYPE,
        "publicKey": publicKey,
        "userType": "0"
    }
    url = f"{BASE_URL}/brms/api/v1.0/accounts/authorize"
    r = requests.post(url, json=payload, verify=False)
    logger.info(f"Step 2 status code: {r.status_code}")
    try:
        resp = r.json()
        logger.info("Step 2 JSON response:")
        logger.info(json.dumps(resp, indent=2, ensure_ascii=False))
    except Exception as e:
        logger.error(f"Step 2 failed to decode JSON: {e}")
        logger.error(f"Step 2 raw response text: {r.text}")
        resp = None
    return resp

def get_token_and_login():
    """Complete login process and return token with secretKey/secretVector"""
    # Step 1: Initial login to get challenge
    step1 = login_get_realm()
    if not step1:
        raise ValueError("Step 1 login failed")

    realm = step1['realm']
    randomKey = step1['randomKey']
    encryptType = step1.get('encryptType', 'MD5')
    publicKey = step1.get('publicKey') or step1.get('publickey')
    if not publicKey:
        raise ValueError("publicKey/publickey not found in response: " + str(step1))

    # Step 2: Login with signature
    step2 = login_second(realm, randomKey, encryptType, publicKey)
    if not step2:
        raise ValueError("Step 2 login failed")

    token = step2['token']
    secretKey = step2.get('secretKey')
    secretVector = step2.get('secretVector')

    logger.info(f"Login successful. Token: {token[:20]}...")
    logger.info(f"SecretKey length: {len(secretKey) if secretKey else 0}")
    logger.info(f"SecretVector length: {len(secretVector) if secretVector else 0}")

    return token, secretKey, secretVector

def decrypt_mq_password_rsa(encrypted_password, secretKey, secretVector):
    """
    Try RSA decryption since the keys are 256 bytes (2048-bit RSA)
    """
    try:
        # The encrypted password appears to be hex-encoded
        encrypted_bytes = bytes.fromhex(encrypted_password)

        # Try using secretKey as RSA private key
        try:
            rsa_key = rsa.RSAPrivateKey.from_private_bytes(
                base64.b64decode(secretKey),
                default_backend()
            )
            decrypted = rsa_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.debug(f"RSA decryption with secretKey failed: {e}")

        # Try using secretVector as RSA private key
        try:
            rsa_key = rsa.RSAPrivateKey.from_private_bytes(
                base64.b64decode(secretVector),
                default_backend()
            )
            decrypted = rsa_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.debug(f"RSA decryption with secretVector failed: {e}")

    except Exception as e:
        logger.debug(f"RSA decryption error: {e}")

    return None

def decrypt_mq_password_aes(encrypted_password, secretKey, secretVector):
    """
    Try AES decryption with different key derivation methods
    """
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        # Try different approaches for AES key derivation
        key_data = base64.b64decode(secretKey)
        iv_data = base64.b64decode(secretVector)

        # Method 1: Use first 32 bytes as AES key, first 16 bytes as IV
        if len(key_data) >= 32 and len(iv_data) >= 16:
            aes_key = key_data[:32]
            aes_iv = iv_data[:16]

            try:
                cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
                encrypted_bytes = bytes.fromhex(encrypted_password)
                decrypted = cipher.decrypt(encrypted_bytes)
                password = unpad(decrypted, AES.block_size)
                return password.decode('utf-8')
            except Exception as e:
                logger.debug(f"AES method 1 failed: {e}")

        # Method 2: Hash the key data to get AES key
        try:
            aes_key = hashlib.sha256(key_data).digest()
            aes_iv = hashlib.md5(iv_data).digest()

            cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            encrypted_bytes = bytes.fromhex(encrypted_password)
            decrypted = cipher.decrypt(encrypted_bytes)
            password = unpad(decrypted, AES.block_size)
            return password.decode('utf-8')
        except Exception as e:
            logger.debug(f"AES method 2 failed: {e}")

        # Method 3: Direct base64 decode (original method)
        try:
            encrypted_bytes = base64.b64decode(encrypted_password)
            key = base64.b64decode(secretKey)
            iv = base64.b64decode(secretVector)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_bytes)
            password = unpad(decrypted, AES.block_size)
            return password.decode('utf-8')
        except Exception as e:
            logger.debug(f"AES method 3 failed: {e}")

    except Exception as e:
        logger.debug(f"AES decryption error: {e}")

    return None

def decrypt_mq_password(encrypted_password, secretKey, secretVector):
    """
    Decrypt MQ password using multiple methods

    The password returned from /GetMqConfig is encrypted and needs to be decrypted.
    We try multiple approaches since the exact method may vary by DSS version.
    """
    logger.info(f"Attempting to decrypt MQ password with {len(base64.b64decode(secretKey))} byte key...")

    # Try RSA first (since keys are 256 bytes)
    password = decrypt_mq_password_rsa(encrypted_password, secretKey, secretVector)
    if password:
        logger.info("✅ RSA decryption successful")
        return password

    # Try AES with different methods
    password = decrypt_mq_password_aes(encrypted_password, secretKey, secretVector)
    if password:
        logger.info("✅ AES decryption successful")
        return password

    logger.error("❌ All decryption methods failed")
    return None

def get_mq_config(token):
    """Get MQ configuration from DSS"""
    mq_endpoint = "/brms/api/v1.0/BRM/Config/GetMqConfig"
    mq_payload = {}
    logger.info(f"Calling MQ Config endpoint: {mq_endpoint}")
    mq_result = test_api_call(token, mq_endpoint, mq_payload, method="POST")
    return mq_result

def test_network_connectivity(host, port):
    """Test basic network connectivity to MQ broker"""
    logger.info(f"Testing network connectivity to {host}:{port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            logger.info("✅ Network connectivity: SUCCESS")
            return True
        else:
            logger.error(f"❌ Network connectivity: FAILED (error code: {result})")
            logger.error("   This might indicate firewall issues or the service is not running")
            return False
    except Exception as e:
        logger.error(f"❌ Network test error: {e}")
        return False

class MQSubscriber:
    def __init__(self, mq_config, username, password):
        self.mq_config = mq_config
        self.username = username
        self.password = password
        self.client = None
        self.connected = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5

    def on_connect(self, client, userdata, flags, rc):
        """Callback when connected to MQ broker"""
        if rc == 0:
            logger.info("✅ Connected to MQ broker successfully")
            self.connected = True
            self.reconnect_attempts = 0

            # Subscribe to relevant topics
            topics = [
                "mq.common.msg.topic",  # General message topic (receives all events)
                "vms.addVisitor",       # Visitor management events
                "face.recognition",     # Face recognition events
                "face.scan",           # Face scan events
                "alarm.event",         # Alarm events
                "device.status",       # Device status events
                "person.recognition",  # Person recognition events
                "access.control",      # Access control events
                "system.event"         # System events
            ]

            for topic in topics:
                client.subscribe(topic)
                logger.info(f"Subscribed to topic: {topic}")
        else:
            logger.error(f"❌ Failed to connect to MQ broker with result code {rc}")
            self.connected = False

    def on_message(self, client, userdata, msg):
        """Callback when message is received"""
        try:
            logger.info(f"📨 Received message on topic {msg.topic}")
            payload = json.loads(msg.payload.decode('utf-8'))
            logger.info("Message payload:")
            logger.info(json.dumps(payload, indent=2, ensure_ascii=False))

            # Handle specific event types
            self.handle_event(msg.topic, payload)

        except json.JSONDecodeError:
            logger.warning(f"Received non-JSON message: {msg.payload}")
        except Exception as e:
            logger.error(f"Error processing message: {e}")

    def handle_event(self, topic, payload):
        """Handle specific event types"""
        try:
            if topic == "vms.addVisitor":
                logger.info("=== VISITOR ADDED EVENT ===")
                visitor_id = payload.get('visitorId')
                visitor_name = payload.get('visitorName')
                visitor_phone = payload.get('visitorPhone')
                visit_time = payload.get('visitTime')
                logger.info(f"Visitor {visitor_name} (ID: {visitor_id}) was added")
                logger.info(f"Phone: {visitor_phone}, Time: {visit_time}")

            elif topic == "face.recognition":
                logger.info("=== FACE RECOGNITION EVENT ===")
                person_id = payload.get('personId')
                person_name = payload.get('personName')
                confidence = payload.get('confidence')
                device_id = payload.get('deviceId')
                recognition_time = payload.get('recognitionTime')
                logger.info(f"Face recognized: {person_name} (ID: {person_id})")
                logger.info(f"Confidence: {confidence}, Device: {device_id}")
                logger.info(f"Time: {recognition_time}")

            elif topic == "face.scan":
                logger.info("=== FACE SCAN EVENT ===")
                scan_id = payload.get('scanId')
                scan_time = payload.get('scanTime')
                device_id = payload.get('deviceId')
                scan_result = payload.get('scanResult')
                logger.info(f"Face scan detected: Scan ID {scan_id}")
                logger.info(f"Time: {scan_time}, Device: {device_id}")
                logger.info(f"Result: {scan_result}")

            elif topic == "alarm.event":
                logger.info("=== ALARM EVENT ===")
                alarm_type = payload.get('alarmType')
                alarm_level = payload.get('alarmLevel')
                alarm_time = payload.get('alarmTime')
                device_id = payload.get('deviceId')
                alarm_description = payload.get('alarmDescription')
                logger.info(f"Alarm triggered: Type {alarm_type}, Level: {alarm_level}")
                logger.info(f"Time: {alarm_time}, Device: {device_id}")
                logger.info(f"Description: {alarm_description}")

            elif topic == "device.status":
                logger.info("=== DEVICE STATUS EVENT ===")
                device_id = payload.get('deviceId')
                device_status = payload.get('deviceStatus')
                status_time = payload.get('statusTime')
                logger.info(f"Device {device_id} status: {device_status}")
                logger.info(f"Time: {status_time}")

            elif topic == "person.recognition":
                logger.info("=== PERSON RECOGNITION EVENT ===")
                person_id = payload.get('personId')
                person_name = payload.get('personName')
                confidence = payload.get('confidence')
                device_id = payload.get('deviceId')
                logger.info(f"Person recognized: {person_name} (ID: {person_id})")
                logger.info(f"Confidence: {confidence}, Device: {device_id}")

            elif topic == "access.control":
                logger.info("=== ACCESS CONTROL EVENT ===")
                access_type = payload.get('accessType')
                person_id = payload.get('personId')
                device_id = payload.get('deviceId')
                access_time = payload.get('accessTime')
                logger.info(f"Access control: Type {access_type}")
                logger.info(f"Person: {person_id}, Device: {device_id}")
                logger.info(f"Time: {access_time}")

            elif topic == "system.event":
                logger.info("=== SYSTEM EVENT ===")
                event_type = payload.get('eventType')
                event_description = payload.get('eventDescription')
                event_time = payload.get('eventTime')
                logger.info(f"System event: {event_type}")
                logger.info(f"Description: {event_description}")
                logger.info(f"Time: {event_time}")

            else:
                logger.info(f"=== UNKNOWN EVENT TYPE: {topic} ===")
                logger.info("Full payload:")
                logger.info(json.dumps(payload, indent=2, ensure_ascii=False))

        except Exception as e:
            logger.error(f"Error handling event {topic}: {e}")

    def on_disconnect(self, client, userdata, rc):
        """Callback when disconnected from MQ broker"""
        logger.warning(f"Disconnected from MQ broker with result code {rc}")
        self.connected = False

        # Attempt reconnection if not manually disconnected
        if rc != 0 and self.reconnect_attempts < self.max_reconnect_attempts:
            self.reconnect_attempts += 1
            logger.info(f"Attempting reconnection {self.reconnect_attempts}/{self.max_reconnect_attempts}")
            time.sleep(5)  # Wait before reconnecting
            self.connect()

    def connect(self):
        """Connect to MQ broker with comprehensive error handling"""
        try:
            # Create MQTT client with newer API version and proper client ID
            client_id = f"dahua_dss_client_{int(time.time())}"
            self.client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
            self.client.username_pw_set(self.username, self.password)

            # Set callbacks
            self.client.on_connect = self.on_connect
            self.client.on_message = self.on_message
            self.client.on_disconnect = self.on_disconnect

            # Configure TLS if enabled
            if self.mq_config.get('enableTls') == 1:
                logger.info("Configuring TLS connection...")
                self.client.tls_set(
                    ca_certs=None,  # Use system CA certificates
                    certfile=None,
                    keyfile=None,
                    cert_reqs=ssl.CERT_NONE,  # Start with no verification for testing
                    tls_version=ssl.PROTOCOL_TLS,
                    ciphers=None
                )
                self.client.tls_insecure_set(True)  # Allow insecure connections for testing

            # Try MQTT port first (1883), then fallback to ActiveMQ port (61616)
            mqtt_port = self.mq_config.get('mqtt', '192.168.100.254:1883')
            broker_addr = self.mq_config.get('addr', '192.168.100.254:61616')

            # Parse MQTT port first
            if ':' in mqtt_port:
                host, port = mqtt_port.split(':')
                port = int(port)
            else:
                host = mqtt_port
                port = 1883

            logger.info(f"Trying MQTT connection: {host}:{port}")

            # Test network connectivity first
            if not test_network_connectivity(host, port):
                logger.warning(f"MQTT port {port} not accessible, trying ActiveMQ port...")
                # Fallback to ActiveMQ port
                if ':' in broker_addr:
                    host, port = broker_addr.split(':')
                    port = int(port)
                else:
                    host = broker_addr
                    port = 61616
                logger.info(f"Trying ActiveMQ connection: {host}:{port}")

                if not test_network_connectivity(host, port):
                    logger.error("Network connectivity test failed. Please check:")
                    logger.error("1. Firewall settings (ports 1883, 61616)")
                    logger.error("2. Network connectivity to the broker")
                    logger.error("3. Whether the MQ service is running")
                    return False

            # Connect to broker
            self.client.connect(host, port, 60)

            # Start the loop in a separate thread
            self.client.loop_start()

            # Wait for connection
            timeout = 15
            while not self.connected and timeout > 0:
                time.sleep(1)
                timeout -= 1

            if not self.connected:
                logger.error("Failed to connect to MQ broker within timeout")
                return False

            return True

        except Exception as e:
            logger.error(f"Error connecting to MQ broker: {e}")
            return False

    def disconnect(self):
        """Disconnect from MQ broker"""
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()
            logger.info("Disconnected from MQ broker")

# General API test function for diagnostics
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

def main():
    """Main function to demonstrate MQ integration"""
    logger.info("=== Dahua DSS MQ Integration Demo ===")

    try:
        # Step 1: Login and get token
        logger.info("1. Logging in to DSS...")
        token, secretKey, secretVector = get_token_and_login()

        # Step 2: Get MQ configuration
        logger.info("2. Getting MQ configuration...")
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

        # Step 3: Decrypt MQ password
        logger.info("3. Decrypting MQ password...")
        encrypted_password = mq_config.get('password')
        if encrypted_password:
            mq_password = decrypt_mq_password(encrypted_password, secretKey, secretVector)
            if mq_password:
                logger.info(f"✅ Decrypted MQ password: {mq_password}")
            else:
                logger.error("❌ Failed to decrypt MQ password")
                logger.error("Trying common passwords as fallback...")
                # Try common passwords as fallback
                common_passwords = ["admin", "consumer", "password", "123456", "dahua", "system"]
                for pwd in common_passwords:
                    logger.info(f"Trying password: {pwd}")
                    if test_mq_connection_with_password(mq_config, pwd):
                        mq_password = pwd
                        logger.info(f"✅ Found working password: {pwd}")
                        break
                else:
                    logger.error("❌ No working password found")
                    return
        else:
            logger.error("No encrypted password found in MQ config")
            return

        # Step 4: Connect to MQ broker
        logger.info("4. Connecting to MQ broker...")
        mq_username = mq_config.get('userName', 'admin')

        subscriber = MQSubscriber(mq_config, mq_username, mq_password)

        if subscriber.connect():
            logger.info("✅ Successfully connected to MQ broker!")
            logger.info("Listening for events... (Press Ctrl+C to stop)")

            try:
                # Keep the main thread alive
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Stopping MQ subscriber...")
                subscriber.disconnect()
                logger.info("MQ subscriber stopped")
        else:
            logger.error("❌ Failed to connect to MQ broker")

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        import traceback
        logger.error(traceback.format_exc())

def test_mq_connection_with_password(mq_config, password):
    """Test MQ connection with a specific password"""
    try:
        client_id = f"test_client_{int(time.time())}"
        client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
        client.username_pw_set(mq_config.get('userName', 'admin'), password)

        # Configure TLS if enabled
        if mq_config.get('enableTls') == 1:
            client.tls_set(
                ca_certs=None,
                certfile=None,
                keyfile=None,
                cert_reqs=ssl.CERT_NONE,
                tls_version=ssl.PROTOCOL_TLS,
                ciphers=None
            )
            client.tls_insecure_set(True)

        # Parse broker address
        broker_addr = mq_config.get('addr', '192.168.100.254:61616')
        if ':' in broker_addr:
            host, port = broker_addr.split(':')
            port = int(port)
        else:
            host = broker_addr
            port = 61616

        # Quick connection test
        client.connect(host, port, 5)
        client.loop_start()
        time.sleep(3)
        client.loop_stop()
        client.disconnect()
        return True

    except Exception as e:
        logger.debug(f"Password {password} failed: {e}")
        return False

if __name__ == "__main__":
    main()
