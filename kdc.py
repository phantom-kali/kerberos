# kdc.py
# Run this in one terminal: python kdc.py

import socket
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import time

# Hardcoded keys (16 bytes for AES-128)
CLIENT_KEY = b'clientsecretkeyy'
TGS_KEY = b'tgssecretkeyyyyy'
SERVICE_KEY = b'serviceseckeyyyy'

# Lifetime in seconds
TICKET_LIFETIME = 3600  # 1 hour

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt(data, key):
    data = base64.b64decode(data)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def handle_as_request(client_name):
    # Generate client-TGS session key
    client_tgs_session_key = get_random_bytes(16)
    
    # Create TGT: encrypted with TGS_KEY
    tgt_data = {
        'client_name': client_name,
        'session_key': base64.b64encode(client_tgs_session_key).decode(),
        'timestamp': time.time(),
        'lifetime': TICKET_LIFETIME
    }
    tgt_enc = encrypt(json.dumps(tgt_data).encode(), TGS_KEY)
    
    # Encrypt session key and other info for client with CLIENT_KEY
    client_response_data = {
        'session_key': base64.b64encode(client_tgs_session_key).decode(),
        'timestamp': tgt_data['timestamp'],
        'lifetime': TICKET_LIFETIME
    }
    client_response_enc = encrypt(json.dumps(client_response_data).encode(), CLIENT_KEY)
    
    return {
        'tgt': tgt_enc.decode(),
        'client_response': client_response_enc.decode()
    }

def handle_tgs_request(tgt_enc, service_name, authenticator_enc):
    # Decrypt TGT with TGS_KEY
    tgt_data = json.loads(decrypt(tgt_enc.encode(), TGS_KEY).decode())
    client_tgs_session_key = base64.b64decode(tgt_data['session_key'])
    
    # Check timestamp in TGT
    if time.time() > tgt_data['timestamp'] + tgt_data['lifetime']:
        raise ValueError("TGT expired")
    
    # Decrypt authenticator with client_tgs_session_key
    authenticator = json.loads(decrypt(authenticator_enc.encode(), client_tgs_session_key).decode())
    if time.time() - authenticator['timestamp'] > 300:  # 5 min skew
        raise ValueError("Authenticator timestamp invalid")
    
    # Generate client-service session key
    client_service_session_key = get_random_bytes(16)
    
    # Create Service Ticket (ST): encrypted with SERVICE_KEY
    st_data = {
        'client_name': tgt_data['client_name'],
        'session_key': base64.b64encode(client_service_session_key).decode(),
        'timestamp': time.time(),
        'lifetime': TICKET_LIFETIME
    }
    st_enc = encrypt(json.dumps(st_data).encode(), SERVICE_KEY)
    
    # Encrypt session key for client with client_tgs_session_key
    client_response_data = {
        'session_key': base64.b64encode(client_service_session_key).decode(),
        'timestamp': st_data['timestamp'],
        'lifetime': TICKET_LIFETIME
    }
    client_response_enc = encrypt(json.dumps(client_response_data).encode(), client_tgs_session_key)
    
    return {
        'st': st_enc.decode(),
        'client_response': client_response_enc.decode()
    }

def start_kdc_server(host='0.0.0.0', port=8888):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"KDC listening on {host}:{port}")
        
        while True:
            conn, addr = s.accept()
            with conn:
                try:
                    data = conn.recv(4096).decode()
                    if not data:
                        # Empty connection, likely a health check
                        continue
                    request = json.loads(data)
                except json.JSONDecodeError:
                    # Invalid JSON, ignore and continue
                    continue
                except Exception as e:
                    print(f"Error receiving data: {e}")
                    continue
                
                response = {}
                try:
                    if request['type'] == 'AS':
                        response = handle_as_request(request['client_name'])
                    elif request['type'] == 'TGS':
                        response = handle_tgs_request(request['tgt'], request['service_name'], request['authenticator'])
                    else:
                        response = {'error': 'Invalid request type'}
                except Exception as e:
                    response = {'error': str(e)}
                
                conn.sendall(json.dumps(response).encode())

if __name__ == '__main__':
    start_kdc_server()
