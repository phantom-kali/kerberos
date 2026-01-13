# service.py
# Run this in another terminal: python service.py

import socket
import json
from Crypto.Cipher import AES
import base64
import time

# Hardcoded key
SERVICE_KEY = b'serviceseckeyyyy'

def decrypt(data, key):
    data = base64.b64decode(data)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def handle_secure_connection(conn, addr, request):
    # AP_REQ already received and parsed in start_service_server
    if request['type'] != 'AP':
        conn.sendall(json.dumps({'error': 'Invalid request type'}).encode())
        return
    
    try:
        # Decrypt ST with SERVICE_KEY
        st_data = json.loads(decrypt(request['st'].encode(), SERVICE_KEY).decode())
        client_service_session_key = base64.b64decode(st_data['session_key'])
        
        # Check ST timestamp
        if time.time() > st_data['timestamp'] + st_data['lifetime']:
            raise ValueError("ST expired")
        
        # Decrypt authenticator with client_service_session_key
        authenticator = json.loads(decrypt(request['authenticator'].encode(), client_service_session_key).decode())
        if time.time() - authenticator['timestamp'] > 300:
            raise ValueError("Authenticator timestamp invalid")
        
        # Send success (could include service authenticator for mutual auth, but simplified)
        conn.sendall(json.dumps({'status': 'authenticated'}).encode())
        
        print(f"Service: Authenticated client {st_data['client_name']} from {addr}")
        
        # Now start secure chat
        while True:
            enc_message = conn.recv(4096).decode()
            if not enc_message:
                break
            message = decrypt(enc_message.encode(), client_service_session_key).decode()
            print(f"Client: {message}")
            
            if message.lower() == 'exit':
                break
            
            response = input("Service response: ")
            enc_response = encrypt(response.encode(), client_service_session_key)
            conn.sendall(enc_response.encode())
    
    except Exception as e:
        conn.sendall(json.dumps({'error': str(e)}).encode())

def handle_insecure_connection(conn, addr, request):
    """Reject insecure connections - Kerberos authentication is required."""
    error_msg = {
        'error': 'INSECURE MODE BLOCKED: Authentication denied. '
                 'This service requires Kerberos authentication. '
                 'Please use Kerberos mode for secure communication.',
        'status': 'rejected'
    }
    conn.sendall(json.dumps(error_msg).encode())
    print(f"Service: REJECTED insecure connection attempt from {addr} - Kerberos required")

def start_service_server(host='0.0.0.0', port=9999):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Service listening on {host}:{port}")
        
        while True:
            conn, addr = s.accept()
            with conn:
                try:
                    # Peek at first message to determine mode
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
                
                if request['type'] == 'AP':
                    handle_secure_connection(conn, addr, request)
                elif request['type'] == 'INSECURE':
                    # SECURITY PATCH: Block all insecure connections
                    handle_insecure_connection(conn, addr, request)
                else:
                    conn.sendall(json.dumps({'error': 'Invalid mode. Only Kerberos (AP) authentication is allowed.'}).encode())

if __name__ == '__main__':
    start_service_server()
