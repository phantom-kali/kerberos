# service.py
# Run this in another terminal: python service.py

import socket
import json
from Crypto.Cipher import AES
import base64
import time

# Hardcoded key
SERVICE_KEY = b'serviceseckey123'

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

def handle_secure_connection(conn, addr):
    # Receive AP_REQ: ST + authenticator
    data = conn.recv(4096).decode()
    request = json.loads(data)
    
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

def handle_insecure_connection(conn, addr):
    conn.sendall(json.dumps({'status': 'insecure_connected'}).encode())
    print(f"Service: Insecure connection from {addr}")
    
    while True:
        message = conn.recv(4096).decode()
        if not message:
            break
        print(f"Client (insecure): {message}")
        
        if message.lower() == 'exit':
            break
        
        response = input("Service response: ")
        conn.sendall(response.encode())

def start_service_server(host='localhost', port=9999):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Service listening on {host}:{port}")
        
        while True:
            conn, addr = s.accept()
            with conn:
                # Peek at first message to determine mode
                data = conn.recv(4096).decode()
                request = json.loads(data)
                
                if request['type'] == 'AP':
                    handle_secure_connection(conn, addr)
                elif request['type'] == 'INSECURE':
                    handle_insecure_connection(conn, addr)
                else:
                    conn.sendall(json.dumps({'error': 'Invalid mode'}).encode())

if __name__ == '__main__':
    start_service_server()
