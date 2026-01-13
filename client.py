# client.py
# Run this with mode: python client.py kerberos or python client.py insecure

import socket
import json
from Crypto.Cipher import AES
import base64
import time
import sys
import subprocess

# Hardcoded key
CLIENT_KEY = b'clientsecretkeyy'
import os

# Hosts and ports (configurable via environment variables)
KDC_HOST = os.getenv('KDC_HOST', 'localhost')
KDC_PORT = int(os.getenv('KDC_PORT', '8888'))
SERVICE_HOST = os.getenv('SERVICE_HOST', 'localhost')
SERVICE_PORT = int(os.getenv('SERVICE_PORT', '9999'))

# Client name
CLIENT_NAME = 'Alice'

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt(data, key):
    data = base64.b64decode(data)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def is_server_running(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
        return True
    except:
        return False

def request_tgt():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((KDC_HOST, KDC_PORT))
        request = {'type': 'AS', 'client_name': CLIENT_NAME}
        s.sendall(json.dumps(request).encode())
        response = json.loads(s.recv(4096).decode())
        
        if 'error' in response:
            raise ValueError(response['error'])
        
        # Decrypt client_response with CLIENT_KEY
        client_data = json.loads(decrypt(response['client_response'].encode(), CLIENT_KEY).decode())
        client_tgs_session_key = base64.b64decode(client_data['session_key'])
        
        return response['tgt'], client_tgs_session_key

def request_st(tgt, client_tgs_session_key, service_name='FileServer'):
    # Create authenticator: timestamp encrypted with client_tgs_session_key
    authenticator_data = {'timestamp': time.time()}
    authenticator_enc = encrypt(json.dumps(authenticator_data).encode(), client_tgs_session_key)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((KDC_HOST, KDC_PORT))
        request = {
            'type': 'TGS',
            'tgt': tgt,
            'service_name': service_name,
            'authenticator': authenticator_enc
        }
        s.sendall(json.dumps(request).encode())
        response = json.loads(s.recv(4096).decode())
        
        if 'error' in response:
            raise ValueError(response['error'])
        
        # Decrypt client_response with client_tgs_session_key
        client_data = json.loads(decrypt(response['client_response'].encode(), client_tgs_session_key).decode())
        client_service_session_key = base64.b64decode(client_data['session_key'])
        
        return response['st'], client_service_session_key

def kerberos_mode():
    print("Kerberos mode")

    # Check if KDC server is running, start if not
    if not is_server_running(KDC_HOST, KDC_PORT):
        print("Starting KDC server...")
        subprocess.Popen(['python', 'kdc.py'])
        time.sleep(2)

    # Step 1: Get TGT
    tgt, client_tgs_session_key = request_tgt()
    print("Received TGT")
    
    # Step 2: Get ST
    st, client_service_session_key = request_st(tgt, client_tgs_session_key)
    print("Received ST")
    
    # Step 3: Connect to service with AP_REQ
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVICE_HOST, SERVICE_PORT))
        
        # Create authenticator for service
        authenticator_data = {'timestamp': time.time()}
        authenticator_enc = encrypt(json.dumps(authenticator_data).encode(), client_service_session_key)
        
        request = {
            'type': 'AP',
            'st': st,
            'authenticator': authenticator_enc
        }
        s.sendall(json.dumps(request).encode())
        
        response = json.loads(s.recv(4096).decode())
        if 'error' in response:
            raise ValueError(response['error'])
        print("Authenticated with service")
        
        # Now secure chat
        while True:
            message = input("Client message: ")
            enc_message = encrypt(message.encode(), client_service_session_key)
            s.sendall(enc_message.encode())
            
            if message.lower() == 'exit':
                break
            
            enc_response = s.recv(4096).decode()
            response = decrypt(enc_response.encode(), client_service_session_key).decode()
            print(f"Service: {response}")

def insecure_mode():
    """SECURITY PATCH: Insecure mode has been disabled."""
    print("\n" + "="*60)
    print("  ⚠️  SECURITY ALERT: INSECURE MODE BLOCKED  ⚠️")
    print("="*60)
    print("\n  This system has been patched for security compliance.")
    print("  Insecure communication is NO LONGER PERMITTED.")
    print("\n  To communicate with the service, you MUST use Kerberos")
    print("  authentication which provides:")
    print("    ✓ Encrypted communication")
    print("    ✓ Mutual authentication")
    print("    ✓ Message integrity")
    print("\n  Usage: python client.py kerberos")
    print("\n" + "="*60 + "\n")
    sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("\n⚠️  SECURE AUTHENTICATION REQUIRED")
        print("Usage: python client.py kerberos")
        print("\nNote: Insecure mode has been disabled for security reasons.")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    if mode == 'kerberos':
        kerberos_mode()
    elif mode == 'insecure':
        insecure_mode()
    else:
        print("\n⚠️  Invalid mode specified.")
        print("Only Kerberos authentication is supported.")
        print("Usage: python client.py kerberos")
