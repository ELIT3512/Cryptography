from flask import Flask, request
import scrypt
import hashlib
import hmac
import json
import os
from Crypto.Hash import RIPEMD
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from ecies.utils import generate_key
from Crypto.Util.Padding import unpad
from ecies import encrypt, decrypt
from coincurve import PublicKey
import binascii

app =Flask(__name__)

# Generate EC key pairs (Peer 1 and Peer 2)
peer1_private_key = generate_key()
peer1_public_key = peer1_private_key.public_key
peer1_public_key_hex = peer1_public_key.format(True).hex()

peer2_private_key = generate_key()
peer2_public_key = peer2_private_key.public_key
peer2_public_key_hex = peer2_public_key.format(True).hex() 

print(f"Peer 1 Private Key: {peer1_private_key.to_hex()}")
print(f"Peer 1 Public Key: {peer1_public_key_hex}")
print(f"Peer 2 Private Key: {peer2_private_key.to_hex()}")
print(f"Peer 2 Public Key: {peer2_public_key_hex}")

@app.route('/crypto1/sha256', methods=["POST"])
def sha256_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    hash_value = hashlib.sha256(values["msg"].encode()).hexdigest()

    response = {"hash": hash_value}

    return json.dumps(response), 201

@app.route('/crypto1/sha512', methods=["POST"])
def sha512_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    hash_value = hashlib.sha512(values["msg"].encode()).hexdigest()

    response = {"hash": hash_value}

    return json.dumps(response), 201

@app.route('/crypto1/ripemd160', methods=["POST"])
def ripemd160_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg"]
    if not all(k in values for k in required):
        return "Missing values", 400

    hash_obj = RIPEMD.new()
    hash_obj.update(values["msg"].encode())
    hash_value = hash_obj.hexdigest()

    response = {"hash": hash_value}

    return json.dumps(response), 201

@app.route('/crypto1/hmac', methods=["POST"])
def hmac_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["msg", "key"]
    if not all(k in values for k in required):
        return "Missing values", 400

    hmac_value = hmac.new(values["key"].encode(), values["msg"].encode(), hashlib.sha256).hexdigest()

    response = {"hmac": hmac_value}

    return json.dumps(response), 201

@app.route('/crypto1/scrypt', methods=["POST"])
def scrypt_endpoint():
    values = request.get_json()
    if not values:
        return "Missing body", 400

    required = ["password", "salt"]
    if not all(k in values for k in required):
        return "Missing values", 400

    derived_key = scrypt.hash(values["password"], values["salt"], N=16384, r=16, p=1, buflen=32)

    response = {"key": derived_key.hex()}

    return json.dumps(response), 201

@app.route('/crypto1/encrypt', methods=["POST"])
def encrypt_endpoint():
    values = request.get_json()

    # Ensure values are provided before accessing keys
    if not values:
        return json.dumps({"error": "Missing body"}), 400

    required = ["password", "message"]
    if not all(k in values for k in required):
        return json.dumps({"error": "Missing values"}), 400

    password = values["password"].encode()  # Ensure password is bytes
    message = values["message"]

    # Generate a 256-bit (32-byte) random salt
    salt = os.urandom(32)

    # Derive a 512-bit key (64 bytes) using Scrypt
    dklen = 64  # 512 bits
    n, r, p = 16384, 16, 1  # Scrypt parameters
    derived_key = scrypt.hash(password, salt, N=n, r=r, p=p, buflen=dklen)

    # Split derived key into encryption key (32 bytes) and HMAC key (32 bytes)
    enc_key = derived_key[:32]
    hmac_key = derived_key[32:]

    # Generate a 128-bit (16-byte) random IV
    iv = os.urandom(16)

    # Pad and encrypt the message using AES-256 CBC
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

    # Generate HMAC-SHA256 authentication code
    mac = hmac.new(hmac_key, ciphertext, hashlib.sha256).hexdigest()

    # Prepare the output JSON structure
    encrypted_data = {
        "scrypt": {
            "dklen": dklen,
            "salt": salt.hex(),
            "n": n,
            "r": r,
            "p": p
        },
        "aes": ciphertext.hex(),
        "iv": iv.hex(),
        "mac": mac
    }

    return json.dumps(encrypted_data, indent=4), 201

@app.route('/crypto1/decrypt', methods=["POST"])
def decrypt_endpoint():
    values = request.get_json()
    if not values:
        return json.dumps({"error": "Missing body"}), 400

    required = ["password", "encrypted_json"]
    if not all(k in values for k in required):
        return json.dumps({"error": "Missing values"}), 400

    password = values["password"].encode()  # Ensure password is bytes
    encrypted_data = values["encrypted_json"]  # Directly use the dict, no need for json.loads()

    try:
        # Extract Scrypt parameters
        salt = bytes.fromhex(encrypted_data["scrypt"]["salt"])
        dklen = encrypted_data["scrypt"]["dklen"]
        n, r, p = encrypted_data["scrypt"]["n"], encrypted_data["scrypt"]["r"], encrypted_data["scrypt"]["p"]

        # Derive a 512-bit key (64 bytes) using Scrypt
        derived_key = scrypt.hash(password, salt, N=n, r=r, p=p, buflen=dklen)

        # Split derived key into encryption key (32 bytes) and HMAC key (32 bytes)
        enc_key = derived_key[:32]
        hmac_key = derived_key[32:]

        # Extract IV, ciphertext, and MAC
        iv = bytes.fromhex(encrypted_data["iv"])
        ciphertext = bytes.fromhex(encrypted_data["aes"])
        stored_mac = encrypted_data["mac"]

        # Verify HMAC before decryption
        computed_mac = hmac.new(hmac_key, ciphertext, hashlib.sha256).hexdigest()
        if computed_mac != stored_mac:
            return json.dumps({"error": "HMAC verification failed! Incorrect password or data corruption."}), 401

        # Decrypt the message using AES-256 CBC
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

        # Return decrypted message in JSON format
        return json.dumps({"decrypted_message": decrypted_message}), 200

    except Exception as e:
        return json.dumps({"error": str(e)}), 500

@app.route('/crypto1/asymmetric_encrypt', methods=["POST"])
def asymmetric_encrypt_endpoint():
    values = request.get_json()
    if not values:
        return json.dumps({"error": "Missing body"}), 400

    required = ["message"]
    if not all(k in values for k in required):
        return json.dumps({"error": "Missing values"}), 400

    # Message to encrypt
    message = values["message"].encode()

    # Generate a 16-byte IV
    iv = os.urandom(16)

    # Compute shared secret using Peer 1's private key and Peer 2's public key
    shared_secret = peer1_private_key.ecdh(peer2_public_key.format())

    # Convert shared secret to hex format
    shared_secret_hex = binascii.hexlify(shared_secret).decode()

    #  Extract the Correct 32-Byte AES Key**
    shared_secret_bytes = binascii.unhexlify(shared_secret_hex)
    if len(shared_secret_bytes) >= 33:
        aes_key = shared_secret_bytes[1:33]  # Remove first byte, take 32 bytes
    else:
        aes_key = shared_secret_bytes[-32:]  # Take last 32 bytes if shorter

    #  Process IV to Ensure Correct 14-Byte Counter**
    iv_bytes = iv[2:] if len(iv) > 2 else iv  # Ensure IV remains 14 bytes
    ctr_nonce = iv_bytes[:14]  # First 14 bytes used as nonce

    # **AES-256-CTR Encryption with PKCS7 Padding**
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=ctr_nonce)
    encrypted_message_aes = cipher.encrypt(pad(message, AES.block_size))

    # **Calculate HMAC-SHA256**
    mac = hmac.new(aes_key, encrypted_message_aes, hashlib.sha256).hexdigest()

    # **Prepare Response**
    response = {
        "peer1_public_key": peer1_public_key_hex,
        "iv": iv.hex(),
        "hmac": mac,
        "encrypted_message": binascii.hexlify(encrypted_message_aes).decode()
    }

    return json.dumps(response, indent=4), 201

@app.route('/crypto1/asymmetric_decrypt', methods=["POST"])
def asymmetric_decrypt_endpoint():
    values = request.get_json()
    if not values:
        return json.dumps({"error": "Missing body"}), 400

    required = ["encrypted_message", "hmac", "iv", "peer1_public_key"]
    if not all(k in values for k in required):
        return json.dumps({"error": "Missing values"}), 400

    # **Extract values from request**
    encrypted_message = binascii.unhexlify(values["encrypted_message"])
    hmac_received = values["hmac"]
    iv = binascii.unhexlify(values["iv"])
    peer1_public_key_input_hex = values["peer1_public_key"]

    # **Convert Peer 1's Public Key from HEX to an EC PublicKey Object**
    peer1_public_key_input = PublicKey(binascii.unhexlify(peer1_public_key_input_hex))

    # **Compute shared secret using Peer 2's private key and Peer 1's public key**
    shared_secret = peer2_private_key.ecdh(peer1_public_key_input.format())

    # Convert shared secret to hex format
    shared_secret_hex = binascii.hexlify(shared_secret).decode()

    # **Extract 32-byte AES key from shared secret**
    shared_secret_bytes = binascii.unhexlify(shared_secret_hex)
    if len(shared_secret_bytes) >= 33:
        aes_key = shared_secret_bytes[1:33]  # Remove first byte, take 32 bytes
    else:
        aes_key = shared_secret_bytes[-32:]  # Take last 32 bytes if shorter

    # **Process IV (Remove first 2 bytes for CTR mode)**
    iv_bytes = iv[2:] if len(iv) > 2 else iv  # Ensure IV remains 14 bytes
    ctr_nonce = iv_bytes[:14]  # Use first 14 bytes as nonce

    # **Verify HMAC BEFORE Decryption**
    hmac_computed = hmac.new(aes_key, encrypted_message, hashlib.sha256).hexdigest()
    if hmac_computed != hmac_received:
        return json.dumps({"error": "HMAC verification failed! Message integrity compromised."}), 401

    # **AES-256-CTR Decryption**
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=ctr_nonce)
    decrypted_message = cipher.decrypt(encrypted_message)

    # **Remove PKCS7 Padding (If Padding Was Used During Encryption)**
    try:
        decrypted_message = unpad(decrypted_message, AES.block_size).decode()
    except ValueError:
        return json.dumps({"error": "Padding is incorrect. Decryption may be invalid."}), 400

    # **Return Decrypted Message**
    response = {
        "decrypted_message": decrypted_message,
        "hmac_verified": True
    }

    return json.dumps(response, indent=4), 200
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

