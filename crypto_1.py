from flask import Flask, request
import scrypt
import hashlib
import hmac
import json
import os
from Crypto.Hash import RIPEMD
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app =Flask(__name__)

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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

