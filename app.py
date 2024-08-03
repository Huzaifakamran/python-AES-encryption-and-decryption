from flask import Flask, request, render_template,jsonify
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from base64 import b64decode,b64encode

def get_public_key():
    """Retrieve public key securely using pycryptodome methods."""
    key_binary = open("receiver.pem", 'rb')
    key = RSA.import_key(key_binary.read())
    key_binary.close()
    return key.public_key().export_key()


def get_private_key():
    """Retrieve private key securely using pycryptodome methods."""
    key_binary = open("private.pem", 'rb')
    key = RSA.import_key(key_binary.read())
    key_binary.close()
    return key

def encrypt_data(plain_text):
    """Encrypt data using public key."""
    public_key = RSA.import_key(get_public_key())
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_message = cipher.encrypt(plain_text.encode())
    return b64encode(encrypted_message).decode()

def decrypt_data(encrypted_value):
    """Decrypt data using private key obtained securely."""
    cipher = PKCS1_OAEP.new(get_private_key(), hashAlgo=SHA256)
    decrypted_message = cipher.decrypt(b64decode(encrypted_value))
    return decrypted_message.decode()

app = Flask(__name__)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # here we rendreing login template with public key
        return render_template('login.html', key=get_public_key())
    elif request.method == 'POST':
        encrypted_password = request.form['password']
        print(f"Encrypted password: {encrypted_password}")
        text = decrypt_data(encrypted_password)
        print("Decrypted password: ", text)
        test = encrypt_data(text)
        print('TEST',test)
        return jsonify({"response":test})

if __name__ == '__main__':
    app.run(debug=True)