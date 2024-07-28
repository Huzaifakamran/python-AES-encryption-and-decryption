from flask import Flask, request, render_template
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from base64 import b64decode

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
        # Here you can add your logic to validate the username and password
        # For demonstration purposes, I'm just printing them
        print(f"Encrypted password: {encrypted_password}")
        print("Decrypted password: ", decrypt_data(encrypted_password))
        return '200'

if __name__ == '__main__':
    app.run(debug=True)