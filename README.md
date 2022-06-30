# CrytograpyCodes
This assessment has been designed to evaluate your practical skills in application of cryptographic methods and algorithms in software development

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import secrets


# RSA ENCRYPTION

def generate_private_key():
    return RSA.generate(2048)


def get_public_key(private_key: RSA.RsaKey):
    return private_key.public_key()


def encrypt_key(raw_key: str, public_key: RSA.RsaKey):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(raw_key.encode('utf-8'))


def decrypt_key(encrypted_key: str, private_key: RSA.RsaKey):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_key).decode('utf-8')


# AES ENCRYPTION

def _encode_aes(cipher, password, block_size):
    return base64.b64encode(cipher.encrypt(pad(password, block_size)))


def _decode_aes(cipher, encoded_data, block_size):
    return unpad(cipher.decrypt(base64.b64decode(encoded_data)), block_size)


def _encode_data(raw_data, cipher, block_size=32):
    encoded_data = _encode_aes(cipher, raw_data, block_size)

    return _encode_aes(cipher, encoded_data, block_size)


def _decode_data(data, cipher, block_size=32):
    decoded_data = _decode_aes(cipher, data, block_size)
    return _decode_aes(cipher, decoded_data, block_size)


def generate_cipher(block_size=32):
    s = secrets.token_hex(block_size)
    return s


def get_cipher(key: str):
    return AES.new(key.encode('utf-8'), AES.MODE_ECB)


def get_token():
    key = generate_cipher(block_size=8)
    return key


def decode_token(token):
    token = token.encode('utf-8')
    cipher = get_cipher(token)
    return [token, cipher]


def encode_data(raw_data: str, key: str):
    cipher = get_cipher(key)
    encoded_data = _encode_data(raw_data, cipher)
    return encoded_data.decode('utf-8')


def decode_data(encoded_data: str, key: str):
    cipher = get_cipher(key)
    return _decode_data(encoded_data.encode('utf-8'), cipher)
    
    import sender
import base64

if __name__ == '__main__':
    message_bytes = open('./JAMESDYER.jpg', 'rb')
    message_string = base64.b64encode(message_bytes.read())
    receiver_key = sender.get_public_key()
    secret, encrypted_secret = sender.generate_and_encrypt_secret(receiver_key)
    sender.encrypt_and_send_message_to_receiver(message_string, secret, encrypted_secret)
    
    import base64
import encryption as enc

private_key = enc.generate_private_key()
public_key = enc.get_public_key(private_key)

mock_session = {}


# Once Sender Initiates Handshake with receiver
# Send Receivers Public Key to the sender
def send_public_key():
    return public_key


# Receive Encrypted secret, decrypt it and store in the receivers session
# def receive_encrypted_secret(secret: str):
#     mock_session['encrypted_secret'] = enc.decrypt_key(secret, private_key)
#     return


# Receive Encrypted Message, Decrypt it and print on stdout
def receive_encrypted_message(encrypted_message: str, encrypted_secret: str):
    with open('./encrypted_image.txt', 'w') as textFile:
        textFile.write(encrypted_message)
    secret = enc.decrypt_key(encrypted_secret, private_key)
    decrypted_message = enc.decode_data(encrypted_message, secret)
    msg_string = base64.b64decode(decrypted_message)
    with open('./decoded.jpg', 'wb') as file:
        file.write(msg_string)
        
        import encryption as enc
import reciever

private_key = enc.generate_private_key()
public_key = enc.get_public_key(private_key)


# Initiate Handshake to exchange Public Keys from Receiver
def get_public_key():
    receivers_public_key = reciever.send_public_key()
    return receivers_public_key


# Encrypt AES secret with receivers public key and send
def generate_and_encrypt_secret(receivers_public_key: enc.RSA.RsaKey):
    secret = enc.get_token()
    encrypted_secret = enc.encrypt_key(secret, receivers_public_key)
    return [secret, encrypted_secret]


# Send encrypted key to receiver
# NOTE: this is a secure channel for encryption key exchange
# def send_encrypted_secret_to_receiver(encrypted_secret: str):
#     reciever.receive_encrypted_secret(encrypted_secret)
#     return
