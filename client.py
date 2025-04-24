import socket
import threading
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

PORT = 5000
KEY = b'superseguranca123'
IV = b'16bytesivpraaes1'

def encrypt_message(message):
    cipher = AES.new(KEY, AES.MODE_CFB, IV)
    ciphertext = cipher.encrypt(message.encode())
    h = HMAC.new(KEY, digestmod=SHA256)
    h.update(ciphertext)
    return ciphertext + b'||' + h.digest()

def decrypt_message(data):
    try:
        ciphertext, mac = data.split(b'||')
        h = HMAC.new(KEY, digestmod=SHA256)
        h.update(ciphertext)
        h.verify(mac)
        cipher = AES.new(KEY, AES.MODE_CFB, IV)
        return cipher.decrypt(ciphertext).decode()
    except:
        return "[Mensagem alterada ou inválida]"

def receive(sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            print("\n[SERVIDOR]:", decrypt_message(data))
        except:
            print("\n[!] Erro ao receber a mensagem.")
            break

def send(sock):
    while True:
        try:
            msg = input("[Você]: ")
            encrypted = encrypt_message(msg)
            sock.sendall(encrypted)
        except:
            break

def main():
    sock = socket.socket()
    sock.connect(('localhost', PORT))
    
    response = sock.recv(1024).decode()
    print(response)
    password = input("> ").strip()
    sock.sendall(password.encode())

    auth = sock.recv(1024).decode()
    print(auth)
    if "incorreta" in auth:
        return

    threading.Thread(target=receive, args=(sock,)).start()
    threading.Thread(target=send, args=(sock,)).start()

if __name__ == "__main__":
    main()
