import socket
import threading
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import hashlib

PORT = 5000
KEY = b'superseguranca123'  # 16 bytes
IV = b'16bytesivpraaes1'    # 16 bytes fixos (poderia ser aleatório e enviado com a mensagem)

def validate_password(conn):
    conn.sendall(b'Digite a senha para autenticar: ')
    received = conn.recv(1024).strip()
    if received != KEY:
        conn.sendall(b'Senha incorreta. Conexao encerrada.\n')
        conn.close()
        return False
    conn.sendall(b'Acesso autorizado. Bem-vindo ao chat seguro!\n')
    return True

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

def receive(conn):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            print("\n[CLIENTE]:", decrypt_message(data))
        except:
            print("\n[!] Erro ao receber a mensagem.")
            break

def send(conn):
    while True:
        try:
            msg = input("[Você]: ")
            encrypted = encrypt_message(msg)
            conn.sendall(encrypted)
        except:
            break

def main():
    server = socket.socket()
    server.bind(('', PORT))
    server.listen(1)
    print(f"Servidor escutando na porta {PORT}...")

    conn, addr = server.accept()
    print(f"Conectado por {addr}")

    if not validate_password(conn):
        return

    threading.Thread(target=receive, args=(conn,)).start()
    threading.Thread(target=send, args=(conn,)).start()

if __name__ == "__main__":
    main()
