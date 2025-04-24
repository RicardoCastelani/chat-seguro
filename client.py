import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Gera chave AES a partir de senha
def gerar_chave_aes(senha):
    salt = b'salt_fixo'  # Em produção, use um salt aleatório seguro
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(senha.encode())

# Criptografa com AES e retorna IV + ciphertext + HMAC
def criptografar(mensagem, chave):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(chave), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(mensagem.encode()) + encryptor.finalize()

    h = hmac.HMAC(chave, hashes.SHA256())
    h.update(iv + ciphertext)
    tag = h.finalize()
    return iv + ciphertext + tag

# Descriptografa com verificação de HMAC
def descriptografar(dados, chave):
    iv = dados[:16]
    ciphertext = dados[16:-32]
    tag = dados[-32:]

    h = hmac.HMAC(chave, hashes.SHA256())
    h.update(iv + ciphertext)
    h.verify(tag)

    cipher = Cipher(algorithms.AES(chave), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Envia mensagem criptografadapip install cryptography

def enviar(sock, chave):
    while True:
        msg = input("> Você: ")
        criptografada = criptografar(msg, chave)
        sock.send(criptografada)

# Recebe e descriptografa mensagens
def receber(sock, chave):
    while True:
        try:
            dados = sock.recv(4096)
            msg = descriptografar(dados, chave).decode()
            print(f"\n< Outro: {msg}\n> Você: ", end="")
        except Exception as e:
            print("\n[!] Erro ou desconexão.")
            break

# Execução do cliente
def main():
    host = 'localhost'
    porta = 5000

    senha_compartilhada = input("Digite a senha compartilhada com seu colega: ")
    chave_aes = gerar_chave_aes(senha_compartilhada)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, porta))

    threading.Thread(target=receber, args=(sock, chave_aes), daemon=True).start()
    enviar(sock, chave_aes)

if __name__ == "__main__":
    main()
