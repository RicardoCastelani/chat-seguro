import socket
import threading
import sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

# Configurações
HOST = '127.0.0.1'  # Localhost
PORT = 5000
# Chave de exatamente 32 bytes para AES-256
KEY = b'12345678901234567890123456789012'  # 32 bytes exatos
IV = b'1234567890123456'  # 16 bytes exatos
PASSWORD = "senha123"  # Senha para autenticação

def encrypt_message(message):
    cipher = AES.new(KEY, AES.MODE_CFB, IV)
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    h = HMAC.new(KEY, digestmod=SHA256)
    h.update(ciphertext)
    return ciphertext + b'||' + h.digest()

def decrypt_message(data):
    try:
        ciphertext, mac = data.split(b'||', 1)
        h = HMAC.new(KEY, digestmod=SHA256)
        h.update(ciphertext)
        h.verify(mac)
        cipher = AES.new(KEY, AES.MODE_CFB, IV)
        return cipher.decrypt(ciphertext).decode('utf-8')
    except Exception as e:
        return f"[Erro na mensagem: {str(e)}]"

def handle_client(client_socket):
    # Autenticação
    client_socket.send(b'Digite a senha: ')
    password_attempt = client_socket.recv(1024).decode('utf-8').strip()
    
    if password_attempt != PASSWORD:
        client_socket.send(b'Senha incorreta. Conexao encerrada.')
        client_socket.close()
        return
    
    client_socket.send(b'Autenticado com sucesso! Bem-vindo ao chat seguro.')
    
    # Iniciando thread de recebimento
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.daemon = True
    receive_thread.start()
    
    try:
        # Thread principal continua enviando mensagens
        while True:
            msg = input("[Servidor]: ")
            if msg.lower() == 'sair':
                break
            encrypted_msg = encrypt_message(msg)
            client_socket.send(encrypted_msg)
    except:
        pass
    
    print("Conexão encerrada")
    client_socket.close()

def receive_messages(client_socket):
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print("\nCliente desconectado.")
                break
            
            decrypted_msg = decrypt_message(data)
            print(f"\n[Cliente]: {decrypted_msg}")
        except Exception as e:
            print(f"\nErro ao receber mensagem: {str(e)}")
            break

def main():
    try:
        # Criar socket do servidor
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Vincular ao endereço e porta
        server_socket.bind((HOST, PORT))
        
        # Escutar por conexões
        server_socket.listen(1)
        print(f"[*] Servidor iniciado em {HOST}:{PORT}")
        print("[*] Aguardando conexões...")
        
        # Aceitar conexão
        client_socket, addr = server_socket.accept()
        print(f"[+] Conexão aceita de {addr[0]}:{addr[1]}")
        
        # Tratar cliente
        handle_client(client_socket)
        
    except Exception as e:
        print(f"[!] Erro: {str(e)}")
    finally:
        if 'server_socket' in locals():
            server_socket.close()
        print("[*] Servidor encerrado.")

if __name__ == "__main__":
    main()