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

def receive_messages(client_socket):
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print("\nConexão com o servidor perdida.")
                break
            
            # Verifica se é uma mensagem de texto simples
            if b'||' not in data:
                try:
                    print(f"\n{data.decode('utf-8')}")
                    continue
                except:
                    pass
            
            # Tenta descriptografar
            decrypted_msg = decrypt_message(data)
            print(f"\n[Servidor]: {decrypted_msg}")
                
        except Exception as e:
            print(f"\nErro ao receber mensagem: {str(e)}")
            break
    
    print("[*] Encerrando cliente...")
    sys.exit(0)

def main():
    try:
        # Criar socket do cliente
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Conectar ao servidor
        print(f"[*] Conectando ao servidor em {HOST}:{PORT}...")
        client_socket.connect((HOST, PORT))
        print("[+] Conectado ao servidor!")
        
        # Receber solicitação de senha
        prompt = client_socket.recv(1024).decode('utf-8')
        print(prompt, end='')
        
        # Enviar senha
        password = input()
        client_socket.send(password.encode('utf-8'))
        
        # Receber resposta de autenticação
        auth_response = client_socket.recv(1024).decode('utf-8')
        print(auth_response)
        
        if "incorreta" in auth_response:
            print("[!] Autenticação falhou. Encerrando.")
            client_socket.close()
            return
        
        # Iniciar thread para receber mensagens
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
        receive_thread.daemon = True
        receive_thread.start()
        
        # Loop principal para enviar mensagens
        print("\n[*] Digite suas mensagens (digite 'sair' para encerrar):")
        while True:
            msg = input("[Você]: ")
            if msg.lower() == 'sair':
                break
            
            encrypted_msg = encrypt_message(msg)
            client_socket.send(encrypted_msg)
            
    except ConnectionRefusedError:
        print("[!] Não foi possível conectar ao servidor. Verifique se o servidor está rodando.")
    except Exception as e:
        print(f"[!] Erro: {str(e)}")
    finally:
        if 'client_socket' in locals():
            client_socket.close()
        print("[*] Cliente encerrado.")

if __name__ == "__main__":
    main()