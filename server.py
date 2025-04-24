import socket
import threading

def handle_client(client_socket, partner_socket):
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                break
            partner_socket.send(data)
        except:
            break

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5000))
    server.listen(2)
    print("[+] Servidor aguardando conexões...")

    client1, _ = server.accept()
    print("[+] Cliente 1 conectado.")
    client2, _ = server.accept()
    print("[+] Cliente 2 conectado.")

    threading.Thread(target=handle_client, args=(client1, client2)).start()
    threading.Thread(target=handle_client, args=(client2, client1)).start()

if __name__ == "__main__":
    main()
