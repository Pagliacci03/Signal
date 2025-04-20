import socket
import threading

# Lista para almacenar los dos clientes conectados
clients = []

def handle_client(client_socket, client_address, client_id):
    print(f"[+] Cliente {client_id} conectado desde {client_address}")

    if client_id == 0:
        message = "Bob"
        client_socket.send(message.encode())
        keys_received = client_socket.recv(1024)

        # Enviar llaves al otro cliente
        while True:
            other_client = clients[1 - client_id] if len(clients) == 2 else None
            if other_client:
                other_client.send(keys_received)
                break

    if client_id == 1:
        keys_received = client_socket.recv(1024)
        # Enviar llaves al otro cliente
        while True:
            other_client = clients[1 - client_id] if len(clients) == 2 else None
            if other_client:
                other_client.send(keys_received)
                break

    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                print(f"[-] Cliente {client_id} se ha desconectado.")
                break

            print(f"[{client_id}] -> {message.decode()}")

            # Enviar el mensaje al otro cliente
            other_client = clients[1 - client_id] if len(clients) == 2 else None
            if other_client:
                other_client.send(message)
        except:
            break

    client_socket.close()

def main():
    host = '0.0.0.0'
    port = 12345

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(2)

    print("[*] Servidor escuchando en el puerto", port)

    while len(clients) < 2:
        client_socket, client_address = server.accept()
        clients.append(client_socket)
        client_id = len(clients) - 1
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address, client_id))
        thread.start()

    print("[*] Ambos clientes están conectados. Pueden comenzar a chatear.")

if __name__ == "__main__":
    main()
