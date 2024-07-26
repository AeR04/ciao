import socket
import threading
import sys
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import msvcrt
import time

def setup_encryption(password):
    salt = b'salt_'  # Deve corrispondere al salt usato dal server
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def receive_messages(client_socket, fernet):
    global current_input
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                decrypted_message = fernet.decrypt(encrypted_message).decode()
                print(f"\r{' ' * 100}\r{decrypted_message}")  # Pulisce la linea corrente prima di stampare il messaggio
                print(f"[{nome_pc}]: {current_input}", end='', flush=True)  # Ristampa l'input corrente
            else:
                print("\nConnessione persa con il server.")
                sys.exit()
        except:
            print("\nSi è verificato un errore.")
            client_socket.close()
            sys.exit()

def get_input():
    global current_input
    current_input = ""
    while True:
        if msvcrt.kbhit():
            char = msvcrt.getwch()
            if char == '\r':  # Enter key
                return current_input
            elif char == '\b':  # Backspace
                if current_input:
                    current_input = current_input[:-1]
                    print(f"\r[{nome_pc}]: {current_input} ", end='', flush=True)
            else:
                current_input += char
                print(f"\r[{nome_pc}]: {current_input}", end='', flush=True)

def send_messages(client_socket, fernet, nome_pc):
    global current_input
    while True:
        message = get_input()
        if message:
            print()  # Move to the next line after sending
            encrypted_message = fernet.encrypt(message.encode())
            client_socket.send(encrypted_message)
        current_input = ""

def loading_animation(duration):
    chars = ['|', '/', '-', '\\']
    start_time = time.time()
    while time.time() - start_time < duration:
        for char in chars:
            print(f"\rConnessione in corso... {char}", end='', flush=True)
            time.sleep(0.1)
    print("\r" + " " * 30, end='', flush=True)  # Clear the line

def main():
    global nome_pc, current_input
    current_input = ""
    
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 5000

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
    except:
        print("Impossibile connettersi al server.")
        sys.exit()
    os.system('cls' if os.name == 'nt' else 'clear')
    room_id = input("Inserisci l'ID della stanza: ")
    password = input("Inserisci la password della stanza: ")
    nome_pc = os.environ.get('COMPUTERNAME', os.environ.get('HOSTNAME', 'Unknown'))

    client_socket.send(f"{room_id}:{password}:{nome_pc}".encode('utf-8'))

    response = client_socket.recv(1024).decode('utf-8')
    if response != "no_anon" and response != "si_anon":
        print("ID stanza o password non validi.")
        client_socket.close()
        sys.exit()

    loading_animation(3)

    fernet = setup_encryption(password)

    os.system('cls' if os.name == 'nt' else 'clear')
    anonimo = "Stanza non anonima."
    if response == "si_anon": 
        anonimo = "Stanza anonima."
    print("Connesso alla chat. Inizia a digitare i tuoi messaggi. " + anonimo)

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, fernet))
    receive_thread.daemon = True
    receive_thread.start()

    send_messages(client_socket, fernet, nome_pc)

if __name__ == "__main__":
    main()