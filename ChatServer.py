import socket
import threading
import json
import logging
import os
from cryptography.fernet import Fernet
import sqlite3
import hashlib
import re

GREY = '\033[90m'
RED = '\033[91m'
BOLD_RED = '\033[1;91m'
YELLOW = '\033[93m'
RESET = '\033[0m'

FERNET_KEY = b'yPSePqvvRg6m-_nm4-BMT57M-91TrOnHfxRwjjlILVo='
FERNET = Fernet(FERNET_KEY)

login_pattern = r"TRY LOGIN \((\w+), ([\w\s!\"#$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]+)\)"
register_pattern = r"TRY REGISTER \((\w+), ([\w\s!\"#$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]+)\)"
heartbeat_pattern = r'^HEARTBEAT'
msghistory_pattern =r'^ASK MESSAGE HISTORY'

class CustomFormatter(logging.Formatter):
    format = '%(levelname)s - %(message)s (%(filename)s:%(lineno)d)'

    FORMATS = {
        logging.DEBUG: YELLOW + format + RESET,
        logging.INFO: GREY + format + RESET,
        logging.WARNING: YELLOW + format + RESET,
        logging.ERROR: RED + format + RESET,
        logging.CRITICAL: BOLD_RED + format + RESET
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

ch.setFormatter(CustomFormatter())

logger.addHandler(ch)

active_clients = []
addresses_and_usernames = {}


def register_user(username, password):
    try:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            cursor.execute('INSERT INTO users VALUES (?, ?)', (username, hashed_password))
            db.commit()
            return True
    except Exception as e:
        print(e,'register_user')


def login(sock, username, password, address):
    try:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, hashed_password))
            res = cursor.fetchone()

        if res is not None:
            addresses_and_usernames[address] = username
            sock.send('SUCCESS'.encode())

        else:
            sock.send('FAILURE'.encode())

        return res is not None
    except Exception as e:
        print(e,'login')

def register(sock, username, password, address):
    try:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, hashed_password))
            res = cursor.fetchone()

            if res is None:
                addresses_and_usernames[address] = username
                register_user(username, password)
                sock.send('SUCCESS'.encode())
            else:
                sock.send('FAILURE'.encode())
            
        return res is None
    except Exception as e:
        print(e,'register')

def generic_setup():
    if not os.path.isfile('users.db'):
        with sqlite3.connect('users.db') as db:
            cursor = db.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY,password TEXT)''')

    if not os.path.isfile('message_history.txt'):
        with open('message_history.txt', 'w') as f:
            f.write('')

def accept_clients(server_socket):
    client_socket, client_address = server_socket.accept()
    logger.info(f'Connection established @ {client_address}')
    
    active_clients.append(client_socket)

    client_socket.settimeout(timeout)

    client_thread = threading.Thread(target=handle_client, args=(client_socket,client_address))
    client_thread.start()


def parse_message(data, address):
    parsed_json = None
    try:
        parsed_json = json.loads(data)
    except json.JSONDecodeError as e:
        print("Error parsing JSON:", e)

    data = parsed_json if parsed_json else data
    
    usr = addresses_and_usernames[address]
    msg = data['message']
    
    return f'{usr}: {msg}'


def log_message(msg):
    with open('message_history.txt', 'a') as msgHistory:
        msg = FERNET.encrypt(bytes(msg,encoding='utf-8'))
        msgHistory.write(f'{msg}\n')
        

def send_message_history(client_socket):
    with open('message_history.txt', 'r') as f:
        message_history = f.readlines()
        decrypted_message_history = []
        if not message_history == '' and not message_history == b'':
            for m in message_history:
                if not m == '' or m is None:
                    m = m.replace('\n','').replace('"','')[2:][:-1]
                    m = FERNET.decrypt(bytes(m,encoding='utf-8'))
                    decrypted_message_history.append(m)
                
    t = str(decrypted_message_history)
    msg = f'MESSAGE-HISTORY: {t}'
    client_socket.send(msg.encode())

def send_client_list(sock):
    active_client_list = addresses_and_usernames.values()
    msg = f'ACTIVE-CLIENT-LIST: {active_client_list}'
    sock.send(msg.encode())
    
def send_to_clients(message):
    for client_socket in active_clients:
        try:
            client_socket.send(message)
        except:
            pass


def handle_client(client_socket: socket.socket, address):
    while 1:
        try:
            send_client_list(client_socket)

            data = client_socket.recv(102400000)
            data = data.decode()

            if data == 'quit':
                break

            trying_to_login = re.search(login_pattern, data)
            trying_to_register = re.search(register_pattern, data)
            sending_heartbeat = re.search(heartbeat_pattern, data)
            asking_msg_history = re.search(msghistory_pattern, data)

            if trying_to_login:
                username = trying_to_login.group(1)
                password = trying_to_login.group(2)

                # Print the extracted values
                if login(client_socket, username, password, address):
                    print(f'{username} logged in from {address}')
                    send_client_list(client_socket)
                else:
                    client_socket.send('FAILURE'.encode())
                    print(f'{username} wasn\'t able to login from {address}')

            elif trying_to_register:
                username = trying_to_register.group(1)
                password = trying_to_register.group(2)
            
                if register(client_socket, username, password, address):
                    client_socket.send('SUCCESS'.encode())
                    send_client_list(client_socket)
                else:
                    client_socket.send('FAILURE'.encode())

            elif asking_msg_history:
                threading.Thread(target=send_message_history, args=(client_socket, )).start()

            elif sending_heartbeat:
                logger.debug(f'Received heartbeat @ {address}')
            
            else:
                parsed_msg = parse_message(data, address)
                logger.info(f'Received message from {address} -> {data}')
                
                log_message(parsed_msg)
                
                parsed_msg = str(parsed_msg).encode()
                send_to_clients(parsed_msg)
    
        except Exception as e:
            logger.error(f'Something went wrong at {address}. Exception: {e}')
            break
    try:
        close_connection(client_socket, address)
        active_clients.remove(client_socket)
        addresses_and_usernames.pop(address)
    except KeyError:
        pass


def close_connection(client_socket: socket.socket, address):
    client_socket.close()
    logger.debug(f'Closed connection @ {address}')

def main():
    generic_setup()

    global host, port, timeout, heartbeat
    host = '10.140.0.240'
    port = 631
    timeout = 4.2
    heartbeat = 'HEARTBEAT'

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(10)

    logger.info(f'Server listening on {host}:{port}')

    while True:
        try:
            accept_clients(server_socket)
        except Exception as e:
            exit(logger.critical(e))


if __name__ == '__main__':
    main()
