import json
import socket
import os
import sys

import keys

SAVE_DIRECTORY = "downloads"
MAIN_DIRECTORY = r"C:\Users\Apple\OneDrive\Documents\GitHub\phase2-test\FTP_Files"
VALID_COMMANDS = {'LIST', 'STOR', 'USER', 'PASS', 'RETR', 'DELE', 'MKD', 'RMD', 'PWD', 'CWD', 'CDUP', 'QUIT'}


class FTPclient:
    def __init__(self, address, port, data_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = address
        self.port = int(port)
        self.data_port = int(data_port)
        self.authenticated = False
        self.current_directory = MAIN_DIRECTORY

        self.public_key = {}

        self.p = 97
        self.d = 83
        self.N, self.e, self.d = keys.get_peivate_And_public_key(self.p, self.d,'client')
        self.client_public_key = {"N": self.N, "e": self.e}
        self.client_private_key = {"N": self.N, "d": self.d}
    def validate_path(self, requested_path):
        """
        Ensure the requested path stays within the MAIN_DIRECTORY.
        """
        abs_path = os.path.abspath(os.path.join(self.current_directory, requested_path)).lower()
        if abs_path.startswith(os.path.abspath(MAIN_DIRECTORY.lower())):
            return abs_path
        else:
            print("Access denied: Cannot access outside of the main directory.")
            return None

    def create_connection(self):
        print('Starting connection to', self.address, ':', self.port)

        try:
            server_address = (self.address, self.port)
            self.sock.connect(server_address)
            print('Connected to', self.address, ':', self.port)
            self.sock.send(f"client_Public_Key: {self.client_public_key}".encode())

            input_str = self.sock.recv(1024).decode()
            print(input_str)
            dict_part = input_str.split(": ", 1)[1]
            dict_part_json = dict_part.replace("'", '"')
            self.public_key = json.loads(dict_part_json)
            print(f"Server_Public_Key: {self.public_key}")

        except KeyboardInterrupt:
            self.close_client()
        except Exception as e:
            print('Connection to', self.address, ':', self.port, 'failed$:', str(e))
            self.close_client()

    # TODO Implement USER
    def USER(self):
        # Prompt user for a username
        username = input("Enter username: ")
        self.sock.send(f"USER {username}\r\n".encode())
        response = self.sock.recv(1024).decode()
        print(response)

        # Check server response
        if response.startswith("331"):  # Username OK, need password
            self.PASS()
        else:
            print("Authentication failed.")
            self.close_client()

    # TODO Implement PASS
    def PASS(self):

        password = input("Enter password: ")
        self.sock.send(f"PASS {password}\r\n".encode())
        response = self.sock.recv(1024).decode()
        print(response)

        # Check server response
        if response.startswith("230"):
            print("Authentication successful!")
            self.authenticated = True
        else:
            print("Authentication failed.")
            self.close_client()

    def start(self):
        try:
            self.create_connection()
        except Exception as e:
            print("Error starting client:", str(e))
            self.close_client()

        while True:
            try:
                command = input('Enter command: ')
                if not command:
                    print('Need a command.')
                    continue
            except KeyboardInterrupt:
                self.close_client()
            cmd = command[:4].strip().upper()
            path = command[4:].strip()

            if cmd not in VALID_COMMANDS:
                print(f"Invalid command: {cmd}^")
                continue

            try:
                print(f"not enc: {command}")
                encrypted = keys.encrypt_message(command,self.public_key['N'],self.public_key['e'])
                print(f"after enc: {encrypted}")
                self.sock.send(encrypted.encode())
                data = self.sock.recv(1024).decode()
                print(data)

                if cmd == 'QUIT':
                    self.close_client()
                elif cmd in ['LIST', 'STOR', 'RETR','RMD']:
                    if data and data[:3] == '125':
                        func = getattr(self, cmd)
                        func(path)
                        data = self.sock.recv(1024).decode()
                        print(data)



                # elif cmd == 'RMD':
                #     self.sock.send(command.encode())
                #     data = self.sock.recv(1024).decode()

            except Exception as e:
                print("Error in client main loop:", str(e))
                self.close_client()

    def connect_datasock(self):
        self.datasock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.datasock.connect((self.address, self.data_port))
        print("data_sock connected")

    def RETR(self, path):
        print(f"Retrieving {path} from the server")
        if not os.path.exists(SAVE_DIRECTORY):
            os.makedirs(SAVE_DIRECTORY)
        try:
            self.connect_datasock()
            file_path = os.path.join(SAVE_DIRECTORY, os.path.basename(path))
            print(file_path)
            with open(file_path, 'wb') as f:  # Open file in binary mode
                while True:
                    download = self.datasock.recv(1024)
                    if not download:
                        break
                    decrypted_data = keys.decrypt_message(download.decode(), self.N, self.d)
                    download_to_byte = decrypted_data[2:-1].replace("\\r", "\r").replace("\\n", "\n").encode()
                    f.write(download_to_byte)
        except Exception as e:
            print("Error *: ", str(e))
        finally:
            self.datasock.close()
    # TODO Implement LIST
    def LIST(self, path):
        try:

            if not path:
                path = '.'

            self.connect_datasock()

            while True:
                dirlist = self.datasock.recv(1024).decode()
                if not dirlist:
                    break
                sys.stdout.write(dirlist)
                sys.stdout.flush()
        except Exception as e:
            print("Error during LIST command:", str(e))
        finally:
            self.datasock.close()

    # TODO Implement STOR
    def STOR(self, two_path):
        client_path, server_path = two_path.split(maxsplit=1)

        print(f"0: {client_path}")
        print(f"1: {server_path}")

        if not os.path.isfile(client_path):
            print(f"Error: File '{client_path}' does not exist.")
            return

        print(f"Uploading '{client_path}' to server directory: '{server_path}'")

        validated_path = self.validate_path(server_path)
        if not validated_path:
            print("The requested file upload operation has been canceled.")
            return
        print(f"validate Done! : {validated_path}\n")
        # print(f"Storing {client_path} to the server")
        # self.connect_datasock()
        try:
            self.connect_datasock()
            with open(client_path, 'rb') as f:  # Open file in binary mode
                while (data := f.read(1024)):  # Read chunks of 1024 bytes
                    print(f"not enc data: {data}")
                    encrypted = keys.encrypt_message(str(data), self.public_key['N'], self.public_key['e'])
                    print(f"after enc data: {encrypted}")
                    self.datasock.send(encrypted.encode())
                    # self.sock.send(encrypted.encode())
                    print(f"Sending {len(data)} bytes of data...")
            print("File transfer completed. Closing data socket.")

        except Exception as e:
            print("Error:>", str(e))
        finally:
            try:
                self.datasock.close()
                print("Data socket closed successfully.")
            except:
                print("Failed to close the data socket.")
    def CWD(self, path):
        """
        Change the working directory, ensuring it stays within the main directory.
        """
        validated_path = self.validate_path(path)
        if not validated_path:
            print("The directory change operation has been canceled.")
            return

        self.sock.send(f"CWD {path}\r\n".encode())
        response = self.sock.recv(1024).decode()
        print(response)
        if response.startswith("250"):
            self.current_directory = validated_path

    def DELE(self, path):
        """
        Sends the DELE command to delete a file on the server.
        """
        if not path:
            print("Please specify the file to delete.")
            return

        try:
            self.sock.send(f"DELE {path}\r\n".encode())
            response = self.sock.recv(1024).decode()
            print(response)
        except Exception as e:
            print("Error during DELE command:", str(e))

    # Stop FTP client, close the connection and exit the program

    # TODO Implement MKD
    def MKD(self, path):
        if not path:
            print("Please specify a directory to create.")
            return
        self.sock.send(f"MKD {path}\r\n".encode())
        response = self.sock.recv(1024).decode()
        print(response)

    def RMD(self, path):
        if not path:
            print("Please specify a directory to remove.")
            return
        self.sock.send(f"RMD {path}\r\n".encode())
        response = self.sock.recv(1024).decode()
        print(response)

    def close_client(self):
        print('Closing socket connection...')
        self.sock.close()
        print('FTP client terminating...')
        sys.exit()


# TODO Implement RMD
address = input("Destination address - if left empty, default address is localhost: ")

if not address:
    address = 'localhost'

port = input("Port - if left empty, default port is 21: ")

if not port:
    port = 21

data_port = input("Data port - if left empty, default port is 20: ")

if not data_port:
    data_port = 20

ftpClient = FTPclient(address, port, data_port)
ftpClient.start()
