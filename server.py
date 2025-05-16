import ast
import errno
import json
import socket
import os
import sys
import threading
import time
import pandas as pd
import keys

MAIN_DIRECTORY = r"C:\Users\Apple\OneDrive\Documents\GitHub\phase2-test\FTP_Files"

# users_info = pd.read_csv("users.csv", index_col=0).to_dict()["PASSWORD"]

users_info = pd.read_csv("users.csv").set_index("USERNAME").to_dict("index")
for user, details in users_info.items():
    details["PERMISSIONS"] = details["PERMISSIONS"].split(",")  # Convert to list


def has_permission(user_in_use, permission):
    return permission in users_info[user_in_use]["PERMISSIONS"]


class FTPThreadServer(threading.Thread):
    def __init__(self, client_tuple, local_ip, data_port):
        client, client_address = client_tuple
        self.client = client
        self.client_address = client_address
        self.cwd = os.getcwd()
        self.data_address = (local_ip, data_port)

        self.users = users_info
        self.authenticated = False
        self.current_user = None

        self.p = 53
        self.d = 61
        self.N, self.e, self.d = keys.get_peivate_And_public_key(self.p, self.d, 'server')
        self.public_key = {"N": self.N, "e": self.e}
        self.private_key = {"N": self.N, "d": self.d}

        self.client_public_key = {}

        threading.Thread.__init__(self)

    def start_datasock(self):
        try:
            print(f'Creating data socket on {self.data_address}...')

            # Create TCP data socket
            self.datasock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.datasock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            self.datasock.bind(self.data_address)
            self.datasock.listen(5)
            print(f'Data socket started. Listening to {self.data_address}...')
            self.client.send(b'125 Data connection already open; transfer starting.\r\n')
            return self.datasock.accept()
        except Exception as e:
            print(f'ERROR: {self.client_address}: {str(e)}')
            self.close_datasock()
            self.client.send(b'425 Cannot open data connection.\r\n')

    def close_datasock(self):
        print('Closing data socket connection...')
        try:
            self.datasock.close()
        except:
            print("can't close datasock")
            pass

    def run(self):
        try:
            print(f'Client connected: {self.client_address}\n')
            self.client.send(f"Public_Key: {self.public_key}".encode())
            input_key = self.client.recv(1024).decode()
            print(input_key)
            print()
            dict_part = input_key.split(": ", 1)[1]
            dict_part_json = dict_part.replace("'", '"')
            self.client_public_key = json.loads(dict_part_json)

            while True:
                cmd = self.client.recv(1024).decode().strip()
                print(f"not decripted cmd: {cmd}")
                cmd = keys.decrypt_message(cmd, self.N, self.d)
                print(f"decrypted :  cmdd: {cmd}")
                if not cmd:
                    break
                print(f'Commands from {self.client_address}: {cmd}')
                try:
                    func = getattr(self, cmd[:4].strip().upper())
                    func(cmd)
                except AttributeError:
                    print(f'ERROR: {self.client_address}: Invalid Command.')
                    self.client.send(b'550 Invalid Command\r\n')
        except Exception as e:
            print(f" cmd : {cmd}")
            print(f'ERROR: &{self.client_address}: {str(e)}')
            self.QUIT('')

    def USER(self, cmd):
        username = cmd[5:].strip()
        if username in self.users:
            self.current_user = username
            self.client.send(b'331 User name okay, need password.\r\n')
        else:
            self.client.send(b'530 Invalid username.Try again\r\n')

    def PASS(self, cmd):
        if self.current_user is None:
            self.client.send(b'503 Login with USER first.\r\n')
            return

        password = cmd[5:].strip()
        if self.users[self.current_user]["PASSWORD"] == password:
            self.authenticated = True
            self.client.send(b'230 User logged in, proceed.\r\n')
        else:
            self.client.send(b'530 Invalid password.\r\n')

    def QUIT(self, cmd):
        try:
            self.client.send(b'221 Goodbye.\r\n')
        finally:
            print(f'Closing connection from {self.client_address}...')
            self.close_datasock()
            self.client.close()
            sys.exit()

    def LIST(self, cmd):
        if not self.authenticated:
            self.client.send(b'530 Please log in first.\r\n')
            return
        if not has_permission(self.current_user, "READ"):
            self.client.send(b'550 Permission denied: READ access is required.\r\n')
            return
        # Parse the optional path
        path = cmd[4:].strip() or self.cwd
        if not os.path.isdir(path):
            self.client.send(f'550 "{path}": No such file or directory.\r\n'.encode())
            return

        print(f'LIST {path}')
        client_data, client_address = self.start_datasock()

        try:
            listdir = os.listdir(path)
            if not listdir:
                client_data.send(b'No files or directories found.\r\n')
                self.client.send(b'\r\n226 Directory send OK.\r\n')
                return

            max_length = len(max(listdir, key=len)) if listdir else 0
            header = '| {name:<{width}} | {type:<9} | {size:<12} | {modified:<20} | {permissions:<11} | {owner:<12} |'.format(
                name="Name", width=max_length, type="Filetype", size="Filesize", modified="Last Modified",
                permissions="Permission", owner="User/Group")
            table = f"{'-' * len(header)}\n{header}\n{'-' * len(header)}\n"
            client_data.send(table.encode())

            for i in listdir:
                filepath = os.path.join(path, i)
                stat = os.stat(filepath)
                data = '| {name:<{width}} | {type:<9} | {size:<12} | {modified:<20} | {permissions:<11} | {owner:<12} |\n'.format(
                    name=i, width=max_length, type='Directory' if os.path.isdir(filepath) else 'File',
                    size=f"{stat.st_size}B", modified=time.strftime('%b %d, %Y %H:%M', time.localtime(stat.st_mtime)),
                    permissions=oct(stat.st_mode)[-4:], owner=f"{stat.st_uid}/{stat.st_gid}")
                client_data.send(data.encode())

            table = f"{'-' * len(header)}\n"
            client_data.send(table.encode())
            self.client.send(b'\r\n226 Directory send OK.\r\n')
        except Exception as e:
            print(f'ERROR: {self.client_address}: {str(e)}')
            self.client.send(b'426 Connection closed; transfer aborted.\r\n')
        finally:
            client_data.close()
            self.close_datasock()

    # TODO Implement PWD

    def PWD(self, cmd):
        if not self.authenticated:
            self.client.send(b'530 Please log in first.\r\n')
            return
        self.client.send(f'257 \"{self.cwd}\".\r\n'.encode())

    # TODO Implement CWD
    def CWD(self, cmd):
        print("in CWD method")
        if not self.authenticated:
            self.client.send(b'530 Please log in first.\r\n')
            return
        validated_path = self.validate_path(cmd[4:].strip())
        print("in CWD method before path validation ")

        if not validated_path:
            print("The directory change operation has been canceled.")
            self.client.send(b'999 not Allowed to change to this path .\r\n')
            return

        print("in CWD method after path validation ")
        dest = os.path.join(self.cwd, cmd[4:].strip())
        if os.path.isdir(dest):
            self.cwd = dest
            self.client.send(f'250 OK \"{self.cwd}\".\r\n'.encode())
        else:
            print(f'ERROR: ^ {self.client_address}: No such file or directory.')
            self.client.send(f'550 \"{dest}\": No such file or directory.\r\n'.encode())

        print("in CWD method END")

    # TODO Implement CDUP
    def CDUP(self, cmd):
        if not self.authenticated:
            self.client.send(b'530 Please log in first.\r\n')
            return

        validated_path = self.validate_path(self.cwd)
        if not validated_path:
            print("The directory change operation has been canceled.")
            self.client.send(b'999 not Allowed to change to this path .\r\n')
            return

        dest = os.path.abspath(os.path.join(self.cwd, '..'))
        if os.path.isdir(dest):
            self.cwd = dest
            self.client.send(f'250 OK \"{self.cwd}\".\r\n'.encode())
        else:
            print(f'ERROR: {self.client_address}: No such file or directory.')
            self.client.send(f'550 \"{dest}\": No such file or directory.\r\n'.encode())

    def STOR(self, cmd):
        if not self.authenticated:
            self.client.send(b'530 Please log in first.\r\n')
            return

        if not has_permission(self.current_user, "WRITE"):
            self.client.send(b'550 Permission denied: WRITE access is required.\r\n')
            return

        try:
            parts = cmd[4:].strip().split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError("Invalid STOR command format. Expected: 'STOR source_path destination_dir'")

            source_path = parts[0]  # Source file path (client-side)
            destination_dir = parts[1]  # Target directory on the server

            # Extract the filename from the source path
            filename = os.path.basename(source_path)
            if not filename:
                raise ValueError("Source path does not contain a valid filename.")

            # Construct the full destination path
            filepath = os.path.join(destination_dir, filename)

        except ValueError as e:
            self.client.send(b'501 Syntax error in parameters or arguments.\r\n')
            print(f"ERROR: * {e}")
            return

        print(f"Source file: {source_path}")
        print(f"Target directory: {destination_dir}")
        print(f"Full destination file path: {filepath}")

        # Ensure the target directory exists
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
        except Exception as e:
            print(f"ERROR: Could not create directory: {str(e)}")
            self.client.send(b'550 Permission denied: Unable to create directory.\r\n')
            return

        if not self.validate_path(filepath):
            print(f"999 you don't have access to upload in this path: {filepath}")
            self.client.send(b"999 you don't have access to upload in this path: {filepath}.\r\n")
            return
        # Debugging output
        print(f"Attempting to write to: {filepath}")
        print(f"Directory exists: {os.path.exists(os.path.dirname(filepath))}")
        print(f"Writable directory: {os.access(os.path.dirname(filepath), os.W_OK)}")

        print(f'STOR {filepath}')

        client_data, client_address = self.start_datasock()
        print("aftere  daaat")
        if not client_data:
            print("not client daaat")
            self.client.send(b'425 Cannot open data connection.\r\n')
            return
        try:
            # Write the file to the destination path
            with open(filepath, 'wb') as f:
                while True:
                    data = client_data.recv(1024)
                    if not data:
                        break
                    decrypted_data = keys.decrypt_message(data.decode(), self.N, self.d)
                    temp = decrypted_data[2:-1].replace("\\r", "\r").replace("\\n", "\n")
                    f.write(temp.encode())
            client_data.close()
            self.client.send(b'226 Transfer complete.\r\n')
            print("response sent")
            print(f"File '{filepath}' successfully stored.")
        except PermissionError as e:
            print(f"ERROR: {self.client_address}: Permission denied: {str(e)}")
            self.client.send(b'550 Permission denied: Unable to write to the specified location.\r\n')
        except Exception as e:
            print(f"ERROR:  (){self.client_address}: {str(e)}")
            self.client.send(b'426 Connection closed; transfer aborted.\r\n')
        finally:
            try:
                self.close_datasock()
            except:
                print("Failed to close the data socket.")

    def validate_path(self, requested_path):
        requested_path = requested_path.strip()
        print(f"requested_path {requested_path}")
        abs_path = os.path.abspath(requested_path).lower()
        print(f"abs_path:{abs_path}")
        if abs_path.startswith(os.path.abspath(MAIN_DIRECTORY.lower())):
            return abs_path
        else:
            print("Access denied: Cannot access outside of the main directory.")
            return None

    def RETR(self, cmd):
        filename = cmd[4:].strip()

        if not self.authenticated:
            self.client.send(b'530 Please log in first.\r\n')
            return

        if not has_permission(self.current_user, "READ"):
            self.client.send(b'550 Permission denied: READ access is required.\r\n')
            return

        if not filename:
            self.client.send(b'501 Syntax error in parameters or arguments.\r\n')
            return

        validated_path = self.validate_path(cmd[4:].strip())
        if not validated_path:
            self.client.send(b"The requested file retrieval operation has been canceled.")
            print("The requested file retrieval operation has been canceled.")
            return

        filepath = os.path.join(self.cwd, filename)

        print(f"RETR {filepath}")

        # Check if the file exists
        if not os.path.isfile(filepath):
            self.client.send(b'550 File not found.\r\n')
            return

        client_data, client_address = self.start_datasock()

        try:

            self.client.send(b'150 File status okay; opening data connection.\r\n')

            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(1024)
                    if not data:
                        break
                    print(f"not enc data: {data}")
                    encrypted = keys.encrypt_message(str(data), self.client_public_key['N'], self.client_public_key['e']).encode()
                    print(f"after enc data: {encrypted}")
                    client_data.send(encrypted)
                    # client_data.send(data)

            self.client.send(b'226 Transfer complete.\r\n')
            print(f"File '{filepath}' successfully sent to client.")
        except Exception as e:
            print(f"ERROR: {self.client_address}: {str(e)}")
            self.client.send(b'426 Connection closed; transfer aborted.\r\n')
        finally:
            client_data.close()
            self.close_datasock()

    # TODO Implement RMD
    def RMD(self, cmd):
        if not self.authenticated:
            self.client.send(b'530 Please log in first.\r\n')
            return

        if not has_permission(self.current_user, "DELETE"):
            self.client.send(b'550 Permission denied: DELETE access is required.\r\n')
            return
        dir_to_remove = os.path.join(self.cwd, cmd[4:].strip())
        print(f"dir_to_remove1: {dir_to_remove}")
        dir_to_remove = os.path.abspath(dir_to_remove)
        print(f"dir_to_remove2: {dir_to_remove }")
        if not os.path.isdir(dir_to_remove):
            self.client.send(f'550 "{dir_to_remove}": No such directory.\r\n'.encode())
            return

        validated_path = self.validate_path(cmd[4:].strip())
        if not validated_path:
            print("The directory change operation has been canceled.")
            self.client.send(b'999 not Allowed to change to this path .\r\n')
            return

        print(f"Requested path: {cmd[4:].strip()}")
        print(f"Full path: {dir_to_remove}")

        # Ensure we have permission to access
        if not os.access(dir_to_remove, os.W_OK):  # Writable
            self.client.send(f'550 Permission denied: No write access to "{dir_to_remove}".\r\n'.encode())
            return

        try:

            os.rmdir(dir_to_remove)
            self.client.send(f'250 Directory "{dir_to_remove}" removed successfully.\r\n'.encode())
        except FileNotFoundError:
            self.client.send(f'550 "{dir_to_remove}": No such directory.\r\n'.encode())
        except PermissionError:
            self.client.send(
                f'550 Permission denied: You do not have permission to delete "{dir_to_remove}".\r\n'.encode())
        except OSError as e:
            if e.errno == errno.ENOTEMPTY:
                self.client.send(f'550 Cannot remove directory "{dir_to_remove}": Directory not empty.\r\n'.encode())
            else:
                self.client.send(f'550 Failed to remove directory "{dir_to_remove}": {str(e)}.\r\n'.encode())

    def MKD(self, cmd):
        if not self.authenticated:
            self.client.send(b'530 Please log in first.\r\n')
            return

        if not has_permission(self.current_user, "CREATE"):
            self.client.send(b'550 Permission denied: CREATE access is required.\r\n')
            return

        path = cmd[4:].strip()
        validated_path = self.validate_path(path)
        if not validated_path:
            print("The requested file upload operation has been canceled.")
            return

        dir_to_create = os.path.join(self.cwd, )
        try:
            os.mkdir(dir_to_create)
            self.client.send(f'257 Directory "{dir_to_create}" created successfully.\r\n'.encode())
        except Exception as e:
            self.client.send(f'550 Failed to create directory: {str(e)}.\r\n'.encode())

    # TODO Implement DELE
    def DELE(self, cmd):
        path = cmd[4:].strip() or self.cwd
        if len(path)<3 or not path:
            print("No path entered or path too short.")
            self.client.send(b'550 No path specified or path is too short.\r\n')
            return

        if not self.authenticated:
            self.client.send(b'530 Please log in first.\r\n')
            return

        if not has_permission(self.current_user, "DELETE"):
            self.client.send(b'550 Permission denied: CREATE access is required.\r\n')
            return
        if not os.path.isfile(path) :
            self.client.send(f'550 "{path}": No such file or directory.\r\n'.encode())
            return
        print(f'DELE :: {path}')

        # listdir = os.listdir(path)
        # if not listdir:
        #     self.client.send(b'No files or directories found.\r\n')
        #     return

        filename = os.path.basename(path)
        print(f"filename : {filename}")
        if not filename:
            raise ValueError("Source path does not contain a valid filename.")
        validated_path = self.validate_path(path)
        if not validated_path:
            print("The directory (filename) change operation has been canceled.")
            self.client.send(b'999 not Allowed to change to this path .\r\n')
            return

        file_to_delete = os.path.join(self.cwd, path)
        file_to_delete = os.path.abspath(file_to_delete)

        print(f"Requested file to delete: {file_to_delete}")

        # if not file_to_delete.startswith(self.cwd): # baraye in ke toye folder bashi ta betoni deletesh koni
        #     self.client.send(b'550 Permission denied: Invalid path.\r\n')
        #     return

        if not os.path.isfile(file_to_delete):
            self.client.send(f'550 "{file_to_delete}": No such file.\r\n'.encode())
            return

        if not os.access(file_to_delete, os.W_OK):
            self.client.send(f'550 Permission denied: Cannot delete "{file_to_delete}".\r\n'.encode())
            return

        try:
            os.remove(file_to_delete)
            self.client.send(f'250 File "{file_to_delete}" deleted successfully.\r\n'.encode())
            print(f"File '{file_to_delete}' successfully deleted.")
        except PermissionError:
            self.client.send(f'550 Permission denied: Unable to delete "{file_to_delete}".\r\n'.encode())
        except Exception as e:
            self.client.send(f'550 Failed to delete file "{file_to_delete}": {str(e)}.\r\n'.encode())


class FTPserver:
    def __init__(self, port, data_port):
        self.address = '0.0.0.0'
        self.port = int(port)
        self.data_port = int(data_port)

    def start_sock(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_address = (self.address, self.port)

        try:
            print(f'Creating data socket on {self.address}:{self.data_port}...')
            self.sock.bind(server_address)
            self.sock.listen(5)
            print(f'Server is up. Listening to {self.address}:{self.port}')
        except Exception as e:
            print(f'Failed to create server on {self.address}:{self.port} because {str(e)}')
            sys.exit()

    def start(self):
        self.start_sock()

        try:
            while True:
                print('Waiting for a connection...')
                thread = FTPThreadServer(self.sock.accept(), self.address, self.data_port)
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print('Closing socket connection...')
            self.sock.close()
            sys.exit()


# Main
port = input("Port - if left empty, default port is 21: ")
if not port:
    port = 21

data_port = input("Data port - if left empty, default port is 20: ")
if not data_port:
    data_port = 20

server = FTPserver(port, data_port)
server.start()
