from datetime import datetime
import socket
import uuid
import selectors
import database
import protocol
import encrypt
import utils
from struct import *

DATABASE = ".\server.db"
PACKET_SIZE = 1024
MAX_QUEUED_CONN = 5
IS_BLOCKING = False


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.database = database.Database(DATABASE, None)
        self.handle_request = {
            protocol.EnumRequestCode.REQUEST_REG.value: self.handle_reg_request,
            protocol.EnumRequestCode.REQUEST_PAIRING.value: self.handle_public_key_request,
            protocol.EnumRequestCode.REQUEST_UPLOAD.value: self.handle_file_upload_request,
        }

    def accept(self, sock, mask):
        """Accept a connection from client"""
        conn, addr = sock.accept()
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def read(self, conn, mask):
        """Reada data from client and parse it"""
        data = conn.recv(PACKET_SIZE)
        if data:
            request_header = protocol.RequestHeader()
            success = False
            print(data)
            print(f"length of data -> {len(data)}")
            if not request_header.unpack(data):
                print("Failed parsing request data header")
            else:
                # checking if code exists
                if request_header.code in self.handle_request.keys():
                    success = self.handle_request[request_header.code](
                        conn, data, request_header
                    )
            # if we got any issues handling the request
            if not success:
                response_header = protocol.ResponseHeader(
                    protocol.EnumResponseCode.RESPONSE_ERROR.value
                )
                self.write(conn, response_header.pack())
            # TODO add last seen database
        self.sel.unregister(conn)
        conn.close()

    def write(self, conn, data):
        """Send response to client

        Args:
            conn (Socket): Socket to client
            data (str): data to send the client
        """
        size = len(data)
        sent = 0
        while sent < size:
            left_over = size - sent
            if left_over > PACKET_SIZE:
                left_over = PACKET_SIZE
            data_to_send = data[sent : sent + left_over]
            if len(data_to_send):
                data_to_send += bytearray(PACKET_SIZE - len(data_to_send))
            try:
                conn.send(data_to_send)
                sent += len(data_to_send)
            except:
                print(f"ERROR: failed sending a response to {conn}")
        print(f"Response has been sent succesfully")
        return True

    def start(self):
        """Start Listen for connections"""
        self.database.create_connection()
        self.database.init_tables()
        try:
            sock = socket.socket()
            sock.bind((self.host, self.port))
            sock.listen(MAX_QUEUED_CONN)
            sock.setblocking(IS_BLOCKING)
            self.sel.register(sock, selectors.EVENT_READ, self.accept)
        except Exception as e:
            self.last_err = e
            return False
        print(f"Server is listening for connection on port {self.port}")
        while True:
            try:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as e:
                print(f"Server main loop exception: {e}")

    def handle_reg_request(self, conn, data, header):
        """Register a new user and save to db"""
        request = protocol.RegRequest(header)
        response = protocol.RegResponse()
        if not request.unpack(data):
            print("Failed parsing request")
            return False
        try:
            if not request.name.isalnum():
                print("invalid username")
                return False
            if self.database.client_username_exists(request.name):
                print("Usename already exists")
                return False
        except:
            print("Failed to connect to database")
            return False
        # aes key doesnt exist on register
        client = database.Client(
            uuid.uuid4(), request.name, request.key, str(datetime.now()), aes_key=""
        )
        if not self.database.store_client(client):
            return False
        response.uuid = client.uuid.bytes_le
        response.header.payload_size = protocol.UUID_SIZE
        return self.write(conn, response.pack())

    def handle_public_key_request(self, conn, data, header):
        """Respond the public key and create RSA key"""
        request = protocol.KeyPairingRequest(header)
        response = protocol.KeyPairingResponse()
        if not request.unpack(data):
            print("Public key request, failed to parse")
        pKey = self.database.get_public_key(request.header.uuid)
        # No public key set in user
        if pKey[0][0] == b"":
            if not self.database.update_public_key(
                uuid=request.header.uuid, public_key=request.key
            ):
                return False
        encryptor = encrypt.Encryptor(request.key)
        aes_key_encrypted = encryptor.encrypt_with_public_key(encryptor.aes_key)
        print(f"encrypted_aes_key = {aes_key_encrypted}")
        print(f"len encrypted_aes_key = {len(aes_key_encrypted)}")
        self.database.update_aes_key(request.header.uuid, encryptor.aes_key)
        response.key = aes_key_encrypted
        response.header.payload_size = 128
        return self.write(conn, response.pack())

    def handle_file_upload_request(self, conn, data, header):
        """Responds the file handler"""
        request = protocol.FileUploadRequest(header)
        response = protocol.ResponseHeader(protocol.INIT_VAL)
        if not request.unpack(data):
            print("File upload request, failed to parse")
        print("Getting AES Key from db")

        aes_key = self.database.get_aes_key(request.header.uuid)
        if not aes_key:
            return False
        encryptor = encrypt.Encryptor(aes_key=aes_key)
        retries = 0
        while retries < protocol.MAX_RETRIES:
            (
                get_file_success,
                file_encrypted_path,
                file_decrypted_path,
            ) = self.get_user_file(conn, data, header)
            if not get_file_success:
                return False
            if not encryptor.decrypt_file(file_encrypted_path, file_decrypted_path):
                return False
            response_code = self.send_crc(conn, file_decrypted_path)
            if response_code == protocol.EnumRequestCode.CRC_OK.value:
                response.code = protocol.EnumResponseCode.RESPONSE_OK.value
                self.write(conn, response.pack())
                break
            retries += 1
            if retries:
                data = conn.recv(PACKET_SIZE)
                header = protocol.RequestHeader()
                if not header.unpack(data):
                    return False

        if header.code == protocol.EnumRequestCode.CRC_FAILED.value:
            return False

        return True

    def get_user_file(self, conn, data, header):
        try:
            request = protocol.FileUploadRequest(header)
            if not request.unpack(data):
                print("File upload request, failed to parse")
            file_encrypted, file_encrypted_path = utils.create_file(
                str(request.header.uuid), request.filename + ".enc"
            )
            _, file_decrypted_path = utils.create_file(
                str(request.header.uuid), request.filename
            )
            readen_bytes = protocol.FILE_MAX_DATA_PACKET
            file_encrypted.write(request.encrypted_data_packet)
            while readen_bytes < request.encrypted_file_size:
                data = conn.recv(PACKET_SIZE)
                request.unpack(data)
                # writing to encrypted file
                file_encrypted.write(request.encrypted_data_packet)
                readen_bytes += protocol.FILE_MAX_DATA_PACKET
            print("Encrypted file has been copy.")
            file_encrypted.close()
            return (True, file_encrypted_path, file_decrypted_path)
        except Exception as exp:
            print(exp)
            return (False, file_encrypted_path, file_decrypted_path)

    def send_crc(self, conn, file_path):
        header_client_response = protocol.RequestHeader()
        crc = utils.get_crc32(file_path)
        crc_to_client = protocol.FileUploadResponse()
        crc_to_client.crc = crc
        if not self.write(conn, crc_to_client.pack()):
            return False
        crc_response_data = conn.recv(PACKET_SIZE)
        header_client_response.unpack(crc_response_data)
        return header_client_response.code
