import socket
import uuid
import database
import protocol
import encrypt
import utils
import threading
from struct import *

DATABASE = "server.db"
PORT_INFO = "port.info"
HOST = '0.0.0.0'
PACKET_SIZE = 1024
MAX_QUEUED_CONN = 5
IS_BLOCKING = False


class Server:
    def __init__(self):
        self.logger = utils.create_logger()
        self.host = HOST
        self.port = self.__load_config()
        self.database = database.Database(DATABASE, self.logger)
        self.lock = threading.Lock()
        self.handle_request = {
            protocol.EnumRequestCode.REQUEST_REG.value: self.handle_reg_request,
            protocol.EnumRequestCode.REQUEST_PAIRING.value: self.handle_public_key_request,
            protocol.EnumRequestCode.REQUEST_UPLOAD.value: self.handle_file_upload_request,
        }

    def __load_config(self):
        with open(PORT_INFO,'r') as port_info:
            port_info_data = port_info.readlines()
            port_info_data = [line.strip() for line in port_info_data if line!='\n']
            if len(port_info_data) > 2 or len(port_info_data) == 0:
                self.logger.error(f"Too many lines in {PORT_INFO}")
                exit(1)
            if not port_info_data[0].isnumeric():
                self.logger.error(f"Port is not numeric in {PORT_INFO}")
                exit(1)
            return int(port_info_data[0])

    def read(self, conn):
        """Reada data from client and parse it"""
        data = conn.recv(PACKET_SIZE)
        if data:
            request_header = protocol.RequestHeader()
            success = False
            if not request_header.unpack(data):
                self.logger.error("Failed parsing request data header")
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
            with self.lock:
                self.database.update_last_seen(request_header)
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
                self.logger.error(f"ERROR: failed sending a response to {conn}")
        self.logger.info(f"Response has been sent succesfully")
        return True

    def start_server(self):
        """Start Listen for connections"""
        self.database.create_connection()
        self.database.init_tables()
        try:
            sock = socket.socket()
            sock.bind((self.host, self.port))
            sock.listen(MAX_QUEUED_CONN)
            self.logger.info(f"Server is listening for connection on port {self.port}")
            while True:
                conn, address = sock.accept()
                self.logger.info('Connected to: ' + address[0] + ':' + str(address[1]))
                t1 = threading.Thread(target=self.read, args=(conn,),name='clientThread')
                t1.start()
        except Exception as e:
            self.logger.exception(f"Failed openning socket : {e}")
            return False
       

    def __create_uuid(self, table_check: str) -> uuid.UUID:
        new_uuid = uuid.uuid4()
        with self.lock:
            while self.database.id_exists(new_uuid, table_check):
                new_uuid = uuid.uuid4()
        return new_uuid

    def handle_reg_request(self, conn:socket, data:bytes, header:protocol.RequestHeader):
        """Register a new user and save to db"""
        request = protocol.RegRequest(header)
        response = protocol.RegResponse()
        if not request.unpack(data):
            self.logger.error("Failed parsing request")
            return False
        if not request.name.isalnum():
            self.logger.error("Username is not alphanumeric")
            return False
        with self.lock:
            if self.database.client_username_exists(request.name):
                self.logger.error("Username already exists")
                return False
        # aes key doesnt exist on register
        client = database.Client(self.__create_uuid(database.TABLE_CLIENTS), request.name, request.key, aes_key="")
        self.logger.info("Acquiring lock to store client")
        with self.lock:
            self.logger.debug("Lock has been acquired, storing client...")
            if not self.database.store_client(client):
                return False
        self.logger.info(f"New Client has been registered:\n\t{client.__str__()}")
        response.uuid = client.uuid.bytes_le
        self.logger.debug(f"uuid in bytes --> {response.uuid}")
        response.header.payload_size = protocol.UUID_SIZE
        return self.write(conn, response.pack())


    def handle_public_key_request(self, conn:socket, data:bytes, header:protocol.RequestHeader) -> bool:
        """Receive public key from user, saves it into client table.
            Generates a new AES key saves it into DB then encrypt it with client public key and sends it to client.
        Args:
            conn (socket): Connection with the client
            data (list): _description_
            header (_type_): _description_

        Returns:
            bool: True if all succeded and False if got any failure
        """
        request = protocol.KeyPairingRequest(header)
        response = protocol.KeyPairingResponse()
        if not request.unpack(data):
            self.logger.info("Public key request, failed to parse")
        with self.lock:
            if not self.database.id_exists(request.header.uuid, database.TABLE_CLIENTS):
                return False
            pKey = self.database.get_public_key(request.header.uuid)
        # No public key set in user
        if pKey and pKey != request.key:
            return False
        encryptor = encrypt.Encryptor(request.key, logger=self.logger)
        aes_key_encrypted = encryptor.encrypt_with_public_key(encryptor.aes_key)
        self.logger.info(f"encrypted_aes_key = {aes_key_encrypted}")
        self.logger.info("Acquiring lock to read")
        
        with self.lock:
            if not self.database.update_public_key(uuid=request.header.uuid, public_key=request.key):
                return False
            if not self.database.update_aes_key(request.header.uuid, encryptor.aes_key):
                return False
        response.key = aes_key_encrypted
        response.header.payload_size = protocol.AES_ENCRYPTED
        return self.write(conn, response.pack())

    def handle_file_upload_request(self, conn, data, header):
        """Responds the file handler"""
        self.logger.debug("Start handle file")
        request = protocol.FileUploadRequest(header)
        response = protocol.ResponseHeader(protocol.INIT_VAL)
        retries = 0
        self.logger.debug("Unpacking data from request")
        if not request.unpack(data):
            self.logger.error("Failed to parse file upload request")
            return False

        self.logger.info("Getting AES Key from db")
        with self.lock:
            aes_key = self.database.get_aes_key(request.header.uuid)
        if not aes_key:
            return False
        encryptor = encrypt.Encryptor(aes_key=aes_key, logger=self.logger)

        while retries < protocol.MAX_RETRIES:
            self.logger.info(f"Number of retries: {retries}")
            self.logger.info(f"File upload for client {str(request.header.uuid)} has been initialized")
            get_file_success, file_encrypted_path, file_decrypted_path = self.get_user_file(conn, data, header)
            new_file = database.File_DB(request.header.uuid, file_decrypted_path, False)

            if not get_file_success:
                self.logger.info("Getting file from client has failed... exiting")
                return False
            if not encryptor.decrypt_file(file_encrypted_path, file_decrypted_path):
                return False
            response_code = self.send_crc(conn, header, file_decrypted_path)
            self.logger.info(f"Response code from sending CRC: {response_code}")
            if response_code == protocol.EnumRequestCode.CRC_OK.value:
                response.code = protocol.EnumResponseCode.RESPONSE_OK.value
                self.write(conn, response.pack())
                new_file.verified = True
                break
            retries += 1
            if retries:
                new_file.verified = False
                self.logger.info("Getting file from user because CRC doesnt match")
                data = conn.recv(PACKET_SIZE)
                header = protocol.RequestHeader()
                if not header.unpack(data):
                    return False
                if header.code != protocol.EnumRequestCode.REQUEST_UPLOAD.value:
                    self.logger.error(
                        f"Expected OpCode{protocol.EnumRequestCode.REQUEST_UPLOAD.value} but received {header.code}"
                    )
                    return False

        if header.code == protocol.EnumRequestCode.CRC_FAILED.value:
            self.logger.error("Max retries has been reached...")
            return False
        with self.lock:
            if not self.database.store_file(new_file):
                self.logger.error("Failed saving file data into DB")
        return True

    def get_user_file(self, conn:socket, data:list, header:protocol.FileUploadRequest) -> tuple:
        """_summary_

        Args:
            conn (socket): _description_
            data (list): _description_
            header (protocol.FileUploadRequest): _description_

        Returns:
            tuple: _description_
        """
        try:
            request = protocol.FileUploadRequest(header)
            if not request.unpack(data):
                self.logger.error("Failed to parse file upload request")
            file_encrypted, file_encrypted_path = utils.create_file(
                str(request.header.uuid), request.filename + ".enc"
            )
            _, file_decrypted_path = utils.create_file(
                str(request.header.uuid), request.filename, False
            )
            readen_bytes = request.header.payload_size
            file_encrypted.write(request.encrypted_data_packet)
            while readen_bytes < request.encrypted_file_size:
                #getting more data
                self.logger.debug(
                    f"Readen bytes: {readen_bytes}, Size of Encrypted File: {request.encrypted_file_size}"
                )
                data = conn.recv(PACKET_SIZE)
                #unpacking data
                self.logger.debug("Got another packet from user, start unpacking..")
                new_header = protocol.RequestHeader()
                new_header.unpack(data)
                self.logger.debug(f"Received packet from client {str(new_header.uuid)}")
                self.logger.info(data)
                if header != new_header:
                    self.logger.error("New received header doesnt equal to the previous header.")
                    return (False, file_encrypted_path, file_decrypted_path)
                request.header= new_header
                request.unpack(data)
                # writing to encrypted file
                self.logger.debug(f"Writing message to encrypted file")
                file_encrypted.write(request.encrypted_data_packet)
                readen_bytes += request.header.payload_size
                self.logger.debug(
                    f"Readen bytes: {readen_bytes}, Size of Encrypted File: {request.encrypted_file_size}"
                )
            self.logger.info(f"Encrypted file has been received: {file_encrypted_path}")
            file_encrypted.close()
            return (True, file_encrypted_path, file_decrypted_path)
        except Exception as exp:
            self.logger.error(f"Got an exception in get_user_file: {exp}")
            return (False, file_encrypted_path, file_decrypted_path)

    def send_crc(self, conn, header, file_path) -> int:
        """Calculates CRC32 of Client's file and send it to client.
           Awaits for reply from client and returns the opCode

        Args:
            conn (_type_): _description_
            file_path (str): _description_

        Returns:
            int: OpCode of Response
        """
        header_client_response = protocol.RequestHeader()
        crc_to_client = protocol.FileUploadResponse()
        crc = utils.get_crc32(file_path)
        self.logger.info(f"CRC of file {file_path} = {crc}")
        crc_to_client.crc = crc
        self.logger.info(f"Sending CRC to client {conn}")
        if not self.write(conn, crc_to_client.pack()):
            self.logger.error("Failed while sending CRC packet to client")
            return False
        self.logger.info(f"Waiting for CRC response from {conn}")
        crc_response_data = conn.recv(PACKET_SIZE)
        header_client_response.unpack(crc_response_data)
        if header.uuid != header_client_response.uuid:
            return protocol.EnumRequestCode.CRC_FAILED.value
        return header_client_response.code
