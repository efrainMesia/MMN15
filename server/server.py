from datetime import datetime
import socket
import uuid
import selectors
import database
import protocol
import encrypt
from struct import *
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP

DATABASE = '.\server.db'
PACKET_SIZE = 1024
MAX_QUEUED_CONN = 5
IS_BLOCKING = False

class Server():
    def __init__(self,host, port):
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.database = database.Database(DATABASE,None)
        self.handle_request = {
            protocol.EnumRequestCode.REQUEST_REG.value:self.handle_reg_request,
            protocol.EnumRequestCode.REQUEST_PAIRING.value:self.handle_public_key_request
        }

    def accept(self,sock, mask):
        """Accept a connection from client"""
        conn,addr = sock.accept()
        self.sel.register(conn,selectors.EVENT_READ,self.read)
    
    def read(self,conn,mask):
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
                    success = self.handle_request[request_header.code](conn,data,request_header)
            # if we got any issues handling the request
            if not success:
                response_header = protocol.ResponseHeader(protocol.EnumResponseCode.RESPONSE_ERROR.value)
                self.write(conn,response_header.pack())
            #TODO add last seen database
        self.sel.unregister(conn)
        conn.close()
    

    def write(self,conn,data):
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
            data_to_send = data[sent: sent+left_over]
            if len(data_to_send):
                data_to_send += bytearray(PACKET_SIZE-len(data_to_send))
            try:
                conn.send(data_to_send)
                sent += len(data_to_send)
            except:
                print(f"ERROR: failed sending a response to {conn}")
        print(f"Response has been sent succesfully")
        return True

    def start(self):
        """Start Listen for connections
        """
        self.database.create_connection()
        self.database.init_tables()
        try:
            sock = socket.socket()
            sock.bind((self.host,self.port))
            sock.listen(MAX_QUEUED_CONN)
            sock.setblocking(IS_BLOCKING)
            self.sel.register(sock,selectors.EVENT_READ,self.accept)
        except Exception as e:
            self.last_err = e
            return False
        print(f"Server is listening for connection on port {self.port}")
        while True:
            try:
                events = self.sel.select()
                for key,mask in events:
                    callback = key.data
                    callback(key.fileobj,mask)
            except Exception as e:
                print(f"Server main loop exception: {e}")
    
    def handle_reg_request(self,conn,data,header):
        """ Register a new user and save to db"""
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
        client = database.Client(uuid.uuid4(), request.name,request.key,str(datetime.now()),aes_key="")
        if not self.database.store_client(client):
            return False
        response.uuid = client.uuid.bytes_le
        response.header.payload_size = protocol.UUID_SIZE
        return self.write(conn,response.pack())

    def handle_public_key_request(self,conn,data,header):
        """ Respond the public key and create RSA key"""
        request = protocol.KeyPairingRequest(header)
        response = protocol.KeyPairingResponse()
        if not request.unpack(data):
            print("Public key request, failed to parse")
        pKey = self.database.get_public_key(request.header.uuid)
        # No public key set in user
        if pKey[0][0] == b'':
            if not self.database.update_public_key(uuid=request.header.uuid,public_key=request.key):
                return False
        encryptor = encrypt.Encryptor(request.key)
        aes_key_encrypted = encryptor.encrypt_with_public_key(encryptor.aes_key)
        print(f"encrypted_aes_key = {aes_key_encrypted}")
        print(f"len encrypted_aes_key = {len(aes_key_encrypted)}")
        response.key= aes_key_encrypted
        response.header.payload_size = 128
        return self.write(conn,response.pack())
        

