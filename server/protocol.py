import struct
from enum import Enum

INIT_VAL = 0
UUID_SIZE = 16
CODE_SIZE = 2 
PAYLOAD_SIZE = 2
HEADER_SIZE = UUID_SIZE + CODE_SIZE + PAYLOAD_SIZE    #Not including the UUID
SYMM_KEY_SIZE = 16
NAME_SIZE = 127
FILE_NAME_MAX_SIZE = 256      #File name to bits
FILE_LENGTH_SIZE = 1   #Length of filename in bytes
FILE_MAX_DATA_PACKET = 20
FILE_PACKET_SIZE = 1
KEY_SIZE = 160     #Convert 160 bytes to bits
CRC_SIZE = 4

FORMAT_REQUEST_HEADER = f"<{UUID_SIZE}sHH"
FORMAT_REG_REQUEST = f"<{NAME_SIZE}s"
#TODO: ADD format for key_pair

#B- FileName length , 256s - filename , B-datapacket length, 20s-DataPacket, I-crc
FORMAT_FILE_UPLOAD_REQUEST = f"<B{FILE_NAME_MAX_SIZE}sB{FILE_MAX_DATA_PACKET}sI"



class EnumRequestCode(Enum):
    REQUEST_REG = 1000      #uuid ignored
    REQUEST_PAIRING = 1001  #update keys
    REQUEST_UPLOAD = 1002
    REQUEST_CRC = 1003

class EnumResponseCode(Enum):
    RESPONSE_REG = 2000
    RESPONSE_PAIRING = 2001
    RESPONSE_UPLOAD = 2002
    RESPONSE_CRC = 2003
    RESPONSE_ERROR = 2004




class RequestHeader:
    def __init__(self):
        self.uuid = b'' 
        self.code = INIT_VAL
        self.payload_size = INIT_VAL
    
    def unpack(self,data):
        """Little Endian unpack Request Header

        Args:
            data (packet): data packet to unpack
        """
        try:
            header_data = data[:HEADER_SIZE]
            self.uuid,self.code,self.payload_size = struct.unpack(FORMAT_REQUEST_HEADER, header_data)
            return True
        except Exception as excep:
            print(excep)
            return False

class ResponseHeader:
    def __init__(self,code) -> None:
        self.code = code
        self.payload_size = INIT_VAL    #2 bytes
    
    def pack(self):
        try:
            return struct.pack("<HH",self.code,self.payload_size)
        except:
            return b""

class RegRequest:
    def __init__(self,header) -> None:
        self.header = header
        self.name = b""
        self.key = b""
    
    def unpack(self,data):
        """Little Endian unpack Registration Header

        Args:
            data (bin str): data packet to unpack
        """
        if not self.header.unpack(data):
            print("unable to unpack the header request")
        try:
            print("trimming the byte array")
            reg_request_data = data[HEADER_SIZE:HEADER_SIZE + NAME_SIZE]
            self.name = str(struct.unpack(FORMAT_REG_REQUEST, reg_request_data)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except Exception as excep:
            self.name =b""
            return False


class RegResponse:
    def __init__(self) -> None:
        self.header = ResponseHeader(EnumResponseCode.RESPONSE_REG.value)
        self.uuid = b""
    
    def pack(self):
        """Little Endian pack Response Header and UUID
        """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{UUID_SIZE}s",self.uuid)
            print(data)
            return data
        except Exception as e:
            print(e)
            return b""


class KeyPairingRequest:
    def __init__(self, header:RequestHeader) -> None:
        self.header = header
        self.key = b""
    def unpack(self,data):
        """Little Endian unpack Public Key pairing Header

        Args:
            data (bin str): data packet to unpack
        """
        if not self.header.unpack(data):
            print("unable to unpack the header request")
        try:
            print("trimming the key pairing array")
            key_pair_data = data[HEADER_SIZE:]      #trimming Key Data
            self.key = struct.unpack(f"<{self.header.payload_size}s",key_pair_data)[0]
            print(self.key)
            return True
        except Exception as excep:
            print(excep)
            self.key =b""
            return False


class KeyPairingResponse:
    def __init__(self) -> None:
        self.header = ResponseHeader(EnumResponseCode.RESPONSE_PAIRING.value)
        self.key = b""
    
    def pack(self):
        """Little Endian pack Response Header and Public Key
        """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{KEY_SIZE}s",self.key)
            return data
        except:
            return b""


class FileUploadRequest:
    #TODO: CHECK THIS CLASS!!!
    def __init__(self,header:RequestHeader) -> None:
        self.header = header
        self.filename_length = INIT_VAL
        self.filename = b""
        self.size_data_packet = INIT_VAL
        self.data_packet = b""
        self.crc_key = b""

    def unpack(self,data):
        """Little Endian unpack request header and File data

        Args:
            conn (Socket): connection to user
            data (bin str): data packet to unpack
        """
        packet_size = len(data)
        try:
            print(f"****** Unpacking file request ******")
            print(data)
            payload = data[HEADER_SIZE:]
            self.filename_length,self.filename,self.size_data_packet,self.data_packet,self.crc_key = struct.unpack(FORMAT_FILE_UPLOAD_REQUEST,payload)
            self.filename=str(self.filename.partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            print("Exception in FileUploadRequest")
            self.filename_length = INIT_VAL
            self.file_size = INIT_VAL
            self.filename = b""
            self.file = b""
            return False


class FileUploadResponse:
    #response is giving back the CRC of the file
    def __init__(self) -> None:
        self.header = ResponseHeader(EnumResponseCode.RESPONSE_CRC.value)
        self.crc = b""

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"{CRC_SIZE}",self.crc)
            return data
        except:
            return b""

