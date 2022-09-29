import struct
from enum import Enum
import uuid

INIT_VAL = 0
UUID_SIZE = 16
CODE_SIZE = 2
PAYLOAD_SIZE = 2
HEADER_SIZE = 23  # Not including the UUID
SYMM_KEY_SIZE = 16
NAME_SIZE = 127
FILE_NAME_MAX_SIZE = 256  # File name to bits
FILE_LENGTH_SIZE = 1  # Length of filename in bytes
FILE_MAX_DATA_PACKET = 256
FILE_PACKET_SIZE = 1
KEY_SIZE = 160  # Convert 160 bytes to bits
CRC_SIZE = 4
AES_ENCRYPTED = 128


# 16s- UUID, B- version, H- opcode, I-payload_size
FORMAT_REQUEST_HEADER = f"<{UUID_SIZE}sBHI"
# 127s- Name
FORMAT_REG_REQUEST = f"<{NAME_SIZE}s"
# TODO: ADD format for key_pair

# L- encrypted File Size, 256s - filename, 255s-DataPacket
FORMAT_FILE_UPLOAD_REQUEST = f"<L{FILE_NAME_MAX_SIZE}s{FILE_MAX_DATA_PACKET}s"

MAX_RETRIES = 3


class EnumRequestCode(Enum):
    REQUEST_REG = 1100
    REQUEST_PAIRING = 1101
    REQUEST_UPLOAD = 1103
    CRC_OK = 1104
    CRC_AGAIN = 1105
    CRC_FAILED = 1106


class EnumResponseCode(Enum):
    RESPONSE_REG = 2100
    RESPONSE_PAIRING = 2102
    RESPONSE_UPLOAD_CRC_OK = 2103
    RESPONSE_OK = 2104
    RESPONSE_ERROR = 2005


class RequestHeader:
    def __init__(self):
        self.uuid = b""
        self.version = INIT_VAL
        self.code = INIT_VAL
        self.payload_size = INIT_VAL

    def unpack(self, data):
        """Little Endian unpack Request Header

        Args:
            data (packet): data packet to unpack
        """
        try:
            header_data = data[:HEADER_SIZE]
            self.uuid, self.version, self.code, self.payload_size = struct.unpack(
                FORMAT_REQUEST_HEADER, header_data
            )
            self.uuid = uuid.UUID(bytes_le=self.uuid)
            return True
        except Exception as excep:
            print(excep)
            return False


class ResponseHeader:
    def __init__(self, code) -> None:
        self.version = INIT_VAL
        self.code = code
        self.payload_size = INIT_VAL  # 2 bytes

    def pack(self):
        try:
            return struct.pack("<BHL", self.version, self.code, self.payload_size)
        except:
            print("Exception in Response Header")
            return b""


class RegRequest:
    def __init__(self, header) -> None:
        self.header = header
        self.name = b""
        self.key = b""

    def unpack(self, data):
        """Little Endian unpack Registration Header

        Args:
            data (bin str): data packet to unpack
        """
        try:
            print("trimming the byte array")
            reg_request_data = data[HEADER_SIZE : HEADER_SIZE + NAME_SIZE]
            self.name = str(
                struct.unpack(FORMAT_REG_REQUEST, reg_request_data)[0]
                .partition(b"\0")[0]
                .decode("utf-8")
            )
            return True
        except Exception as excep:
            self.name = b""
            return False


class RegResponse:
    def __init__(self) -> None:
        self.header = ResponseHeader(EnumResponseCode.RESPONSE_REG.value)
        self.uuid = b""

    def pack(self):
        """Little Endian pack Response Header and UUID"""
        try:
            data = self.header.pack()
            data += struct.pack(f"<{UUID_SIZE}s", self.uuid)
            print(data)
            return data
        except Exception as e:
            print(e)
            return b""


class KeyPairingRequest:
    def __init__(self, header: RequestHeader) -> None:
        self.header = header
        self.key = b""

    def unpack(self, data):
        """Little Endian unpack Public Key pairing Header

        Args:
            data (bin str): data packet to unpack
        """
        try:
            print("trimming the key pairing array")
            key_pair_data = data[HEADER_SIZE:]  # trimming Key Data
            self.key = struct.unpack(f"<{self.header.payload_size}s", key_pair_data)[0]
            print(self.key)
            return True
        except Exception as excep:
            print(excep)
            self.key = b""
            return False


class KeyPairingResponse:
    def __init__(self) -> None:
        self.header = ResponseHeader(EnumResponseCode.RESPONSE_PAIRING.value)
        self.key = b""

    def pack(self):
        """Little Endian pack Response Header and Public Key"""
        try:
            data = self.header.pack()
            data += struct.pack(f"<{KEY_SIZE}s", self.key)
            return data
        except:
            return b""


class FileUploadRequest:
    def __init__(self, header: RequestHeader) -> None:
        self.header = header
        self.encrypted_file_size = INIT_VAL
        self.filename = b""
        self.encrypted_data_packet = b""

    def unpack(self, data):
        """Little Endian unpack request header and File data

        Args:
            conn (Socket): connection to user
            data (bin str): data packet to unpack
        """
        try:
            print(f"****** Unpacking file request ******")
            print(data)
            payload = data[HEADER_SIZE:]
            (
                self.encrypted_file_size,
                self.filename,
                self.encrypted_data_packet,
            ) = struct.unpack(FORMAT_FILE_UPLOAD_REQUEST, payload)
            self.filename = str(self.filename.partition(b"\0")[0].decode("utf-8"))
            self.encrypted_data_packet = self.encrypted_data_packet[
                : self.header.payload_size
            ]
            return True
        except:
            print("Exception in FileUploadRequest")
            self.filename_length = INIT_VAL
            self.file_size = INIT_VAL
            self.filename = b""
            self.file = b""
            return False


class FileUploadResponse:
    # response is giving back the CRC of the file
    def __init__(self) -> None:
        self.header = ResponseHeader(EnumResponseCode.RESPONSE_UPLOAD_CRC_OK.value)
        self.crc = INIT_VAL

    def pack(self):
        try:
            data = self.header.pack()
            data += struct.pack(f"<L", self.crc)
            return data
        except:
            return b""
