import os
import zlib

PARENT_DIR = "D:\\MMN15\\"


def create_file(client_uuid, file_name):
    path = os.path.join(PARENT_DIR, client_uuid)
    os.mkdir(path)
    file_path = os.path.join(PARENT_DIR, client_uuid, file_name)
    file = open(file_path, "a")
    return file


BUFFER_SIZE = 8192


def get_crc32(client_uuid, file_name):
    file_path = os.path.join(PARENT_DIR, client_uuid, file_name)
    with open(file_path, "rb") as f:
        crc = 0
        while True:
            data = f.read(BUFFER_SIZE)
            if not data:
                break
            crc += zlib.crc32(data, crc)
    return crc
