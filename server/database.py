import sqlite3
import os
import uuid
from datetime import datetime
from sqlite3 import Error
from unittest import result
import struct

TABLE_CLIENTS = "clients"
TABLE_FILES = "files"


class Client:
    def __init__(self, uuid, name, public_key, aes_key) -> None:
        self.uuid = uuid
        self.name = name
        self.public_key = public_key
        self.last_seen = str(datetime.now())
        self.aes_key = aes_key

    def __str__(self) -> str:
        return f"UUID: {str(self.uuid)}\n\tUsername: {self.name}\n\tPublicKey: {self.public_key}\n\tAesKey: {self.aes_key}\n\tLastSeen: {self.last_seen}"


class File:
    def __init__(self, uuid:uuid.UUID, file_path:str, verified:bool) -> None:
        self.uuid = uuid
        self.file_name = os.path.basename(file_path)
        self.path_name = os.path.dirname(file_path)
        self.verified = verified


class Database:
    def __init__(self, filename, logger) -> None:
        self.filename = filename
        self.sql_conn = None
        self.logger = logger

    def create_connection(self):
        """Create a database connection to SQLite database"""
        # TODO: create trigger  that updates Last seen
        try:
            sqlite3.register_adapter(uuid.UUID, lambda u: u.bytes_le)
            sqlite3.register_converter("GUID", lambda b: uuid.UUID(bytes_le=b))
            self.logger.info(f"Intizaliting connection to Databate: {self.filename}")
            self.sql_conn = sqlite3.connect(self.filename)
            self.logger.info(f"SQLite3 version -> {sqlite3.version}")

        except Error as e:
            self.logger.error(e)
            raise (e)

    def init_tables(self):
        """create a table from the create_table_sql statement"""
        sql_create_clients_table = f"""CREATE TABLE IF NOT EXISTS {TABLE_CLIENTS} (
                                    id GUID PRIMARY KEY,
                                    name text NOT NULL,
                                    publicKey text,
                                    lastSeen TIMESTAMP,
                                    aesKey text);"""
        sql_create_files_table = f"""CREATE TABLE IF NOT EXISTS {TABLE_FILES} (
                                    id GUID PRIMARY KEY,
                                    fileName text NOT NULL,
                                    pathName text NOT NULL,
                                    verified bool
                                );"""
        if self.sql_conn is not None:
            self.logger.info("Creating Tables")
            try:
                cursor = self.sql_conn.cursor()
                cursor.execute(sql_create_clients_table)
                cursor.execute(sql_create_files_table)
            except Error as e:
                self.logger.error(e)
                raise (e)
        else:
            self.logger.error("Error! cannot create the database connection.")
            # self.logger.info("Tables already Exists")

    def execute_query(self, query, args, commit=False, get_last_row=False):
        """Given an query and args, execute query, and return the results."""
        results = None
        try:
            cursor = self.sql_conn.cursor()
            cursor.execute(query, args)
            if commit:
                self.sql_conn.commit()
                results = True
            else:
                results = cursor.fetchall()
            if get_last_row:
                results = cursor.lastrowid
        except Exception as e:
            self.logger.error(e)
        return results

    def client_username_exists(self, username):
        """Check if username already exists in database

        Args:
            username (str): username to create
        """
        results = self.execute_query(
            f"SELECT * FROM {TABLE_CLIENTS} where Name = ?", [username]
        )
        if not results:
            self.logger.info(f"{username} doesnt exist in DB")
            return False
        return len(results) > 0

    def id_exists(self, uuid, table):
        """Check if user UUID exists in database

        Args:
            uuid (str): UUID of user
        """
        results = self.execute_query(f"SELECT * FROM {table} WHERE id = ?", [uuid])
        if not results:
            self.logger.info(f"{uuid} doesnt exist in DB")
            return False
        return len(results) > 0

    def get_public_key(self, uuid: str):
        """Get public key from database

        Args:
            uuid (str): UUID of user
        """
        result = self.execute_query(
            f"SELECT publicKey FROM {TABLE_CLIENTS} WHERE id = ?", [uuid]
        )

        if result:
            self.logger.info(f"{uuid}'s public Key has been retrieved from DB")
            return result[0][0]
        else:
            return False

    def update_public_key(self, uuid: str, public_key):
        """Updates the User's public key

        Args:
            uuid (str): UUID of user
        """
        result = self.execute_query(
            f"UPDATE {TABLE_CLIENTS} SET publicKey = ? where id = ?",
            [public_key, uuid],
            commit=True,
        )
        return result

    def update_aes_key(self, uuid: str, aes_key):
        """Updates the User's public key

        Args:
            uuid (str): UUID of user
        """
        result = self.execute_query(
            f"UPDATE {TABLE_CLIENTS} SET aesKey = ? where id = ?",
            [aes_key, uuid],
            commit=True,
        )
        return result

    def get_aes_key(self, uuid: str):
        """_summary_

        Args:
            uuid (str): Client uuid

        """
        result = self.execute_query(
            f"SELECT aesKey FROM {TABLE_CLIENTS} WHERE id = ?", [uuid]
        )
        if result:
            self.logger.info(f"{uuid}'s AES Key has been retrieved from DB")
            return result[0][0]
        else:
            return False

    def store_client(self, client: Client) -> bool:
        """Saves the client into the DB

        Args:
            client (Client): New Client

        Returns:
            bool: True if succeded
        """
        return self.execute_query(
            f"INSERT INTO {TABLE_CLIENTS} VALUES (?, ?, ?, ?, ?)",
            [
                client.uuid,
                client.name,
                client.public_key,
                client.last_seen,
                client.aes_key,
            ],
            True,
        )

    def store_file(self,file:File) -> bool:
        return self.execute_query(
            f"INSERT INTO {TABLE_FILES} VALUES (?, ?, ?, ?)",
            [   
                file.uuid,
                file.file_name,
                file.path_name,
                file.verified
            ],
            True,
        )