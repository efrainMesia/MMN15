import sqlite3
import uuid 
from sqlite3 import Error
from unittest import result
import struct
TABLE_CLIENTS = 'clients'
TABLE_FILES = 'files'

class Client:
    def __init__(self,uuid,name,public_key,last_seen,aes_key) -> None:
        self.uuid = uuid
        self.name = name
        self.public_key = public_key
        self.last_seen  = last_seen
        self.aes_key = aes_key

class Database():
    def __init__(self,filename,logger) -> None:
        self.filename = filename
        self.sql_conn = None
        self.logger = logger
    
    def create_connection(self):
        """Create a database connection to SQLite database"""

        try:
            sqlite3.register_adapter(uuid.UUID, lambda u: u.bytes_le)
            sqlite3.register_converter('GUID', lambda b: uuid.UUID(bytes_le=b))
            #self.logger.info("Intizaliting connection to Databate")
            print(self.filename)
            self.sql_conn = sqlite3.connect(self.filename)
            #self.logger.info(f"SQLite3 version -> {sqlite3.version}")


        except Error as e:
            #self.logger.error(e)
            raise(e)

    def init_tables(self):
        """create a table from the create_table_sql statement
        """
        sql_create_clients_table = f"""CREATE TABLE IF NOT EXISTS {TABLE_CLIENTS} (
                                    id GUID PRIMARY KEY,
                                    name text NOT NULL,
                                    publicKey text,
                                    lastSeen TIMESTAMP,
                                    AESKey text);"""
        sql_create_files_table = f"""CREATE TABLE IF NOT EXISTS {TABLE_FILES} (
                                    id GUID PRIMARY KEY,
                                    fileName text NOT NULL,
                                    pathName text NOT NULL,
                                    verified bool
                                );"""
        if self.sql_conn is not None:
            #self.logger.info("Creating Tables")
            try:
                cursor = self.sql_conn.cursor()
                cursor.execute(sql_create_clients_table)
                cursor.execute(sql_create_files_table)
            except Error as e:
                #self.logger.error(e)
                raise(e)
        else:
            print("Error! cannot create the database connection.")
            #self.logger.info("Tables already Exists")
    
    def execute_query(self,query,args,commit=False, get_last_row=False):
        """Given an query and args, execute query, and return the results."""
        results = None
        try:
            cursor = self.sql_conn.cursor()
            cursor.execute(query,args)
            if commit:
                self.sql_conn.commit()
                results = True
            else:
                results = cursor.fetchall()
            if get_last_row:
                results = cursor.lastrowid
        except Exception as e:
            print(e)
        return results


    def client_username_exists(self,username):
        """Check if username already exists in database

        Args:
            username (str): username to create
        """
        results = self.execute_query(f"SELECT * FROM {TABLE_CLIENTS} where Name = ?", [username])
        if not results:
            return False
        return len(results)>0
    
    def client_id_exists(self,uuid):
        """Check if user UUID exists in database

        Args:
            uuid (str): UUID of user
        """
        results = self.execute_query(f"SELECT * FROM {TABLE_CLIENTS} WHERE GUID = ?", [uuid])
        if not results:
            return False
        return len(results)>0
    
    def get_public_key(self,uuid:str):
        """Get public key from database

        Args:
            uuid (str): UUID of user
        """
        results = self.execute_query(f"SELECT publicKey FROM {TABLE_CLIENTS} WHERE id = ?",[uuid])
        print(f"results from db {results}")
        return results
    
    def update_public_key(self,uuid:str,public_key):
        """Updates the User's public key

        Args:
            uuid (str): UUID of user
        """ 
        results = self.execute_query(f"UPDATE {TABLE_CLIENTS} SET publicKey = ? where id = ?",[public_key,uuid],commit=True)
        return results


    def store_client(self,client:Client):
        print(type(client.uuid))
        print(client.uuid)
        print(str(client.uuid))
        return self.execute_query(f"INSERT INTO {TABLE_CLIENTS} VALUES (?, ?, ?, ?, ?)",
                            [client.uuid, client.name, client.public_key, client.last_seen,client.aes_key], True)

    

