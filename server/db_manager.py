import sqlite3
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DB_FILE = "totally_not_my_privateKeys.db"

#Set up SQLite database
def setup_database():
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute(''' 
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
# Store a PEM-encoded RSA key and its expiration timestamp in the database
def store_rsa_key(rsa_obj, expiry):
    pem_data = rsa_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem_data, expiry))

# Retrieve a single RSA key from the database;
# if get_expired is True, return an expired key; 
# otherwise, return a valid (unexpired) key.
def get_rsa_key(get_expired=False):
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    query = '''
        SELECT kid, key FROM keys 
        WHERE exp {} ? 
        ORDER BY exp {} LIMIT 1
    '''.format('<' if get_expired else '>', 'DESC' if get_expired else 'ASC')
    
    with sqlite3.connect(DB_FILE) as connection:
        cursor = connection.execute(query, (now_ts,))
        record = cursor.fetchone()

    if record:
        kid = record[0]
        rsa_key = serialization.load_pem_private_key(record[1], password=None)
        return kid, rsa_key
    return None, None
# Generate and store two RSA keys:
# one valid (expires in 1h) and one expired (expired 1h ago)
def generate_and_save_keys():
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    
    valid_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    store_rsa_key(valid_key, now_ts + 3600)  
    store_rsa_key(expired_key, now_ts - 3600)  

# Fetch all valid (unexpired) keys from the database
# return as a list of (kid, key) tuples
def fetch_valid_keys():
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    with sqlite3.connect(DB_FILE) as connection:
        cursor = connection.execute('SELECT kid, key FROM keys WHERE exp > ?', (now_ts,))
        return cursor.fetchall()
