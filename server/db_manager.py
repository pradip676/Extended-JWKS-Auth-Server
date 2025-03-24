import sqlite3
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Name of the SQLite database file
DB_FILE = "totally_not_my_privateKeys.db"


def setup_database():
    """
    Set up a database to store RSA keys
    """
    with sqlite3.connect(DB_FILE) as connection:
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            '''
        )


def store_rsa_key(rsa_obj, expiry):
    """
    Store a PEM-encoded RSA key and its expiration timestamp
    in the database
    """
    pem_data = rsa_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            'INSERT INTO keys (key, exp) VALUES (?, ?)', (pem_data, expiry)
        )


def get_rsa_key(get_expired=False):
    """
    Retrieve a single RSA key from the database,
    if get_expired is True, return an expired key,
    otherwise, return a valid (unexpired) key.
    """
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    # SQL to select valid or expired keys
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
        rsa_key = serialization.load_pem_private_key(
            record[1], password=None
        )
        # Return key id and secret key obj
        return kid, rsa_key
    # for no key found
    return None, None


def generate_and_save_keys():
    """
    Generate and store two RSA keys:
    - one valid (expires in 1h)
    - one expired (expired 1h ago)
    """
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    # Generate RSA private key
    valid_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Store valid key with expiry of 1hr from now
    store_rsa_key(valid_key, now_ts + 3600)

    # Store expired key with expiry 1hr ago
    store_rsa_key(expired_key, now_ts - 3600)


def fetch_valid_keys():
    """
    Fetch all valid (unexpired) keys from the database
    return as a list of (kid, key) tuples
    """
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    with sqlite3.connect(DB_FILE) as connection:
        cursor = connection.execute(
            'SELECT kid, key FROM keys WHERE exp > ?', (now_ts,)
        )
        # Return all valid keys
        return cursor.fetchall()
