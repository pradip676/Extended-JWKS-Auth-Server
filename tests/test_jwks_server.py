#!/usr/bin/env python3
import unittest
import sqlite3
import json
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa

# Import our app and database functions from our modules within the 'server' package.
from server.jwks_server import app
from server.db_manager import (
    setup_database,
    generate_and_save_keys,
    store_rsa_key,
    get_rsa_key,
    fetch_valid_keys
)

DATABASE_NAME = "totally_not_my_privateKeys.db"

class TestJWKSApp(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Initialize the database once for the test class."""
        setup_database()

    def setUp(self):
        """Set up a test client and clear the DB before each test."""
        self.client = app.test_client()
        self._clear_db()

    def tearDown(self):
        """Clear the DB after each test to avoid state carryover."""
        self._clear_db()

    def _clear_db(self):
        """Helper function to clear the keys table."""
        with sqlite3.connect(DATABASE_NAME) as conn:
            conn.execute("DELETE FROM keys")
            conn.commit()

    def test_initialize_db(self):
        """Test that the database table is created."""
        with sqlite3.connect(DATABASE_NAME) as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'")
            result = cursor.fetchone()
        self.assertIsNotNone(result, "The 'keys' table should exist after initialization.")

    def test_create_and_save_keys(self):
        """Test that keys are generated and stored in the database."""
        create_and_save_keys()
        with sqlite3.connect(DATABASE_NAME) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM keys")
            count = cursor.fetchone()[0]
        self.assertGreater(count, 0, "At least one key should be stored in the database.")

    def test_authenticate_user(self):
        """Test the /auth endpoint for token generation."""
        create_and_save_keys()
        payload = {"username": "testuser"}
        response = self.client.post('/auth', json=payload)
        self.assertEqual(response.status_code, 200, "Authentication should succeed with status code 200.")
        data = json.loads(response.data)
        self.assertIn('token', data, "Response should include a token.")

    def test_get_jwks(self):
        """Test the /.well-known/jwks.json endpoint returns valid keys."""
        create_and_save_keys()
        response = self.client.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200, "JWKS endpoint should return status code 200.")
        data = json.loads(response.data)
        self.assertIn('keys', data, "JWKS response must include a 'keys' field.")
        self.assertGreater(len(data['keys']), 0, "There should be at least one key in the JWKS response.")

    def test_retrieve_rsa_key(self):
        """Test retrieval of a valid RSA key from the database."""
        # Generate and store a valid key (expires in the future)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600
        store_rsa_key(private_key, exp)

        kid, key = retrieve_rsa_key(get_expired=False)
        self.assertIsNotNone(kid, "A valid key's ID should be retrieved.")
        self.assertIsNotNone(key, "A valid RSA key should be retrieved.")

    def test_retrieve_rsa_key_no_valid(self):
        """Test retrieval when no valid key exists."""
        # Without inserting any valid keys, attempt to retrieve one.
        kid, key = retrieve_rsa_key(get_expired=False)
        self.assertIsNone(kid, "Should return None when no valid key exists.")
        self.assertIsNone(key, "Should return None when no valid key exists.")

    def test_store_rsa_key(self):
        """Test that storing an RSA key increases the DB count."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        exp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600
        store_rsa_key(private_key, exp)
        with sqlite3.connect(DATABASE_NAME) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM keys")
            count = cursor.fetchone()[0]
        self.assertGreater(count, 0, "Storing a key should result in at least one record in the database.")

    def test_expired_key_retrieval(self):
        """Test that an expired key is properly retrieved when requested."""
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) - 3600
        store_rsa_key(expired_key, expired_time)
        kid, key = retrieve_rsa_key(get_expired=True)
        self.assertIsNotNone(kid, "An expired key's ID should be retrieved.")
        self.assertIsNotNone(key, "An expired RSA key should be retrieved.")

    def test_fetch_valid_keys(self):
        """Test that fetch_valid_keys returns only valid keys."""
        # Insert one valid key and one expired key.
        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        store_rsa_key(valid_key, now_ts + 3600)   # valid
        store_rsa_key(expired_key, now_ts - 3600)   # expired

        keys = fetch_valid_keys()
        # Only the valid key should be returned.
        self.assertEqual(len(keys), 1, "fetch_valid_keys should return only unexpired keys.")

if __name__ == '__main__':
    unittest.main()
