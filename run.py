# This program sets up the SQLite database, generates RSA keys for JWT authentication,
# and runs a JWKS server using Flask.

from server.jwks_server import app
from server.db_manager import setup_database, generate_and_save_keys

if __name__ == '__main__':
    setup_database()
    generate_and_save_keys()
    app.run(port=8080, debug=False)