import datetime
import jwt
import base64
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization

# Import database functions from db_manager
from .db_manager import get_rsa_key, fetch_valid_keys

app = Flask(__name__)

# /auth endpoint: creates a JWT token
@app.route('/auth', methods=['POST'])
def post_token():
    if not request.is_json:
        return jsonify({'error': 'Invalid content type'}), 415

    req_body = request.get_json()
    want_expired = request.args.get('expired', 'false').lower() == 'true'

    try:
        username = req_body['username']
    except KeyError:
        return jsonify({'error': 'Missing username field'}), 400

    key_id, rsa_priv = get_rsa_key(get_expired=want_expired)
    if not rsa_priv:
        return jsonify({'error': 'No suitable key found'}), 404

    current_time = datetime.datetime.now(datetime.timezone.utc)
    token_exp = current_time + datetime.timedelta(hours=1)  # Standard expiration

    if want_expired:
        token_exp = current_time - datetime.timedelta(minutes=5)  # Already expired

    try:
        token = jwt.encode(
            {'sub': username, 'iat': current_time, 'exp': token_exp},
            rsa_priv,
            algorithm='RS256',
            headers={'kid': str(key_id)}
        )
        return jsonify({'token': token})
    except Exception:
        return jsonify({'error': 'Token generation failed'}), 500

# /well-known/jwks.json endpoint: returns public keys in JWKS format
@app.route('/.well-known/jwks.json', methods=['GET'])
def serve_jwks():
    jwks_keys = []
    # Get all valid (unexpired) keys from the database
    valid_keys = fetch_valid_keys()
    for kid, key_data in valid_keys:
        # Load the private key from the DB and get its public key numbers
        private_key = serialization.load_pem_private_key(key_data, password=None)
        public_numbers = private_key.public_key().public_numbers()
        # Convert modulus and exponent to bytes
        n_bytes = public_numbers.n.to_bytes(256, 'big')
        e_bytes = public_numbers.e.to_bytes(3, 'big')
        # Add the key info in JWKS format to the list
        jwks_keys.append({
            'kid': str(kid),
            'kty': 'RSA',
            'alg': 'RS256',
            'use': 'sig',
            'n': base64.urlsafe_b64encode(n_bytes).decode().rstrip('='),
            'e': base64.urlsafe_b64encode(e_bytes).decode().rstrip('=')
        })
    return jsonify({'keys': jwks_keys})
