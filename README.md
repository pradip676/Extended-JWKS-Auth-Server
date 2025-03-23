# JWKS Server (Extended Version)

This project extends a basic JSON Web Key Set (JWKS) server by integrating **SQLite** to securely store private keys. It enhances authentication security by persisting keys to disk and preventing SQL injection.

## Features
- **SQLite-backed storage** for private keys
- **Secure database queries** to prevent SQL injection
- **JWT signing** using stored private keys
- **RESTful API endpoints** for authentication and key retrieval
- **Comprehensive test suite** ensuring over 80% test coverage
- **Gradebot compatibility** for validation

## Installation

### Prerequisites
Ensure you have SQLite and required dependencies installed:
```bash
pip install flask cryptography pyjwt pytest pytest-cov flake8 sqlite3
```
or,
```bash
pip3 install flask cryptography pyjwt pytest pytest-cov flake8 sqlite3
```

## Project Structure
```
-------------- jwks_server --------------
                    |         
  --------------------------------------------
  |                 |                        |  
 server/          tests/                 (root files)
  |                 |                        |
  |                 |              --------------------------------
  |                 |             |      |            |           |
 __init__.py  test_jwks_server.py |    README.md      |     SS of Gradebot
 db_manager.py                    run.py          SS of test Coverage
 jwks_server.py
```

## Usage

### Run the Server
```bash
python3 run.py
```
or,
```bash
python run.py
```
The server will start on `http://127.0.0.1:8080`

### Endpoints

#### 1. JWKS Endpoint
- `GET /.well-known/jwks.json` – Returns valid public keys in JWKS format.
- Invalid methods (POST, PUT, DELETE, PATCH) – Returns `405 Method Not Allowed`.

#### 2. Authentication Endpoint
- `POST /auth` – Returns a valid JWT.
- `POST /auth?expired=true` – Returns an expired JWT.
- Invalid methods (GET, PUT, DELETE, PATCH, HEAD) – Returns `405 Method Not Allowed`.

## Testing

### Run Tests

### Run Tests with Coverage
```bash
python3 -m pytest --cov=server --cov-report=term tests/
```
or, 
```bash
python -m pytest --cov=server --cov-report=term tests/
```

### Test Coverage Result
```
platform darwin -- Python 3.12.5, pytest-8.3.4, pluggy-1.5.0
rootdir: /Users/pradipsapkota/Documents/Extended-JWKS-Auth-Server
plugins: cov-6.0.0
collected 9 items                                                                                                                                                                                   

tests/test_jwks_server.py .........

---------- coverage: platform darwin, python 3.12.5-final-0 ----------
Name                    Stmts   Miss  Cover
-------------------------------------------
server/__init__.py          0      0   100%
server/db_manager.py       34      0   100%
server/jwks_server.py      40      7    82%
-------------------------------------------
TOTAL                      74      7    91%
```

## Linting
Ensure the code follows PEP8 guidelines using flake8:
```bash
flake8 app/
```

## Testing the Server Manually

### 1. Get a Valid JWT:
```bash
curl -X POST http://127.0.0.1:8080/auth -H "Content-Type: application/json" -d '{"username": "userABC"}'  
```
Sample output:
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1IiwidH..."
}
```

### 2. Get Public Keys (JWKS):
```bash
curl -X GET http://127.0.0.1:8080/.well-known/jwks.json
```

Sample output:
```json
{  
  "keys": [  
    {  
      "alg": "RS256",  
      "e": "AQAB",  
      "kid": "25",  
      "kty": "RSA",  
      "n": "rNWyn2dKi_nq19kqf_oj7JqaGVibb-D3LI9A2NSb3Da5...",  
      "use": "sig"  
    }  
  ]  
}  
```

## Run the test client
```bash
./gradebot project2
```
The test client will check for the **DB file** in the current directory, so ensure the client can access it.

## Gradebot output
```
╭────────────────────────────────┬────────┬──────────┬─────────╮
│ RUBRIC ITEM                    │ ERROR? │ POSSIBLE │ AWARDED │
├────────────────────────────────┼────────┼──────────┼─────────┤
│ /auth valid JWT authN          │        │       15 │      15 │
│ Valid JWK found in JWKS        │        │       20 │      20 │
│ Database exists                │        │       15 │      15 │
│ Database query uses parameters │        │       15 │      15 │
├────────────────────────────────┼────────┼──────────┼─────────┤
│                                │  TOTAL │       65 │      65 │
╰────────────────────────────────┴────────┴──────────┴─────────╯   
```
