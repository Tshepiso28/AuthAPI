from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt
)
import psycopg2
from psycopg2 import extras
import os

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key')
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blacklist

def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        database=os.environ.get('DB_NAME', 'testapi'),
        user=os.environ.get('DB_USER', 'postgres'),
        password=os.environ.get('DB_PASSWORD', '1017'),
        cursor_factory=extras.DictCursor
    )

# Sign-up Route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        conn.close()
        return jsonify({'message': 'User already exists'}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    cursor.execute(
        "INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s)",
        (name, email, password_hash)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'message': 'User created successfully'}), 201

# Sign-in Route
@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user and bcrypt.check_password_hash(user['password_hash'], password):
        access_token = create_access_token(identity=str(user['id']))
        cursor.close()
        conn.close()
        return jsonify({'access_token': access_token}), 200

    cursor.close()
    conn.close()
    return jsonify({'message': 'Invalid credentials'}), 401

# Sign-out Route
@app.route('/signout', methods=['POST'])
@jwt_required()
def signout():
    jti = get_jwt()["jti"]
    blacklist.add(jti)
    return jsonify({"message": "Successfully signed out"}), 200

# @app.route('/protected', methods=['GET'])
# @jwt_required()
# def protected():
#     return jsonify({"message": "You are logged in and token is valid!"}), 200

if __name__ == '__main__':
    app.run(debug=True)
