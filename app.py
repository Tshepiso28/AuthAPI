from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt, get_jwt_identity
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
        database=os.environ.get('DB_NAME', 'rentdb'),
        user=os.environ.get('DB_USER', 'damacm179'),
        password=os.environ.get('DB_PASSWORD', '1017'),
        cursor_factory=extras.DictCursor
    )

# Sign-up Route
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM user_rent WHERE email = %s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        conn.close()
        return jsonify({'message': 'User already exists'}), 400

    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    cursor.execute(
        "INSERT INTO user_rent (full_name, email, password_hash) VALUES (%s, %s, %s)",
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

    cursor.execute("SELECT * FROM user_rent WHERE email = %s", (email,))
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

# Helper function to check if user is subscribed
def is_user_subscribed(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT is_subscribed FROM user_rent WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user and user['is_subscribed']

# List all available solar panels
@app.route('/solar-panels', methods=['GET'])
@jwt_required()
def list_solar_panels():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, name, description, rental_price_per_day, owner_id "
        "FROM solar_panels WHERE is_available = TRUE"
    )
    panels = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([
        {
            'id': panel['id'],
            'name': panel['name'],
            'description': panel['description'],
            'rental_price_per_day': float(panel['rental_price_per_day']),
            'owner_id': panel['owner_id']
        } for panel in panels
    ]), 200


# Add a new solar panel (subscribed users only)
@app.route('/solar-panels', methods=['POST'])
@jwt_required()
def add_solar_panel():
    user_id = get_jwt_identity()
    if not is_user_subscribed(user_id):
        return jsonify({'message': 'Subscription required to add solar panels'}), 403

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    rental_price_per_day = data.get('rental_price_per_day')

    if not name or not rental_price_per_day or not isinstance(rental_price_per_day,
                                                              (int, float)) or rental_price_per_day <= 0:
        return jsonify({'message': 'Invalid or missing fields'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO solar_panels (name, description, rental_price_per_day, owner_id) "
        "VALUES (%s, %s, %s, %s) RETURNING id",
        (name, description, rental_price_per_day, user_id)
    )
    panel_id = cursor.fetchone()['id']
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'Solar panel added successfully', 'panel_id': panel_id}), 201


# Rent a solar panel
@app.route('/rentals', methods=['POST'])
@jwt_required()
def rent_solar_panel():
    user_id = get_jwt_identity()
    data = request.get_json()
    solar_panel_id = data.get('solar_panel_id')

    if not solar_panel_id or not isinstance(solar_panel_id, int):
        return jsonify({'message': 'Valid solar_panel_id required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if panel exists and is available
    cursor.execute(
        "SELECT is_available, owner_id FROM solar_panels WHERE id = %s",
        (solar_panel_id,)
    )
    panel = cursor.fetchone()

    if not panel:
        cursor.close()
        conn.close()
        return jsonify({'message': 'Solar panel not found'}), 404

    if not panel['is_available']:
        cursor.close()
        conn.close()
        return jsonify({'message': 'Solar panel not available'}), 400

    if panel['owner_id'] == int(user_id):
        cursor.close()
        conn.close()
        return jsonify({'message': 'Cannot rent your own solar panel'}), 400

    # Create rental record and mark panel as unavailable
    cursor.execute(
        "INSERT INTO rentals (user_id, solar_panel_id) VALUES (%s, %s) RETURNING id",
        (user_id, solar_panel_id)
    )
    rental_id = cursor.fetchone()['id']
    cursor.execute(
        "UPDATE solar_panels SET is_available = FALSE WHERE id = %s",
        (solar_panel_id,)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'message': 'Solar panel rented successfully', 'rental_id': rental_id}), 201

# List user's rentals
@app.route('/rentals', methods=['GET'])
@jwt_required()
def list_rentals():
    user_id = get_jwt_identity()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT r.id, r.solar_panel_id, r.rental_start_date, r.status, sp.name, sp.rental_price_per_day "
        "FROM rentals r JOIN solar_panels sp ON r.solar_panel_id = sp.id "
        "WHERE r.user_id = %s",
        (user_id,)
    )
    rentals = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify([
        {
            'id': rental['id'],
            'solar_panel_id': rental['solar_panel_id'],
            'name': rental['name'],
            'rental_price_per_day': float(rental['rental_price_per_day']),
            'rental_start_date': rental['rental_start_date'].isoformat(),
            'status': rental['status']
        } for rental in rentals
    ]), 200

if __name__ == '__main__':
    app.run(debug=True)
