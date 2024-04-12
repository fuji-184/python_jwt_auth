import jwt
import datetime
from flask import current_app, request, jsonify

def set_secret_key(secret_key):
    current_app.config['SECRET_KEY'] = secret_key

def generate_tokens(user_id, username):
    access_token_payload = {'user_id': user_id, 'username': username}
    refresh_token_payload = {'user_id': user_id, 'username': username, 'type': 'refresh'}
    
    access_token = jwt.encode(access_token_payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    refresh_token = jwt.encode(refresh_token_payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    
    return access_token, refresh_token

def verify_token(token):
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

def refresh_access_token(refresh_token):
    try:
        refresh_token_payload = jwt.decode(refresh_token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        if refresh_token_payload.get('type') != 'refresh':
            return jsonify({'message': 'Invalid refresh token'}), 401
        
        # Generate new access token
        user_id = refresh_token_payload.get('user_id')
        username = refresh_token_payload.get('username')
        new_access_token = generate_tokens(user_id, username)[0]
        
        return jsonify({'access_token': new_access_token})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token'}), 401
