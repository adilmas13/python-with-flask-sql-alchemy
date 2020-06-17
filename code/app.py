from db import db
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_restful import Api
from resources.item import Item, ItemList
from resources.store import Store
from resources.store import StoreList
# Resource are concerned with entities eg Student. They are mapped with db
from resources.user import UserRegister, User, UserLogin, TokenRefresh, UserLogout

from blacklist import BLACKLIST

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True  # tracks JWT error
app.config['JWT_BLACKLIST_ENABLED'] = True  # enable black listing fo jwt users
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access',
                                            'refresh']  # enabling black list for both access and refresh token
app.config['JWT_SECRET_KEY'] = 'adil'
api = Api(app)


@app.before_first_request
def create_tables():
    db.create_all()


# jwt = JWT(app, authenticate, identity)  # creates /auth end point
jwt = JWTManager(app)


# returns a boolean whether to block a user. if return True then user is blocked
# @jwt.token_in_blacklist_loader
# def check_if_token_in_blacklist(decrypted_token):
#     return decrypted_token['identity'] in BLACKLIST  # check if user is in black list


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return decrypted_token['jti'] in BLACKLIST  # check if user is in black list for logout

@jwt.user_claims_loader
def add_claims_to_jwt(identity):
    if identity == 1:  # instead of hard coding, you can read data from database
        return {'is_admin': True}
    return {'is_admin': False}


@jwt.expired_token_loader
def expired_token_callback():  # message to send back to user when token is expired
    return jsonify({
        'description': 'The token has expired',
        'error': 'token_expired'
    }), 401


@jwt.invalid_token_loader
def invalid_token_callback():
    return jsonify({
        'description': 'Signature verification failed',
        'error': 'invalid_token'
    }), 401


@jwt.unauthorized_loader
def missing_token_callback():
    return jsonify({
        'description': 'Request does not contain an access token',
        'error': 'authorization_required'
    }), 401


@jwt.needs_fresh_token_loader
def token_not_fresh_callback():
    return jsonify({
        'description': 'The token is not fresh',
        'error': 'fresh_token_required'
    }), 401


@jwt.revoked_token_loader
def revoke_token_callback():
    return jsonify({
        'description': 'The token has been revoked',
        'error': 'token_revoked'
    }), 401


api.add_resource(Store, '/store/<string:name>')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(UserRegister, '/register')
api.add_resource(StoreList, '/stores')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout, '/logout')
api.add_resource(TokenRefresh, '/refresh')

# run this only if it a main file ie it is executed via terminal
# will not run app if app is imported from another file
if __name__ == '__main__':
    db.init_app(app)
    app.run(port=5000, debug=True)
