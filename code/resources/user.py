from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, jwt_refresh_token_required, \
    get_jwt_identity, get_raw_jwt
from flask_restful import Resource, reqparse
from models.user_model import UserModel

from blacklist import BLACKLIST


class UserRegister(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username', type=str, required=True, help="Username cannot be blank!")
    parser.add_argument('password', type=str, required=True, help="Password cannot be blank!")

    def post(self):
        data = UserRegister.parser.parse_args()
        if UserModel.find_by_username(data['username']):
            return {'message': "User by the name '{}' already exists".format(data['username'])}, 400

        # user = UserModel(data['username'], data['password'])
        user = UserModel(**data)
        user.save_to_db()
        return {"message": "User created successfully"}, 201


class User(Resource):
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {
                       'message': 'User not found'
                   }, 404
        return user.json()

    @classmethod
    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {
                       'message': 'User not found'
                   }, 404
        user.delete_from_db()
        return {'message': 'User deleted'}


class UserLogin(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username', type=str, required=True, help="Username cannot be blank!")
    parser.add_argument('password', type=str, required=True, help="Password cannot be blank!")

    @classmethod
    def post(cls):
        # get data from the parser
        data = cls.parser.parse_args()

        # find user in database
        user = UserModel.find_by_username(data['username'])
        if user and user.password == data['password']:
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {
                       'access_token': access_token,
                       'refresh_token': refresh_token
                   }, 200

        return {'message': 'Invalid credentials'}, 401


class UserLogout(Resource):

    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']  # jti is "JWT ID", a unique identifier for a JWT
        BLACKLIST.add(jti)
        return {'message': 'successfully logged out'}


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        new_token = create_access_token(current_user,
                                        fresh=False)  # its not fresh token, Fresh token is the actual token
        return {'access_token': new_token}, 200
