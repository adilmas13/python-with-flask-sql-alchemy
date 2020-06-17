from flask_jwt_extended import jwt_required, get_jwt_claims, jwt_optional, get_jwt_identity, fresh_jwt_required
from flask_restful import Resource, reqparse

from models.item_model import ItemModel


class Item(Resource):  # inherits Resource

    # first use reqparse to check if the keys exist as per requirement
    parser = reqparse.RequestParser()
    parser.add_argument('price', type=float, required=True, help="This field cannot be left blank!")
    parser.add_argument('store_id', type=int, required=True, help="Every item needs a store id")

    @jwt_required
    def get(self, name):
        item = ItemModel.find_by_name(name)
        if item:
            return item.json()
        return {'message': 'Item not found'}, 404

    # always requires a fresh access token ie the first token after login.
    # tokens received after calling the TokenRefresh Api will not work
    @fresh_jwt_required
    def post(self, name):
        if ItemModel.find_by_name(name):
            return {'message': "An Item with name '{}' already exists".format(name)}, 400  # Bad request

        data = Item.parser.parse_args()
        item = ItemModel(name, data['price'], data['store_id'])

        try:
            item.save_to_db()
        except:
            return {'message': 'An error occured inserting the item'}, 500  # internal server error
        return item.json(), 201

    @jwt_required
    def delete(self, name):
        print('IDENTITY')
        claims = get_jwt_claims()
        if not claims['is_admin']:
            return {'message': 'Admin privilege required'}, 401
        item = ItemModel.find_by_name(name)
        if item:
            item.delete_from_db()

        return {'message': 'Item deleted successfully'}

    def put(self, name):
        data = Item.parser.parse_args()
        item = ItemModel.find_by_name(name)

        if item is None:
            item = ItemModel(name, data['price'], data['store_id'])
        else:
            item.price = data['price']

        item.save_to_db()
        return item.json()


class ItemList(Resource):

    @jwt_optional # api can be called with and without token
    def get(self):
        user_id = get_jwt_identity() # gets the identity which is the user id
        items = [item.json() for item in ItemModel.find_all()]
        if user_id: # if user is logged in sent all the item data
            return {'items': items}, 200

        return {
            'items': [item['name'] for item in items],  # if user is not logged in send only item names
            'message': 'More data available if you login'
        }, 200
