from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
import pymongo

app = Flask(__name__)
CORS(app)
# Replace your URL here.
connection_url = 'mongodb+srv://abhay:Abhay%409819@cluster0.6i1t3sc.mongodb.net/test'

client = pymongo.MongoClient(connection_url)

# Database
Database = client.get_database('ApsitDB')
# Table
UserTable = Database.logininfo


@app.route('/')
def hello_world():
    return "Hi! i am apsit-community's backend"


@app.route('/add-user', methods=['POST'])
def add_user():
    if request.method == 'POST':
        jsonObjectGotWithAPI = request.json

        queryObject = {'moodle_ID': jsonObjectGotWithAPI['moodleId']}
        query = UserTable.find_one(queryObject)
        if query:
            return make_response({'message': 'User already exists'}, 302)

        newUser = {
            'name': jsonObjectGotWithAPI['user_name'],
            'moodle_ID': jsonObjectGotWithAPI['moodleId'],
            'email': jsonObjectGotWithAPI['email'],
            'password': jsonObjectGotWithAPI['password']
        }

        UserTable.insert_one(newUser)
        return make_response({'message': 'Inserted Successfully'}, 201)


# To find the first document that matches a defined query,
# find_one function is used and the query to match is passed
# as an argument.
@app.route('/find-user', methods=['POST'])
def find_user():
    if request.method == 'POST':
        jsonObjectGotWithAPI = request.json
        queryObject = {'moodle_ID': jsonObjectGotWithAPI['moodleId'], 'password': jsonObjectGotWithAPI['password']}
        query = UserTable.find_one(queryObject)
        if query:
            query.pop('_id')
            query.pop('password')
            return jsonify(query), 200
        return make_response({'message': 'User not found!'}, 200)


# To update a document in a collection, update_one()
# function is used. The queryObject to find the document is passed as
# the first argument, the corresponding updateObject is passed as the
# second argument under the '$set' index.
# @app.route('/update/<key>/<value>/<element>/<updateValue>/', methods=['GET'])
# def update(key, value, element, updateValue):
#     queryObject = {key: value}
#     updateObject = {element: updateValue}
#     query = UserTable.update_one(queryObject, {'$set': updateObject})
#     if query.acknowledged:
#         return "Update Successful"
#     else:
#         return "Update Unsuccessful"


if __name__ == '__main__':
    app.run(debug=True)
