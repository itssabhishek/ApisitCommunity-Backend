from flask import Flask, jsonify, request
from flask_cors import CORS
import pymongo
from flask_bcrypt import Bcrypt
import os


app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
# Replace your URL here.
mongo_uri = os.environ.get('connection_url')
client = pymongo.MongoClient(mongo_uri)

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

        moodle_in_db = UserTable.find_one({'moodleId': jsonObjectGotWithAPI['moodleId']})
        email_in_db =  UserTable.find_one({'email': jsonObjectGotWithAPI['email']})
        if moodle_in_db or email_in_db:
            return jsonify({'message': 'User already exists'}), 302
        
        hashed_password = bcrypt.generate_password_hash(jsonObjectGotWithAPI['password'])
        newUser = {
            'name': jsonObjectGotWithAPI['user_name'],
            'moodleId': jsonObjectGotWithAPI['moodleId'],
            'email': jsonObjectGotWithAPI['email'],
            'password': hashed_password
        }

        UserTable.insert_one(newUser)
        return jsonify({'message': 'Inserted Successfully'}), 201


# To find the first document that matches a defined query,
# find_one function is used and the query to match is passed
# as an argument.
@app.route('/find-user', methods=['POST'])
def find_user():
    if request.method == 'POST':
        jsonObjectGotWithAPI = request.json
        user_in_db = UserTable.find_one({'moodleId': jsonObjectGotWithAPI['moodleId']})
        if user_in_db:
            if bcrypt.check_password_hash(user_in_db['password'], jsonObjectGotWithAPI['password']):
                user_in_db.pop('_id')
                user_in_db.pop('password')
                return jsonify(user_in_db), 200
        else: return jsonify({'message': 'User not found!'}), 204
 


if __name__ == '__main__':
    app.run(debug=True)
