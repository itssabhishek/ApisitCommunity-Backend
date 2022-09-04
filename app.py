from flask import Flask, jsonify, request
from flask_cors import CORS
import pymongo
from flask_bcrypt import Bcrypt
import datetime
import pytz
import os
from PIL import Image
import io
import json
from bson import ObjectId

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
# Replace your URL here.
mongo_uri = os.environ.get('connection_url')
client = pymongo.MongoClient(mongo_uri)

# Database
Database = client.get_database('ApsitDB')
# Table
login_info = Database.logininfo
create_post = Database.Postinfo

user_id = ""


# used for solving the JSON error in add-user
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


@app.route('/')
def hello_world():
    return "Hi! I am APSIT - Community's backend"


dict_for_frontend = {}


@app.route('/add-user', methods=['POST'])
def add_user():
    global dict_for_frontend
    global user_id
    if request.method == 'POST':
        json_object = request.json

        moodle_in_db = login_info.find_one({'moodleId': json_object['moodleId']})
        email_in_db = login_info.find_one({'email': json_object['email']})

        if moodle_in_db or email_in_db:
            return jsonify({'message': 'User already exists'}), 302

        user_id = json_object['branch'] + json_object['year'] + json_object[
            'roll'] + json_object['div']
        hashed_password = bcrypt.generate_password_hash(json_object['password'])

        new_user = {

            'firstName': json_object['firstName'],
            'lastName': json_object['lastName'],
            'year': json_object['year'],
            'branch': json_object['branch'],
            'div': json_object['div'],
            'rollNumber': json_object['roll'],
            'moodleId': json_object['moodleId'],
            'email': json_object['email'],
            'password': hashed_password,
            'user_id': user_id

        }

        login_info.insert_one(new_user)

        new_user.pop('password')
        dict_for_frontend = new_user

        new_user_json = JSONEncoder().encode(dict_for_frontend)

        return new_user_json, 201


# To find the first document that matches a defined query,
# find_one function is used and the query to match is passed
# as an argument.
@app.route('/find-user', methods=['POST'])
def find_user():
    if request.method == 'POST':
        json_object = request.json
        user_in_db = login_info.find_one({'moodleId': json_object['moodleId']})
        if user_in_db:
            if bcrypt.check_password_hash(user_in_db['password'], json_object['password']):
                user_in_db.pop('_id')
                user_in_db.pop('password')
                return jsonify(user_in_db), 200
        else:
            return jsonify({'message': 'User not found!'}), 204


# This is post Section:

@app.route('/create-post', methods=['POST'])
def create_post():
    if request.method == 'POST':
        json_object = request.json
        # to add time:
        current_time = datetime.datetime.now(pytz.timezone('Asia/Kolkata'))
        # to add image:
        image_from_frontend = json_object['image']
        im = Image.open(image_from_frontend)
        image_bytes = io.BytesIO()
        im.save(image_bytes, format='JPEG')
        image = {
            'data': image_bytes.getvalue()
        }
        # creating a post:
        new_post = {
            'post_content': json_object['post_content'],
            'userId': json_object[user_id],
            'datetime': current_time,
            'image': image
        }

        create_post.insert_one(new_post)
        return jsonify({'message': 'Inserted Successfully'}), 201


if __name__ == '__main__':
    app.run(debug=True)
