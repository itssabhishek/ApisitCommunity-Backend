from flask import Flask, jsonify, request
import jwt
from functools import wraps
from flask_cors import CORS
import pymongo
from flask_bcrypt import Bcrypt
import datetime
import pytz
import os
from PIL import Image
import io
import json
from bson import json_util

# Setting up flask app and the database
app = Flask(__name__)
CORS(app)  # for sharing API across other platforms
bcrypt = Bcrypt(app)  # for encrypting the password
mongo_uri = os.environ.get("connection_url")
client = pymongo.MongoClient(mongo_uri)

# Database
Database = client.get_database("ApsitDB")
# Tables
login_info = Database.logininfo
create_post = Database.Postinfo

# --------------------------------------jwt implementation-----------------------------
# configuration:
app.config["SECRET_KEY"] = 'thisisthesecretkey'
# decorator:
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        if not token:
            return jsonify({"message": "token is missing!"}),403

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])
        except:
            return jsonify({"message": "token is invaid"}),403
        
        return f(*args, **kwargs)
    return decorated




@app.route("/")
def hello_world():
    return "Hi! I am APSIT - Community's Backend"

# -----------------------------USER----------------------------------

user_id = ""

# user signup:
@app.route("/add-user", methods=["POST"])
def add_user():
    global user_id
    if request.method == "POST":
        json_object = request.json

        moodle_in_db = login_info.find_one(
            {"moodleId": json_object["moodleId"]})
        email_in_db = login_info.find_one({"email": json_object["email"]})

        if moodle_in_db or email_in_db:
            return jsonify({"message": "User already exists"}), 302

        user_id = json_object["branch"] + json_object["year"] + json_object[
            "roll"] + json_object["div"]
        hashed_password = bcrypt.generate_password_hash(
            json_object["password"])

        new_user = {
            "firstName": json_object["firstName"],
            "lastName": json_object["lastName"],
            "displayName":
            json_object["firstName"] + " " + json_object["lastName"],
            "year": json_object["year"],
            "branch": json_object["branch"],
            "div": json_object["div"],
            "rollNumber": json_object["roll"],
            "moodleId": json_object["moodleId"],
            "email": json_object["email"],
            "password": hashed_password,
            "user_id": user_id
        }

        login_info.insert_one(new_user)
        new_user.pop("password")

        new_user_json = json.loads(json_util.dumps(new_user))
        return jsonify(new_user_json), 201


# user delete:
@app.route("/delete-user", methods=["POST"])
@token_required
def delete_user():
    if request.method == "POST":
        json_object = request.json

        if login_info.find_one({"moodleId": json_object["moodleId"]}):
            login_info.delete_one({"moodleId": json_object["moodleId"]})
            return jsonify({"message": "User deleted successfully"}), 200
        else:
            return jsonify({"message": "User does not exist"}), 404


# user login:
@app.route("/find-user", methods=["POST"])
def find_user():
    if request.method == "POST":
        json_object = request.json
        user_in_db = login_info.find_one({"moodleId": json_object["moodleId"]})
        if user_in_db:
            if bcrypt.check_password_hash(user_in_db["password"],json_object["password"]):
                token = jwt.encode({
                    "user": json_object["moodleId"],
                    "exp": datetime.datetime.now(pytz.timezone("Asia/Kolkata"))+datetime.timedelta(minutes=30)},
                    app.config["SECRET_KEY"]) 
                return jsonify({"token": token}), 200
            else:
                return jsonify({"message": "invalid password!"}),400
        else:
            return jsonify({"message": "coud not  verify!"}), 400

# ------------------------------------POST-----------------------------------------
          
# post create:
@app.route("/create-post", methods=["POST"])
@token_required
def create_post():
    if request.method == "POST":
        json_object = request.json

        # to add time:
        current_time = datetime.datetime.now(pytz.timezone("Asia/Kolkata"))

        # to add image:
        image_from_frontend = json_object["image"]
        im = Image.open(image_from_frontend)
        image_bytes = io.BytesIO()
        im.save(image_bytes, format="JPEG")
        image = {"data": image_bytes.getvalue()}

        new_post = {
            "post_name": json_object["post_name"],
            "post_content": json_object["post_content"],
            "userId": json_object["user_id"],
            "datetime": current_time,
            "image": image
        }

        create_post.insert_one(new_post)
        return jsonify({"message": "post inserted successfully"}), 201


# post update:
# @app.route("/update-post", methods=["POST"])


# post delete:
# @app.route("/delete-post", methods=["DELETE"])







# to run flask app:
if __name__ == "__main__":
    app.run(debug=True)






