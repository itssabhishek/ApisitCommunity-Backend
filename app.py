from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import pymongo
import json
import bson
from bson import json_util, ObjectId
from functools import wraps
import jwt
import os
from datetime import datetime, timedelta


# FLASK CONFIG
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
CORS(app)
bcrypt = Bcrypt(app)

# MONGODB CONFIG
mongo_uri = os.environ.get("connection_url")
client = pymongo.MongoClient(mongo_uri)

Database = client.get_database("ApsitDB")

login_info = Database.logininfo
post_info = Database.Postinfo

# defining necessary variables
user_id = ""
token = ""


# ------------------------------- TOOLS -------------------------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        global token
        token = request.args.get("token")

        if not token:
            return jsonify({
                "message": "Authentication Token is missing!",
                "error": "Unauthorized"
            }), 401

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms="HS256")
            current_user = login_info.find_one({
                "moodleId": data["user"]
            })

            if current_user is None:
                return {
                           "message": "Invalid Authentication token!",
                           "data": None,
                           "error": "Unauthorized"
                       }, 401

        except Exception as e:
            return jsonify({
                "message": "Something went wrong",
                "error": str(e)
            }), 500

        return f(current_user, *args, **kwargs)

    return decorated


def jsoner(d):
    return json.loads(json_util.dumps(d))


# ------------------------------- USER API -------------------------------

@app.route("/")
def hello_world():
    return "Hi! I am APSIT - Community's Backend"


# CREATE ACCOUNT
@app.route("/add-user", methods=["POST"])
def add_user():
    global user_id, token
    if request.method == "POST":
        json_object = request.json

        moodle_in_db = login_info.find_one({"moodleId": json_object["moodleId"]})
        email_in_db = login_info.find_one({"email": json_object["email"]})

        if moodle_in_db or email_in_db:
            return jsonify({"message": "User already exists"}), 302

        # making unique user_id for each registration
        user_id = json_object["branch"] + json_object["year"] + str(json_object["rollNumber"]) + json_object["div"]
        # encrypting password for storing in the database
        hashed_password = bcrypt.generate_password_hash(json_object["password"])

        new_user = {
            "firstName": json_object["firstName"],
            "lastName": json_object["lastName"],
            "displayName": json_object["firstName"] + " " + json_object["lastName"],
            "year": json_object["year"],
            "branch": json_object["branch"],
            "div": json_object["div"],
            "rollNumber": json_object["rollNumber"],
            "moodleId": json_object["moodleId"],
            "email": json_object["email"],
            "password": hashed_password,
            "user_id": user_id
        }

        # appending the details in the db
        login_info.insert_one(new_user)

        # creating a jwt token and adding it to the global variable
        token = jwt.encode({
            "user": json_object["moodleId"],
            "exp": datetime.utcnow() + timedelta(hours=2)
        },
            app.config["SECRET_KEY"])

        # sending the relevant information back to the front-end
        new_user.pop("password")

        new_user_json = jsoner(new_user)

        return {"accessToken": token, "user": new_user_json}, 201


# LOG IN
@app.route("/find-user", methods=["POST"])
def find_user():
    global token
    if request.method == "POST":
        json_object = request.json

        user_in_db = login_info.find_one({"moodleId": json_object["moodleId"]})

        if user_in_db:

            if bcrypt.check_password_hash(user_in_db["password"], json_object["password"]):

                # creating a jwt token and adding it to the global variable
                token = jwt.encode({
                    "user": json_object["moodleId"],
                    "exp": datetime.utcnow() + timedelta(hours=2)
                },
                    app.config["SECRET_KEY"])

                user_in_db.pop("password")
                user_in_db = jsoner(user_in_db)

                return jsonify({"accessToken": token, "user": user_in_db}), 200

            else:
                return jsonify({"message": "Invalid password"}), 204
        else:
            return jsonify({"message": "User not found"}), 401


# DELETE
@app.route("/delete-user", methods=["POST"])
@token_required
def delete_user():
    json_object = request.json
    if request.method == "POST":
        if login_info.find_one({"moodleId": json_object["moodleId"]}):
            login_info.delete_one({"moodleId": json_object["moodleId"]})
            return jsonify({"message": "User deleted successfully"}), 200
        else:
            return jsonify({"message": "User does not exist"}), 204


# JWT Authentication
@app.route("/get-user", methods=["GET", "POST"])
@token_required
def get_user(current_user):
    return jsoner(current_user)


# ------------------------------- POST API -------------------------------


# CREATE
@app.route("/create-post", methods=["POST"])
@token_required
def create_post():
    if request.method == "POST":
        new_post = request.json

        post_info.insert_one(new_post)

        new_post_json = jsoner(new_post)

        # storing the received json message in a variable so that the post id can be returned
        post = {"post": new_post_json}
        return {"_id": post["post"]["_id"]["$oid"]}, 201


# READ
@app.route("/posts", methods=["GET"])
@token_required
def get_posts():
    if request.method == "GET":
        posts = post_info.find().sort("createdAt", pymongo.DESCENDING)
        posts_json = jsoner(posts)
        return {"posts": posts_json}, 200


# READ SPECIFIC POST
@app.route("/post", methods=["GET"])
@token_required
def post_by_id():
    if request.method == "GET":
        post_id = request.args.get('id')
        post = post_info.find_one({"_id": ObjectId(post_id)})

        post_json = jsoner(post)
        return {"post": post_json}, 200


@app.route("/edit-post", methods=["POST"])
@token_required
def edit_post():
    json_object = request.json

    if request.method == "POST":
        post_id = json_object["id"]

        if post_info.find_one(ObjectId(post_id)):

            edited_post = {
                "title": json_object["title"],
                "description": json_object["description"],
                "content": json_object["content"],
                "cover": json_object["cover"],
                "tags": json_object["tags"],
                "publish": json_object["publish"],
                "comments": json_object["comments"],
                "metaTitle": json_object["metaTitle"],
                "metaDescription": json_object["metaDescription"],
                "metaKeywords": json_object["metaKeywords"]
            }
            post_info.update_one({"_id": bson.ObjectId(post_id)}, {"$set": edited_post}, upsert=False)

            return jsonify({"message": "Post updated successfully"}), 200
        else:
            return jsonify({"message": "Post does not exist"}), 201


@app.route("/delete-post", methods=["POST"])
@token_required
def delete_post():
    json_object = request.json

    if request.method == "POST":
        post_id = json_object["id"]
        post_to_delete = post_info.find_one(ObjectId(post_id))
        if post_to_delete:
            post_info.delete_one(post_to_delete)
            return jsonify({"message": "Post deleted successfully"}), 200
        else:
            return jsonify({"message": "Post does not exist"}), 201


if __name__ == "__main__":
    app.run(debug=True)
