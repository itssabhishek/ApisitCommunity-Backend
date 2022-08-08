from flask import Flask, jsonify, request
from flask_cors import CORS
import pymongo

app = Flask(__name__)
CORS(app)
# Replace your URL here. Don't forget to replace the password.
connection_url = 'mongodb+srv://abhay:Abhay%409819@cluster0.6i1t3sc.mongodb.net/test'

client = pymongo.MongoClient(connection_url)

# Database
Database = client.get_database('ApsitDB')
# Table
SampleTable = Database.logininfo


@app.route('/')
def hello_world():
    return "Hi! i am apsit-community's backend"


@app.route('/insert-one/<name>/<moodleId>/<email>/<password>/', methods=['GET'])
def insertOne(name, moodleId, email, password):
    queryObject = {
        'Name': name,
        'ID': moodleId,
        'email': email,
        'password': password
    }
    query = SampleTable.insert_one(queryObject)
    return "Query inserted...!!!"


# To find the first document that matches a defined query,
# find_one function is used and the query to match is passed
# as an argument.
@app.route('/find-one/<moodleId>/<password>/', methods=['GET'])
def findOne(moodleId, password):
    queryObject = {'ID': moodleId, 'password': password}
    query = SampleTable.find_one(queryObject)
    query.pop('_id')
    return jsonify(query)


# To update a document in a collection, update_one()
# function is used. The queryObject to find the document is passed as
# the first argument, the corresponding updateObject is passed as the
# second argument under the '$set' index.
# @app.route('/update/<key>/<value>/<element>/<updateValue>/', methods=['GET'])
# def update(key, value, element, updateValue):
#     queryObject = {key: value}
#     updateObject = {element: updateValue}
#     query = SampleTable.update_one(queryObject, {'$set': updateObject})
#     if query.acknowledged:
#         return "Update Successful"
#     else:
#         return "Update Unsuccessful"


if __name__ == '__main__':
    app.run(debug=True)
