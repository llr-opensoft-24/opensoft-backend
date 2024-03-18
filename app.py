from flask import Flask,  jsonify, request
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

load_dotenv()
app = Flask(__name__)

DB_URI = os.getenv('DB_URI')


try:
    client = MongoClient(DB_URI)
    db = client['sample_mflix']
    print("Connected to MongoDB successfully!")
except ConnectionFailure as e:
    print("Could not connect to MongoDB: %s" % e)


@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/', methods=['GET'])
def hello_world():
    response = {}
    response["error"] = None
    response["results"] = {}
    return response

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)

