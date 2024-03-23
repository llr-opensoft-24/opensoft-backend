from flask import Flask,  jsonify, request
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from flask_bcrypt import Bcrypt
from models import User
import datetime
import arrow
import jwt
import razorpay
import hmac
import hashlib

load_dotenv()
app = Flask(__name__)
bcrypt = Bcrypt(app)

DB_URI = os.getenv('DB_URI')
RAZORPAY_ID = os.getenv('RAZORPAY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET')


try:
    client = MongoClient(DB_URI)
    db = client['sample_mflix']
    print("Connected to MongoDB successfully!")

    # if "user" not in db.list_collection_names():
    #     db.create_collection("user")
    

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


@app.route('/order', methods=['POST'])
def create_razorpay_order():
    response = {}
    response["error"] = None
    response["data"] = {}
    amount = request.args['amount']
    print(amount)
    
    data = {
        "amount": int(amount)*100,
        "currency": "INR",
        "receipt": "receipt#1",
        "notes": {
            "key1": "value3",
            "key2": "value2"
        }
    }

    try:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_ID, RAZORPAY_KEY_SECRET))
        razorpay_response = razorpay_client.order.create(data=data)

        order_id = razorpay_response['id']
        order_status = razorpay_response['status']
        response['data']['order_id'] = order_id
        response['data']['order_status'] = order_status
        response['data']['amount'] = int(amount) * 100
        
        return jsonify(response)
    except Exception as e:
        response['error'] = str(e)
        return response
    
@app.route('/verify', methods=['POST'])
def verify_razorpay_signature():
    response = {}
    response["error"] = None
    response["data"] = {}

    
    try:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_ID, RAZORPAY_KEY_SECRET))

        request_body = request.json
        # print(request_body)
        # print(request_body['razorpay_order_id'])
        # generated_signature = hmac.new(request_body['razorpay_order_id'] + "|" + request_body['razorpay_payment_id'], RAZORPAY_KEY_SECRET, hashlib.sha256).digest()
        # print("hi")
        # if (generated_signature == request_body['razorpay_signature']):
        #     response["data"]["payment_status"] = "verified"
        # print("hi")

        payment_status = razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': request_body["razorpay_order_id"],
            'razorpay_payment_id': request_body["razorpay_payment_id"],
            'razorpay_signature': request_body["razorpay_signature"]
        })
        if payment_status == True:
            response['data']['payment_status'] = True
        else:
            response['data']['payment_status'] = False
        return response
    except Exception as e:
        response['error'] = str(e)
        return response

    


@app.route("/register",methods=["POST"])
def register():
    if request.method == "POST":
        response = {}
        response["error"] = None
        response["results"] = {}
        data = request.get_json()
        print(data)
        hashed_password = bcrypt.generate_password_hash(data["password"]).decode(
            "utf-8"
        )
        data["password"] = hashed_password
        user_collection = db["user"]
        if user_collection.find_one({"email": data["email"]}):
            response["error"]="User already exists!"
            return response
        if user_collection.find_one({"username": data["username"]}):
            response["error"]="Username already taken!"
            return response

        new_user = User(username=data["username"],email=data["email"],password=hashed_password,createdat=datetime.datetime.utcnow(),updatedat=datetime.datetime.utcnow())
        user_collection.insert_one(new_user.to_mongo())

        response["results"] = {"message": "User registered successfully!"}
        return response
    response["error"] = "Wrong request type"
    return response


@app.route("/login", methods=["POST"])
def login():
    response = {"error": None, "results": {}}

    if request.method == "POST":
        data = request.get_json()
        user_collection = db["user"]
        user_data = user_collection.find_one({"email": data["email"]})

        if user_data:
            if bcrypt.check_password_hash(user_data["password"], data["password"]):
                payload = {
                    "user_id": str(user_data["_id"]),
                    "exp": arrow.utcnow().shift(minutes=5).int_timestamp,
                }
                token = jwt.encode(payload, os.getenv("SECRET_KEY"), algorithm="HS256")
                token = str(token)
                del user_data["password"]
                user_data["_id"] = str(user_data["_id"])

                response["results"] = {"user_data": user_data, "token": token}
                return response
            else:
                response["error"] = "Invalid credentials!"
                return response
        else:
            response["error"] = "User not found!"
            return response
    
    response["error"] = "Method not allowed!"
    return response
    


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)

