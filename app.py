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
from functools import wraps
import hashlib

load_dotenv()
app = Flask(__name__)
bcrypt = Bcrypt(app)

DB_URI = os.getenv('DB_URI')
RAZORPAY_ID = os.getenv('RAZORPAY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET')
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")


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


def verify_token(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        response = {}
        response["error"] = None
        response["message"] = ""
        response["data"] = {}
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

        if not token:
            response['message'] = 'Please login to get access'
            response['error'] = 'Token is missing'
            return response, 401
        print(token)
        try:
            decoded_token = jwt.decode(token, verify=True, key=JWT_SECRET_KEY, algorithms=["HS256"])
            user_id = decoded_token['user_id']

        except Exception as e:
            print(str(e))
            response['message'] = "Login session expired"
            response["error"] = "Token is invalid"
            return response, 401

        return func(user_id, *args, **kwargs)

    return decorated_function



@app.route('/', methods=['GET'])
@verify_token
def hello_world(user_id):
    response = {}
    response["error"] = None
    response["data"] = {}
    return response



@app.route('/order', methods=['POST'])
@verify_token
def create_razorpay_order(user_id):
    response = {}
    response["error"] = None
    response["data"] = {}
    amount = request.args['amount']
    print(amount)
    
    rz_data = {
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
        razorpay_response = razorpay_client.order.create(data=rz_data)

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
@verify_token
def verify_razorpay_signature(user_id):
    response = {}
    response["error"] = None
    response["data"] = {}
    response["message"] = ""
    try:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_ID, RAZORPAY_KEY_SECRET))

        request_body = request.json

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
    response = {}
    response["error"] = None
    response["data"] = {}
    response["message"] = ''
    if request.method == "POST":
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

        new_user = User(username=data["username"],email=data["email"],password=hashed_password,createdat=datetime.datetime.utcnow(),updatedat=datetime.datetime.utcnow())
        user_collection.insert_one(new_user.to_mongo())

        response["message"] = "Account created successfully"
        return response
    response["error"] = "Wrong request type"
    return response


@app.route("/login", methods=["POST"])
def login():
    response = {"error": None, "data": {}, "message":""}

    if request.method == "POST":
        data = request.get_json()
        user_collection = db["user"]
        user_data = user_collection.find_one({"email": data["email"]})

        if user_data:
            if bcrypt.check_password_hash(user_data["password"], data["password"]):
                payload = {
                    "user_id": str(user_data["_id"]),
                    "exp": arrow.utcnow().shift(minutes=1440).int_timestamp,
                }
                token = jwt.encode(payload, JWT_SECRET_KEY , algorithm="HS256")
                token = str(token)
                del user_data["password"]
                user_data["_id"] = str(user_data["_id"])

                response["data"] = {"user_data": user_data, "token": token}
                return response
            else:
                response["error"] = "Invalid credentials!"
                response["message"] = "Email / Password is incorrect"
                return response, 401
        else:
            response["error"] = "User not found!"
            response["message"] = "No user exists with given email"
            return response, 404
    
    response["error"] = "Method not allowed!"
    return response
    


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)

