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
from models import User, Verification, Payments
from flask_mail import Mail, Message
import random, string
from bson import ObjectId

load_dotenv()
app = Flask(__name__)
bcrypt = Bcrypt(app)

DB_URI = os.getenv('DB_URI')
RAZORPAY_ID = os.getenv('RAZORPAY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET')
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
DB_NAME = os.getenv("DB_NAME")
MOVIES_COLLECTION_NAME = os.getenv("MOVIES_COLLECTION_NAME")
AUTO_COMPLETE_INDEX_NAME = os.getenv("AUTO_COMPLETE_INDEX_NAME")

try:
    client = MongoClient(DB_URI)
    db = client['sample_mflix']
    print("Connected to MongoDB successfully!")

    if "user" not in db.list_collection_names():
        db.create_collection("user")

    if "verification" not in db.list_collection_names():
        db.create_collection("verification")
    
    if "payments" not in db.list_collection_names():
        db.create_collection("payments")

    user_collection = db["user"]
    verification_collection = db["verification"]
    app.config["MAIL_SERVER"] = "smtp.gmail.com"
    app.config["MAIL_PORT"] = 465
    app.config["MAIL_USE_TLS"] = False
    app.config["MAIL_USE_SSL"] = True
    app.config["MAIL_USERNAME"] = os.getenv("GMAIL_USERNAME")
    app.config["MAIL_PASSWORD"] = os.getenv("GMAIL_APP_PASSWORD")
    mail = Mail(app)
    

except ConnectionFailure as e:
    print("Could not connect to MongoDB: %s" % e)




@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
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


def generate_otp():
    otp = "".join(random.choices(string.digits, k=6))
    print(otp)
    return otp


def send_otp_email(email, otp):
    msg = Message(
        "OTP for registration",
        sender=os.getenv("GMAIL_USERNAME"),
        recipients=[email],
    )
    msg.body = f"Your OTP for registration is {otp}"
    mail.send(msg)


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
    response["message"] = ""
    
    try:

        amount = request.args['amount']
        plan = request.args['plan']
        amount_in_paise = int(amount) * 100

        if plan == "pro" and amount == "299":
            rz_data = {
                "amount": int(amount)*100,
                "currency": "INR",
                "receipt": f"receipt_{user_id}",
                "notes": {
                    "plan ": "pro"
                }
            }
        elif plan == "premium" and amount == "499":
            rz_data = {
                "amount": amount_in_paise,
                "currency": "INR",
                "receipt": f"receipt_{user_id}",
                "notes": {
                    "plan ": "premium"
                }
            }
        else :
            response["error"] = "Plans and amount dont match"
            response["message"] = "please try again later"
            return response

        user_collection = db["user"]
        user_data = user_collection.find_one({"_id":ObjectId(user_id)})
        payments_collection = db["payments"]
        
        if user_data is None:
            response["error"] = "No user exists"
            response["message"] = "No user exists"

        razorpay_client = razorpay.Client(auth=(RAZORPAY_ID, RAZORPAY_KEY_SECRET))
        razorpay_response = razorpay_client.order.create(data=rz_data)
        order_status = razorpay_response['status']

        if order_status =="created":
            response["message"] = "Order created"

            order_id = razorpay_response['id']
            payment = Payments(email = user_data["email"], amount = amount_in_paise, razorpay_order_id = order_id, status = "created", creation_time = datetime.datetime.utcnow(), plan = plan)

            payments_collection.insert_one(payment.to_mongo())
            response['data']['order_id'] = order_id
            response['data']['order_status'] = order_status
            response['data']['amount'] = int(amount)
        else:
            response["message"] = "Couldnt create order"
            response["error"] = "Couldnt create order"
        return response
    except Exception as e:
        response['error'] = str(e)
        response["message"] = "Error creating order"
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

        user_collection = db["user"]
        payments_collection = db["payments"]

        user_data = user_collection.find_one({"_id": ObjectId(user_id)})
        if user_data is None:
            response['error'] = "No user exists"
            response['message'] = "No user exists"


        verification_status = razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': request_body["razorpay_order_id"],
            'razorpay_payment_id': request_body["razorpay_payment_id"],
            'razorpay_signature': request_body["razorpay_signature"]
        })
        if verification_status == True:
            payment_data = payments_collection.find_one({"razorpay_order_id":request_body["razorpay_order_id"]})
            if payment_data['email'] == user_data['email'] and payment_data['status'] == 'created':
                payment = Payments(razorpay_order_id = request_body['razorpay_order_id'], status = "verified", payment_time = datetime.datetime.utcnow())
                payments_collection.update_one({"razorpay_order_id":request_body["razorpay_order_id"]}, {"$set": payment.to_mongo()})
                response["message"] = "Payment Verified"
                user_collection.update_one({"email":user_data['email']},{"$set":{"plan":payment_data['plan'], "subscription_end_date":datetime.datetime.utcnow()+datetime.timedelta(days=30)}})
                response['data']['verification_status'] = True
            else:
                response["error"] = "Couldnt verify details"
                response["message"] = "Couldnt verify details"
        else:
            response['data']['payment_status'] = False
            response["error"] = "Couldnt verify payment details"
            response["message"] = "Couldnt verify payment details"
        return response
    except Exception as e:
        response['error'] = str(e)
        response["message"] = "Error verifying payment details"
        return response

    


@app.route("/register",methods=["POST"])
def register():
    response = {}
    response["error"] = None
    response["data"] = {}
    response["message"] = ''

    try: 
        data = request.get_json()

        hashed_password = bcrypt.generate_password_hash(data["password"]).decode(
            "utf-8"
        )
        data["password"] = hashed_password
        user_collection = db["user"]
        if user_collection.find_one({"email": data["email"]}):
            response["error"]="User already exists!"
            response["message"] = "User already exists!"
            return response

        new_user = User(username=data["username"],email=data["email"],password=hashed_password,createdat=datetime.datetime.utcnow(),updatedat=datetime.datetime.utcnow())
        user_collection.insert_one(new_user.to_mongo())

        response["message"] = "Account created successfully"
        return response
    except Exception as e:
        response["error"] = str(e)
        response["message"] = "Something went wrong"
    return response


@app.route("/login", methods=["POST"])
def login():
    response = {}
    response["error"] = None
    response["data"] = {}
    response["message"] = ''

    try:
        data = request.get_json()
        user_collection = db["user"]
        user_data = user_collection.find_one({"email": data["email"]})

        if user_data:
            if bcrypt.check_password_hash(user_data["password"], data["password"]):
                if user_data["verified"]:
                    payload = {
                        "user_id": str(user_data["_id"]),
                        "exp": arrow.utcnow().shift(minutes=1440).int_timestamp,
                    }
                    print("Payload: ",payload)
                    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
                    token = str(token)
                    del user_data["password"]
                    user_data["_id"] = str(user_data["_id"])

                    response["data"] = {"user_data": user_data, "token": token}
                    response["message"] = "Login Successful"
                    return response
                else:
                    otp = generate_otp()
                    print("OTP: ",otp)
                    send_otp_email(data["email"], otp)
                    print("OTP sent successfully! Please verify OTP to complete registration.")
                    ver = Verification(email=data["email"],otp=otp,otptype="email",generationtime=datetime.datetime.utcnow())
                    verification_collection.update_one({"email": data["email"], "otptype": "email"}, {"$set": ver.to_mongo()}, upsert=True)
                    user1 = user_data
                    user1["_id"] = str(user1["_id"])
                    del user1["password"]
                    response["data"]={"token":None,"user_data":user1}
                    response["message"] ="OTP sent successfully! Please verify OTP to complete registration."
                    return response   
            else:
                response["error"] = "Invalid credentials"
                response["message"] = "Invalid credentials"
                return response, 401
        else:
            response["error"] = "User not found"
            response["message"] = "No user exists with given email"
            return response, 404
    except Exception as e:
        response["error"] = str(e)
        response["message"] = "Unable to Login"
    return response
    

@app.route("/verifyemail",methods=["POST"])
def verifyemail():
    response = {}
    response["error"] = None
    response["data"] = {}
    response["message"] = ''

    try:
        data = request.get_json()
        user_collection = db["user"]
        print(data)
        user_data = user_collection.find_one({"email": data["email"]})
        type = data["type"]
        veridata = verification_collection.find_one({"email": data["email"], "otptype": str(type)})
        print(veridata)
        otp_entered = veridata["otp"]

        if user_data:
            if "otp" in data and str(data["otp"]) == str(otp_entered) and veridata["otptype"]=="email" and veridata["generationtime"]>datetime.datetime.utcnow()-datetime.timedelta(minutes=5):
                del veridata["otp"]
                payload = {
                    "user_id": str(user_data["_id"]),
                    "exp": arrow.utcnow().shift(minutes=1440).int_timestamp,
                }
                token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
                token = str(token)
                user_collection.update_one({"email":data["email"]},{"$set":{"verified":True}})
                user_data["verified"] = True
                del user_data["password"]
                user_data["_id"] = str(user_data["_id"])
                response["data"] = {"user_data": user_data, "token": token}  
                response["message"] = "OTP verified"
                return response
            else:
                print(otp_entered)
                # print(user_data["otp"])
                response["message"] = "Entered OTP is invalid"
                response["error"] = "Entered OTP is invalid"
                return response, 401
        else:
            response["message"] = "No such user found"
            response["error"] = "User not found"
            return response, 404
    except Exception as e:
        response["error"] = str(e)
        response["message"] = "Unable to verify email"
        return response


@app.route("/forgetpassword",methods=["POST"])
def forgetpassword():
    response = {}
    response["error"] = None
    response["data"] = {}
    response["message"] = ''

    try:
        data = request.get_json()
        user_collection = db["user"]
        user_data = user_collection.find_one({"email": data["email"]})

        if user_data:
            otp = generate_otp()
            send_otp_email(data["email"], otp)
            data["otp"] = otp
            ver = Verification(email=data["email"],otp=otp,otptype="password",generationtime=datetime.datetime.utcnow())
            verification_collection.update_one({"email": data["email"], "otptype": "password"}, {"$set": ver.to_mongo()}, upsert=True)
            response["data"] = {"message": "OTP sent successfully! Please verify OTP to reset password."}
            return response
        else:
            response["error"] = "User not found!"
            return response
    except Exception as e:
        response["error"] = str(e)
        response["message"] = "Unable to change password"
    return response


@app.route("/search")
@verify_token
def search_movies(user_id):
    response = {}
    response["error"] = None
    response["data"] = {}
    response["message"] = ''
    try:
        query = request.args.get("q")
        pipeline =[
            {
                '$search': {
                    'index': AUTO_COMPLETE_INDEX_NAME,
                    'autocomplete': {
                                'query': query, 
                                'path': 'title',
                                'tokenOrder': 'any',
                                'fuzzy': {
                                    'maxEdits': 2,
                                    'prefixLength': 3
                                }
                            }
                    }
                },
            {
                '$limit': 10000
            },
            {
                '$project': {
                    '_id': 0, 
                    'title': 1, 
                    'plot': 1, 
                    'cast': 1,
                    'genres': 1,
                    'runtime': 1,
                    'rated': 1,
                    'cast': 1,
                    'poster': 1,
                    'fullplot': 1,
                    'languages': 1,
                    'released': 1,
                    'directors': 1,
                    'writer' : 1,
                    'awards': 1,
                    'year': 1,
                    'imdb': 1,
                    'countries': 1,
                    'type': 1,
                    'lastupdated': 1,
                    'score' : {"$meta": "searchScore"}
                }
            }
        ]
        query_db_result = client[DB_NAME][MOVIES_COLLECTION_NAME].aggregate(pipeline)
        movies_data = []
        for movie in query_db_result:
            print(movie['title'])
            movies_data.append(movie)
        response["data"]= movies_data
    except Exception as e:
        response["error"] = str(e)
        response["message"] = "Search is not working"
        return response
    return response

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080,debug=True)

