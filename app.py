from flask import Flask,  jsonify, request
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from flask_bcrypt import Bcrypt
from models import User, Verification
from flask_mail import Mail, Message
import random, string
import datetime
import arrow
import jwt
load_dotenv()
app = Flask(__name__)
bcrypt = Bcrypt(app)
DB_URI = os.getenv('DB_URI')

try:
    client = MongoClient(DB_URI)
    print("Connected to MongoDB successfully!")
    db = client['sample_mflix']
    
    if "user" not in db.list_collection_names():
        db.create_collection("user")

    if "verification" not in db.list_collection_names():
        db.create_collection("verification")

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
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

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
def hello_world():
    response = {}
    response["error"] = None
    response["results"] = {}
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
        print(data)
        user_data = user_collection.find_one({"email": data["email"]})
        print(user_data)
        if user_data:
            if bcrypt.check_password_hash(user_data["password"], data["password"]):
                if user_data["verified"]:
                    payload = {
                        "user_id": str(user_data["_id"]),
                        "exp": arrow.utcnow().shift(minutes=5).int_timestamp,
                    }
                    print("Payload: ",payload)
                    token = jwt.encode(payload, os.getenv("SECRET_KEY"), algorithm="HS256")
                    token = str(token)
                    del user_data["password"]
                    user_data["_id"] = str(user_data["_id"])

                    response["results"] = {"user_data": user_data, "token": token}
                    return response
                else:
                    otp = generate_otp()
                    print("OTP: ",otp)
                    send_otp_email(data["email"], otp)
                    print("OTP sent successfully! Please verify OTP to complete registration.")
                    ver = Verification(email=data["email"],otp=otp,otptype="email",generationtime=datetime.datetime.utcnow())
                    verification_collection.insert_one(ver.to_mongo())
                    user1 = user_data
                    user1["_id"] = str(user1["_id"])
                    del user1["password"]
                    response["results"]={"message":"OTP sent successfully! Please verify OTP to complete registration.","token":None,"user_data":user1}
                    return response        
            else:
                response["error"] = "Invalid credentials!"
                return response
        else:
            response["error"] = "User not found!"
            return response
    response["error"] = "Method not allowed!"
    return response


@app.route("/verifyemail",methods=["POST"])
def verifyemail():
    response = {"error": None, "results": {}}

    if request.method == "POST":
        data = request.get_json()
        user_collection = db["user"]
        print(data)
        user_data = user_collection.find_one({"email": data["email"]})
        veridata = verification_collection.find_one({"email": data["email"]})
        print(veridata)
        otp_entered = veridata["otp"]

        if user_data:
            if "otp" in data and str(data["otp"]) == str(otp_entered) and veridata["otptype"]=="email" and veridata["generationtime"]>datetime.datetime.utcnow()-datetime.timedelta(minutes=5):
                del veridata["otp"]
                payload = {
                    "user_id": str(user_data["_id"]),
                    "exp": arrow.utcnow().shift(minutes=5).int_timestamp,
                }
                token = jwt.encode(payload, os.getenv("SECRET_KEY"), algorithm="HS256")
                token = str(token)
                user_collection.update_one({"email":data["email"]},{"$set":{"verified":True}})
                user_data["verified"] = True
                del user_data["password"]
                user_data["_id"] = str(user_data["_id"])
                response["results"] = {"user_data": user_data, "token": token}  
                return response
            else:
                print(otp_entered)
                # print(user_data["otp"])
                return "Invalid OTP!", 401
        else:
            return "User not found!", 404
        
        
@app.route("/forgetpassword",methods=["POST"])
def forgetpassword():
    response = {"error": None, "results": {}}

    if request.method == "POST":
        data = request.get_json()
        user_collection = db["user"]
        user_data = user_collection.find_one({"email": data["email"]})

        if user_data:
            otp = generate_otp()
            send_otp_email(data["email"], otp)
            data["otp"] = otp
            ver = Verification(email=data["email"],otp=otp,otptype="password",generationtime=datetime.datetime.utcnow())
            verification_collection.insert_one(ver.to_mongo())
            response["results"] = {"message": "OTP sent successfully! Please verify OTP to reset password."}
            return response
        else:
            response["error"] = "User not found!"
            return response
        
    response["error"] = "Method not allowed!"
    return response

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)

