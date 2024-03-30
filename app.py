from flask import Flask,  jsonify, request, Response
import os
from dotenv import load_dotenv
from pymongo import MongoClient, DESCENDING
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
from gridfs import GridFS, GridFSBucket
from sentence_transformers import SentenceTransformer,util


load_dotenv()
app = Flask(__name__)
bcrypt = Bcrypt(app)

DB_URI = os.getenv('DB_URI')
VIDEOS_DB_URI = os.getenv('VIDEOS_DB_URI')
RAZORPAY_ID = os.getenv('RAZORPAY_ID')
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET')
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
DB_NAME = os.getenv("DB_NAME")
MOVIES_COLLECTION_NAME = os.getenv("MOVIES_COLLECTION_NAME")
AUTO_COMPLETE_INDEX_NAME = os.getenv("AUTO_COMPLETE_INDEX_NAME")
VECTOR_SEARCH_INDEX_NAME = os.getenv("VECTOR_SEARCH_INDEX_NAME")


try:
    client = MongoClient(DB_URI)
    videos_client = MongoClient(VIDEOS_DB_URI)
    db = client['sample_mflix']
    videos_db = videos_client['sample_mflix']
    # grid_fs = GridFS(videos_db, collection="video_files")
    grid_fs_bucket = GridFSBucket(videos_db, bucket_name="video_files")
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


model = SentenceTransformer("all-mpnet-base-v2")
def get_embedding(text):    
    return (model.encode(text,convert_to_tensor=False)).tolist()

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
            return response
        if user_data['plan'] != 'free' and user_data['subscription_end_date'] > (int)(datetime.datetime.utcnow().timestamp()):
            response['error'] = "Subscription Already active"
            response['message'] = "Subscription Already active"
            return response

        print(RAZORPAY_ID, RAZORPAY_KEY_SECRET)
        razorpay_client = razorpay.Client(auth=(RAZORPAY_ID, RAZORPAY_KEY_SECRET))
        razorpay_response = razorpay_client.order.create(data=rz_data)
        order_status = razorpay_response['status']

        if order_status =="created":
            response["message"] = "Order created"
            order_id = razorpay_response['id']
            payment = Payments(email = user_data["email"], amount = amount_in_paise, razorpay_order_id = order_id, status = "created", creation_time = (int)(datetime.datetime.utcnow().timestamp()), plan = plan)
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
        response["time"] = (int)(datetime.datetime.utcnow().timestamp())
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
                payment = Payments(razorpay_order_id = request_body['razorpay_order_id'], status = "verified", payment_time = (int)(datetime.datetime.utcnow().timestamp()))
                payments_collection.update_one({"razorpay_order_id":request_body["razorpay_order_id"]}, {"$set": payment.to_mongo()})
                response["message"] = "Payment Verified"
                user_collection.update_one({"email":user_data['email']},{"$set":{"plan":payment_data['plan'], "subscription_end_date":(int)(datetime.datetime.utcnow().timestamp())+datetime.timedelta(days=30).total_seconds()}})
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

        new_user = User(username=data["username"],email=data["email"],password=hashed_password,createdat=(int)(datetime.datetime.utcnow().timestamp()),updatedat=(int)(datetime.datetime.utcnow().timestamp()))
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
                    ver = Verification(email=data["email"], otp=otp, otptype="email", generationtime=int(datetime.datetime.utcnow().timestamp()))
                    # Update operation with explicit generationtime field
                    verification_collection.update_one(
                        {"email": data["email"], "otptype": "email"},
                        {"$set": {"otp": otp, "generationtime": ver.generationtime}},
                        upsert=True
                    )
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
            print("User found")
            print(veridata["generationtime"])
            print((int)(datetime.datetime.utcnow().timestamp())-datetime.timedelta(minutes=5).total_seconds())
            if "otp" in data and str(data["otp"]) == str(otp_entered) and veridata["generationtime"]>(int)(datetime.datetime.utcnow().timestamp())-datetime.timedelta(minutes=5).total_seconds():
                print("OTP verified")
                del veridata["otp"]
                if type == "email":
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
                else:
                    response["message"] = "OTP verified"
                return response
            else:
                print(otp_entered)
                print(data["otp"])
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


@app.route("/forgotpassword",methods=["POST"])
def forgotpassword():
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
            ver = Verification(email=data["email"],otp=otp,otptype="password",generationtime=(int)(datetime.datetime.utcnow().timestamp()))
            verification_collection.update_one({"email": data["email"], "otptype": "password"}, {"$set": {"otp": otp, "generationtime": ver.generationtime}}, upsert=True)
            response["message"] = "OTP sent successfully! Please verify OTP to reset password."
            return response
        else:
            response["error"] = "User not found!"
            response["message"] = "User not found!"
            return response
    except Exception as e:
        response["error"] = str(e)
        response["message"] = "Unable to change password"
    return response

@app.route("/resetpassword",methods=["POST"])
def resetpassword():

    response = {}
    response["error"] = None
    response["data"] = {}
    response["message"] = ''
    try:
        if request.method == "POST":
            data = request.get_json()
            user_collection = db["user"]
            user_data = user_collection.find_one({"email": data["email"]})
            newpassword = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
            if user_data:
                user_collection.update_one({"email": data["email"]}, {"$set": {"password": newpassword,"updatedat": (int)(datetime.datetime.utcnow().timestamp())}})
                response["message"] = "Password reset successfully"
                return response
            else:
                response["error"] = "User not found!"
                return response
        else:
            response["error"] = "Invalid request"
            return response
    except Exception as e:
        response["error"] = str(e)
        response["message"] = "Unable to reset password"
    return response

@app.route("/search", methods=["GET"])
@verify_token
def search_movies(user_id):
    response = {}
    response["error"] = None
    response["data"] = {}
    response["message"] = ''
    try:
        movies_collection = db['movies']
        embedded_movies_collection = db['embedded_movies']
        query = request.args.get('q')
        query_vector = get_embedding(query)
    
        autocomplete_result = movies_collection.aggregate([
            {
                '$search': {
                    'index': AUTO_COMPLETE_INDEX_NAME,
                    'compound': {
                        'should': [
                            {
                                'autocomplete': {
                                    'query': query, 
                                    'path': 'title',
                                    'tokenOrder': 'sequential',
                                    'fuzzy': {
                                        'maxEdits': 1, 
                                        'prefixLength': 2
                                    }
                                }
                            }
                        ], 
                        'minimumShouldMatch': 1
                    }
                }
            }, 
            {
                '$limit': 200
            }, 
            {
                '$project': {
                    '_id': 0, 'title': 1, 'plot': 1,
                    'tomatoes.viewer.numReviews': 1,
                    'score': {
                        '$meta': 'searchScore'
                    }
                }
            }
        ])
        
        vector_result = embedded_movies_collection.aggregate([
          {
            '$vectorSearch': {
              'index': VECTOR_SEARCH_INDEX_NAME, 
              'path': 'SBERT_embeddings',
              'queryVector': query_vector,
              'numCandidates': 150, 
              'limit': 20
            }
          },
          {
            '$project': {
                    '_id': 0, 'title': 1, 'plot': 1,
                    'tomatoes.viewer.numReviews': 1,
                    'score': {
                        '$meta': 'vectorSearchScore'
                    }
                }
            }
          
        ])
        autocomplete_result = list(autocomplete_result)
        vector_result = list(vector_result)
        combined_result = vector_result + autocomplete_result
        def num_reviews_key(movie):
            if "tomatoes" in movie and movie["tomatoes"] is not None and "viewer" in movie["tomatoes"] and movie["tomatoes"]["viewer"] is not None and "numReviews" in movie["tomatoes"]["viewer"] and movie["tomatoes"]["viewer"]["numReviews"] is not None:
                x = int(movie["tomatoes"]["viewer"]["numReviews"])
            else:
                x = 0
            return x
        combined_result.sort(key=num_reviews_key)
        titles_added = []
        results_titles = []
        combined_result.reverse()
        for movie in combined_result:
            if movie['title'] not in titles_added: 
                titles_added.append(movie['title'])
                results_titles.append({"title":movie['title'],"score":movie["score"]})
            if(len(results_titles) == 10):
                break
        results_titles = sorted(results_titles, key=lambda x: x['score'])
        results_titles.reverse()
    
        for i in results_titles:
            print(i["title"]," ",i["score"])
        results = []
        projection =  {"plot_embedding": 0, "tomatoes": 0, "_id":0}
        for movie in results_titles:
            results.append(movies_collection.find_one({"title": movie["title"]},projection))
        response["data"]= results

    except Exception as e:
        response["error"] = str(e)
        response["message"] = "Search is not working"
        return response
    return response


@app.route('/movies', methods=["GET"])
@verify_token
def get_movies_home(user_id):
    response = {}
    response["error"] = None
    response["data"] = {}
    response["message"] = ''
    try:
        movies_collection = db[MOVIES_COLLECTION_NAME]
        movies_data = []
        comedy_movies = movies_collection.find({"genres.0":"Comedy", "imdb.rating": {"$ne": ''},"poster": {"$exists": True}}).sort('imdb.rating', DESCENDING).limit(20)
        action_movies = movies_collection.find({"genres.0":"Action", "imdb.rating": {"$ne": ''},"poster": {"$exists": True}}).sort('imdb.rating', DESCENDING).limit(20)
        drama_movies = movies_collection.find({"genres.0":"Drama", "imdb.rating": {"$ne": ''},"poster": {"$exists": True}}).sort('imdb.rating', DESCENDING).limit(20)


        for document in comedy_movies:
            for key, value in document.items():
                if isinstance(value, ObjectId):
                    document[key] = str(value)
            movies_data.append(document)
        for document in action_movies:
            for key, value in document.items():
                if isinstance(value, ObjectId):
                    document[key] = str(value)
            movies_data.append(document)
        for document in drama_movies:
            for key, value in document.items():
                if isinstance(value, ObjectId):
                    document[key] = str(value)
            movies_data.append(document)
        
        response["data"] = movies_data
    except Exception as e:
        response["error"] = str(e)
        response["message"] = "Functionality is not working"
        return response
    return response


@app.route("/video", methods=["GET"])
def mongo_video():
    try:
        auth_token = request.args['token']
        filename = request.args['filename']
        print(auth_token)
        if auth_token is None:
            print("hiii")
            return Response("", status=401)
        if filename is None:
            return Response("Requires filename param", status = 400)
        

        decoded_token = jwt.decode(auth_token, verify=True, key=JWT_SECRET_KEY, algorithms=["HS256"])
        user_id = decoded_token['user_id']

        user_collection = db['user']
        user_data = user_collection.find_one({"_id":ObjectId(user_id)})


        user_plan = user_data['plan']
        print(filename)
        requested_video_plan = filename.split("_")[0]
        requested_resolution = filename.split('_')[1].split('.')[0]
        permission_allowed = False


        if user_plan == 'free' and requested_video_plan == 'free' and (requested_resolution in ['360p', '480p', '720p']):
            permission_allowed = True
        if user_plan == 'pro' and requested_video_plan in ['free', 'pro'] and (requested_resolution in ['360p', '480p', '720p', '1080p']):
            permission_allowed = True
        if user_plan == 'premium':
            permission_allowed = True

        
        if permission_allowed == False:
            return Response("Doesn't have access to requested content", 401)

        filename = request.args['filename']
        range_header = request.headers.get('Range')
        if not range_header:
            return Response("Requires Range header", status=400)


        file  = videos_db['video_files.files'].find_one({"filename":filename})
        if file is None:
            return "no video found", 404

        video_size = file['length']
        start = range_header.split("=")[1].split("-")[0]
        start = int(start)
        
        if start == 0:
            end = min(start + 10240, video_size - 1)
        else:
            end = video_size - 1
        
        # end = video_size -1
        content_length = int(end) - int(start) + 1

        headers = {
            "Content-Range": f"bytes {start}-{end}/{video_size}",
            "Accept-Ranges": "bytes",
            "Content-Length": content_length,
            "Content-Type": "video/mp4",
        }

        grid_out = grid_fs_bucket.open_download_stream_by_name(filename=filename)
        grid_fs_seek = grid_out.seek(int(start), 0)


        return Response(grid_out, status=206, headers=headers, mimetype='video/mp4')
    except Exception as e:
        return Response("Something went wrong", status=404)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000,debug=True)

