from mongoengine import (
    Document,
    StringField,
    EmailField,
    DateTimeField,
    BooleanField,
    FloatField
)
import datetime


class User(Document):
    username = StringField()
    email = EmailField(required=True, unique=True)
    password = StringField(default="")
    createdat = DateTimeField(default=datetime.datetime.max)
    updatedat = DateTimeField(default=datetime.datetime.max)
    plan = StringField(default="free")
    subscription_end_date = DateTimeField()
    verified = BooleanField(default=False)


class Verification(Document):
    email = EmailField(required=True, unique=True)
    otp = StringField(required=False)
    otptype = StringField(default="")
    generationtime = DateTimeField(default=datetime.datetime.utcnow)

class Payments(Document):
    email = EmailField(required=True)
    amount = FloatField(required = True)
    razorpay_order_id = StringField(required = True, unique = True)
    status = StringField(required = True)
    plan = StringField(required = True)
    creation_time = DateTimeField(default=datetime.datetime.utcnow)
    payment_time = DateTimeField()