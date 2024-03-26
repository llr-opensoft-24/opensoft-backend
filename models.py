from mongoengine import (
    Document,
    StringField,
    EmailField,
    DateTimeField,
    BooleanField
)
import datetime


class User(Document):
    email = EmailField(required=True, unique=True)
    username = StringField()
    password = StringField(default="abbadabbajabba")
    createdat = DateTimeField(default=datetime.datetime.max)
    updatedat = DateTimeField(default=datetime.datetime.max)
    plan = StringField(default="free")
    verified = BooleanField(default=False)


class Verification(Document):
    email = EmailField(required=True, unique=True)
    otp = StringField(required=False)
    otptype = StringField(default="")
    generationtime = DateTimeField(default=datetime.datetime.utcnow)

