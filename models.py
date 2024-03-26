from mongoengine import (
    Document,
    StringField,
    EmailField,
    DateTimeField,
    BooleanField
)
import datetime


class User(Document):
    username = StringField(required=True, unique=True)
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)
    createdat = DateTimeField(default=datetime.datetime.max)
    updatedat = DateTimeField(default=datetime.datetime.max)
    plan = StringField(default="free")
    verified = BooleanField(default=False)

