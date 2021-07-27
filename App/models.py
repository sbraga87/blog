from app import db
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy import DateTime, ForeignKey
import flask_login

class User(flask_login.UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(256), unique=True)
    password = db.Column(db.String(256))
    isAdmin = db.Column(db.Boolean, default=False)

    @staticmethod
    def get_by_name(name):
        user = db.session.query(User).filter(User.name == name).first()
        if user:
            return user
        else:
            return None


