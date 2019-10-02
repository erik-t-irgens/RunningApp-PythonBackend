''' Trivial Eve-SQLAlchemy example. '''
from eve import Eve
from eve.auth import TokenAuth
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import column_property, validates, relationship

from eve_sqlalchemy import SQL
from eve_sqlalchemy.config import DomainConfig, ResourceConfig
from eve_sqlalchemy.validation import ValidatorSQL

import hashlib
import string
import random

from itsdangerous import TimedJSONWebSignatureSerializer \
    as Serializer
from itsdangerous import SignatureExpired, BadSignature

from werkzeug.security import generate_password_hash, \
    check_password_hash


import json
import base64

from flask import request, jsonify
from werkzeug.exceptions import Unauthorized


Base = declarative_base()

SECRET_KEY = 'this-is-my-super-secret-key'

# Not sure if I need this later, it doesn't work right now.
# class Role(Base):
#     __tablename__ = 'role'

#     id = Column(Integer, primary_key=True)
#     admin = 'admin'
#     user = 'user'


def register_views(app):

    @app.route('/login', methods=['POST'])
    def login(**kwargs):
        """Simple login view that expect to have username
        and password in the request POST. If the username and
        password matches - token is being generated and return.
        """
        data = request.get_json()
        login = data.get('username')
        password = data.get('password')

        if not login or not password:
            raise Unauthorized('Wrong username and/or password.')
        else:
            user = app.data.driver.session.query(User).get(login)
            if user and user.check_password(password):
                token = user.generate_auth_token()
                return jsonify({'token': token.decode('ascii')})
        raise Unauthorized('Wrong username and/or password.')


class User(Base):
    __tablename__ = 'users'

    login = Column(String, primary_key=True)
    password = Column(String)
    # Trying to decide how roles even work here.
    # roles = relationship("Role", backref="users")

    def generate_auth_token(self, expiration=24*60*60):
        """Generates token for given expiration
        and user login."""
        s = Serializer(SECRET_KEY, expires_in=expiration)
        return s.dumps({'login': self.login})

    @staticmethod
    def verify_auth_token(token):
        """Verifies token and eventually returns
        user login.
        """
        s = Serializer(SECRET_KEY)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        return data['login']

# Do I need any of this? Is this just related to roles, or authorization in general?
    # def isAuthorized(self, role_names):
    #     """Checks if user is related to given role_names.
    #     """
    #     allowed_roles = set([r.id for r in self.roles])\
    #         .intersection(set(role_names))
    #     return len(allowed_roles) > 0

    def encrypt(self, password):
        """Encrypt password using werkzeug security module.
        """
        return generate_password_hash(password)

    @validates('password')
    def _set_password(self, key, value):
        """Using SQLAlchemy validation makes sure each
        time password is changed it will get encrypted
        before flushing to db.
        """
        return self.encrypt(value)

    def check_password(self, password):
        if not self.password:
            return False
        return check_password_hash(self.password, password)


class TokenAuthenticate(TokenAuth):
    def check_auth(self, token, allowed_roles, resource, method):
        """First we are verifying if the token is valid. Next
        we are checking if user is authorized for given roles.
        """
        login = User.verify_auth_token(token)
        if login and allowed_roles:
            user = app.data.driver.session.query(User).get(login)
            return user.isAuthorized(allowed_roles)
        else:
            return False


class CommonColumns(Base):
    __abstract__ = True
    _created = Column(DateTime, default=func.now())
    _updated = Column(DateTime, default=func.now(), onupdate=func.now())
    _etag = Column(String(40))


class People(Base):
    __tablename__ = 'people'
    id = Column(Integer, primary_key=True, autoincrement=True)
    firstname = Column(String(80))
    lastname = Column(String(120))
    fullname = column_property(firstname + " " + lastname)
    gender = Column(String(10))
    phonenumber = Column(String(12))
    pace = Column(String(5))
    # Current long/lat/alt (assuming alt=0) is a maximum of 24 chars long at .000001 accuracy.
    location = Column(String(24))


class Tracks(Base):
    __tablename__ = 'tracks'
    id = Column(Integer, primary_key=True, autoincrement=True)
    trackname = Column(String(80))
    description = Column(String(800))
    waypoints = Column(String())
    people_id = Column(Integer, ForeignKey('people.id'))


class Events(Base):
    __tablename__ = 'events'
    id = Column(Integer, primary_key=True, autoincrement=True)
    eventname = Column(String(80))
    description = Column(String(800))
    # This will be the creator of the event itself
    people_id = Column(Integer, ForeignKey('people.id'))
    # This will be the track the event utilizes
    tracks_id = Column(Integer, ForeignKey('people.id'))


SETTINGS = {
    'DEBUG': True,
    'SQLALCHEMY_DATABASE_URI': 'sqlite://',
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'DOMAIN': DomainConfig({
        'people': ResourceConfig(People),
        'tracks': ResourceConfig(Tracks),
        'events': ResourceConfig(Events)
    }).render()
}

app = Eve(auth=TokenAuth, settings=SETTINGS, validator=ValidatorSQL, data=SQL)

# bind SQLAlchemy
db = app.data.driver
Base.metadata.bind = db.engine
db.Model = Base
db.create_all()

# Insert some example data in the db
if not db.session.query(People).count():
    db.session.add_all([
        People(firstname=u'George', lastname=u'Washington', gender=u'Male',
               phonenumber=u'123-123-1234', pace=u'480', location=u'-180.000000,-90.000000,0'),
        People(firstname=u'John', lastname=u'Adams'),
        People(firstname=u'Thomas', lastname=u'Jefferson')])
    db.session.commit()

if not db.session.query(Tracks).count():
    db.session.add_all([
        Tracks(trackname=u'Name of locaton', description=u'Washington',
               waypoints=u'test, test, test, test', people_id=1),
        Tracks(trackname=u'Name of locaton', description=u'Adams',
               waypoints=u'test, test, test, test', people_id=2),
        Tracks(trackname=u'Name of locaton', description=u'Jefferson', waypoints=u'test, test, test, test', people_id=3)])
    db.session.commit()

if not db.session.query(Events).count():
    db.session.add_all([
        Events(eventname=u'George', description=u'Washington',
               people_id=1, tracks_id=1),
        Events(eventname=u'John', description=u'Adams',
               people_id=1, tracks_id=2),
        Events(eventname=u'Thomas', description=u'Jefferson', people_id=3, tracks_id=3)])
    db.session.commit()

if not db.session.query(User).count():
    db.session.add_all([
        User(login="test", password='test'),
        User(login='admin', password='admin')])
    db.session.commit()

if __name__ == '__main__':
    register_views(app)
    # using reloader will destroy in-memory sqlite db
    app.run(debug=True, use_reloader=False)
