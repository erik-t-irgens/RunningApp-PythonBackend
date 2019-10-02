''' Trivial Eve-SQLAlchemy example. '''
from eve import Eve
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import column_property

from eve_sqlalchemy import SQL
from eve_sqlalchemy.config import DomainConfig, ResourceConfig
from eve_sqlalchemy.validation import ValidatorSQL

Base = declarative_base()


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

app = Eve(auth=None, settings=SETTINGS, validator=ValidatorSQL, data=SQL)

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
        People(firstname=u'George', lastname=u'Washington'),
        People(firstname=u'John', lastname=u'Adams'),
        People(firstname=u'Thomas', lastname=u'Jefferson')])
    db.session.commit()

if not db.session.query(Events).count():
    db.session.add_all([
        People(firstname=u'George', lastname=u'Washington'),
        People(firstname=u'John', lastname=u'Adams'),
        People(firstname=u'Thomas', lastname=u'Jefferson')])
    db.session.commit()

# using reloader will destroy in-memory sqlite db
app.run(debug=True, use_reloader=False)
