from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    password = Column(String(250))
    picture = Column(String(250))


class Supermarket(Base):
    __tablename__ = 'supermarket'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    address = Column(String(250), nullable=False)
    picture = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'address': self.address,
            'picture': self.picture,
        }


class Products(Base):
    __tablename__ = 'products'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    details = Column(String(250))
    price = Column(String(8))
    picture = Column(String(250))
    supermarket_id = Column(Integer, ForeignKey('supermarket.id'))
    supermarket = relationship(Supermarket)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'details': self.details,
            'price': self.price,
            'picture': self.picture,
        }


engine = create_engine('sqlite:///supermarket.db')

Base.metadata.create_all(engine)
