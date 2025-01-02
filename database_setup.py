
from sqlalchemy import Column, ForeignKey, Integer, String,Boolean
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from flask_login import UserMixin

Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    role = Column(String, nullable=False, default='user')
    is_approved = Column(Boolean, default=False)
    address = Column(String,nullable = False)
    contact = Column(Integer,nullable=False,default=False)
    membership = Column(String, nullable=False, default='regular')
    def get_id(self):
        return str(self.id)
    def is_admin(self):
        return self.role == 'admin'
    def is_customer(self):
        return self.role=='customer'

class Customer(Base , UserMixin):
    __tablename__ ='customer'

    c_id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    address = Column(String,nullable = False)
    contact = Column(Integer,nullable=False)
    membership = Column(String, nullable=False, default='regular')
    def get_id(self):
        return str(self.c_id)



class Restaurant(Base):
    __tablename__ = 'restaurant'

    name = Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
        }

class MenuItem(Base):
    __tablename__ = 'menu_item'

    name = Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    course = Column(String(250))
    description = Column(String(250))
    price = Column(String(8))
    restaurant_id = Column(Integer, ForeignKey('restaurant.id'))
    restaurant = relationship(Restaurant)



    @property
    def serialize(self):
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'price': self.price,
            'course': self.course
        }

class Cart(Base):
    __tablename__ = 'cart'

    id = Column(Integer, primary_key=True)
    customer_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    customer = relationship('User', backref='cart', uselist=False)

class CartItem(Base):
    __tablename__ = 'cart_item'

    id = Column(Integer, primary_key=True)
    cart_id = Column(Integer, ForeignKey('cart.id'), nullable=False)
    menu_item_id = Column(Integer, ForeignKey('menu_item.id'), nullable=False)
    quantity = Column(Integer, default=1)
    cart = relationship('Cart', backref='items')
    menu_item = relationship('MenuItem', backref='cart_items')

    @property
    def restaurant_name(self):
        return self.menu_item.restaurant.name if self.menu_item and self.menu_item.restaurant else None

    @property
    def total_price(self):
        return float(self.menu_item.price) * self.quantity


    @property
    def total_price(self):
        return self.menu_item.price * self.quantity
    
engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.create_all(engine)
