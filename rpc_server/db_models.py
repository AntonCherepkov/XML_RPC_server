from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(255), nullable=False)


class AppData(Base):
    __tablename__ = 'app_data'

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(50), unique=True, nullable=False)
    value = Column(String(255), nullable=False)
