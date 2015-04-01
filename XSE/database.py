from sqlalchemy import Boolean, Column, DateTime, Integer, LargeBinary, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


def open_database(file_path):
    return create_engine('sqlite:///{0}'.format(file_path))


def create_session_factory(engine):
    return sessionmaker(bind=engine)


class Console(Base):
    __tablename__ = 'consoles'

    id = Column(Integer, primary_key=True)

    # identifying bits
    name = Column(String(100))
    cpu_key = Column(String(32))  # cpu key in hex encoded ascii
    enabled = Column(Boolean)  # allow access
    payment = Column(String(100))  # payment info, paypal etc

    # session related bits
    key_vault = Column(LargeBinary)  # raw key vault data
    hash_data = Column(LargeBinary)  # raw data used for hv hashing
    session_key = Column(String(32))  # randomly generated session key

    # last connection information
    last_ip = Column(String)  # last connection IP
    last_connect = Column(DateTime)  # last connection time
    last_title = Column(Integer)  # last title ID

    # time related bits
    bypass = Column(Boolean, default=False)  # whether or not the user has bo2 bypass
    days = Column(Integer)  # number of days left
    day_expires = Column(DateTime)  # when the current day expires

    def __init__(self, cpu_key, enabled=True):
        self.cpu_key = cpu_key
        self.enabled = enabled

    def __repr__(self):
        return "<Console('{0}', '{1}', '{2}')>".format(self.name, self.cpu_key,
                                                       'enabled' if self.enabled else 'disabled')
