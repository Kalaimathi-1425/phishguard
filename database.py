
from sqlalchemy import create_engine, Column, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

Base = declarative_base()

class ScanResult(Base):
    __tablename__ = "scan_results"
    id          = Column(String, primary_key=True)
    url         = Column(String)
    verdict     = Column(String)
    risk        = Column(String)
    probability = Column(Float)
    flags       = Column(String)
    scanned_at  = Column(DateTime, default=datetime.now)

engine  = create_engine("sqlite:///phishguard.db")
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)
