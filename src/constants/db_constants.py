from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Float, BigInteger, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker


db_user = "root"
db_connection_str = 'mysql+pymysql://' + db_user + ':@localhost/'
dbname = "nist_analytics"

# Classes for db names

Base = declarative_base()

class CvesFact(Base):
    __tablename__ = 'cves_fact'
    
    cve_id = Column(BigInteger, primary_key=True)
    cve_id_str = Column(String(40))
    description = Column(String(3000))
    
    cves_severity = relationship("CvesSeverity", back_populates="cves_fact_relation", uselist = False)
    cves_scores = relationship("CvesScores", back_populates="cves_fact_relation", uselist = False)
    cves_attack_vectors = relationship("CvesAttackVectors", back_populates="cves_fact_relation", uselist = False)
    

class CvesSeverity(Base):
    __tablename__ = 'cves_severity'
    
    id = Column(BigInteger, primary_key=True)
    cve_id = Column(BigInteger, ForeignKey('cves_fact.cve_id'))
    severity =  Column(String(40))  
    last_modified = Column(DateTime)
                   
    cves_fact_relation = relationship("CvesFact", back_populates="cves_severity")


class CvesScores(Base):
    __tablename__ = 'cves_scores'
    
    id = Column(BigInteger, primary_key=True)
    cve_id = Column(BigInteger, ForeignKey('cves_fact.cve_id'))
    exploitability_score = Column(Float)
    impact_score = Column(Float)  
    last_modified = Column(DateTime)
    
    cves_fact_relation = relationship("CvesFact", back_populates="cves_scores")


class CvesAttackVectors(Base):
    __tablename__ = 'cves_attack_vectors'
    
    id = Column(BigInteger, primary_key=True)
    cve_id = Column(BigInteger, ForeignKey('cves_fact.cve_id'))
    attack_vector =  Column(String(40))
    last_modified = Column(DateTime)
    
    cves_fact_relation = relationship("CvesFact", back_populates="cves_attack_vectors")

