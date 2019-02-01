#!/usr/bin/python
#database.py is for Network Analysis

# References:
# https://www.pythoncentral.io/introduction-to-sqlite-in-python/

import sqlite3
from sqlite3 import Error

#-----------------------#
#   BASIC CONNECTIONS   #
#-----------------------# 
def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by the db_file
    :param db_file: database file
    :return: Connection object or None
    """
    try:
        #don't check for same thread (to use multithreading)
        conn = sqlite3.connect(db_file, check_same_thread=False) 
        return conn
    except Error as e:
        print(e)
 
    return None

def close_connection(conn):
    if None != conn:
        conn.close()
 
def createTable(conn, table):
    try:
        c = conn.cursor()
        c.execute(table)
    except Error as e:
        print(e)


#------------------#
#   CASE DETAILS   #
#------------------#
def insertCaseDetails(conn, details):
    sql = ''' INSERT INTO CaseInfo(InvestigatorName, CaseNum, CaseName, CaseFolder, CaseDb, CaseDesc, Datetime)
              VALUES(?,?,?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, details)
    return cur.lastrowid

def select_case_details(conn):
    
    cur = conn.cursor()
    cur.execute("SELECT * FROM CaseInfo")
    rows = cur.fetchall()
    return rows


#----------------------#
#   EVIDENCE DETAILS   #
#----------------------#
def insertEvidenceDetails(conn, details):
    sql = ''' INSERT INTO EvidenceInfo(CaseID, EvidenceName, EvidenceDatetime, Md5, EvidencePath, EvidenceSize)
              VALUES(?,?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, details)
    return cur.lastrowid

def select_evidence_details(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM EvidenceInfo")
    rows = cur.fetchall()
    return rows


#---------------------#
#   CLICK FUNCTIONS   #
#---------------------#
def select_all_files(conn):
    cur = conn.cursor()
    cur.execute("SELECT name, size, ctime, crtime, atime, mtime, uid, gid, md5, parent_path, extension FROM tsk_files WHERE name != '.' AND name != '..'")
    rows = cur.fetchall()
    return rows

def select_queried_files(conn, extension):
    cur = conn.cursor()
    cur.execute("SELECT name, size, ctime, crtime, atime, mtime, uid, gid, md5, parent_path, extension FROM tsk_files WHERE extension={extension}".format(extension=extension))
    rows = cur.fetchall()
    return rows
 
#---------------------#
#   SEARCH FUNCTION   #
#---------------------#
def search_file_name(conn, search):
    cur = conn.cursor()
    cur.execute("SELECT name, size, ctime, crtime, atime, mtime, uid, gid, md5, parent_path, extension FROM tsk_files WHERE name LIKE '%{search}%'".format(search=search))
    rows = cur.fetchall()
    return rows 


#--------------------#
#   FILES DATABASE   #
#--------------------#
def createFilesEvidenceTable(conn):
    try:
        cursor = conn.cursor() # Get a cursor object
        cursor.execute('''CREATE TABLE filesEvidenceTable(id INTEGER PRIMARY KEY, frameNum TEXT, filePath TEXT, srcHost TEXT, srcPort TEXT, dstHost TEXT, dstPort TEXT, protocol TEXT, filename TEXT, ext TEXT, size TEXT)''')
        conn.commit()
        
    except Error as e:
        print(e)


def selectFilesEvidenceDetails(conn, id):
    cursor = conn.cursor()
    #note trailing comma as we're passing a tuple with a single value
    cursor.execute('''SELECT frameNum, filePath, srcHost, srcPort, dstHost, dstPort, protocol, filename, ext, size FROM filesEvidenceTable WHERE id=?''', (id,)) 
    row = cursor.fetchone()
    return row


#-----------------------#
#   SESSIONS DATABASE   #
#-----------------------#
def createSessionsEvidenceTable(conn):
    try:
        cursor = conn.cursor() # Get a cursor object
        cursor.execute('''CREATE TABLE sessionsEvidenceTable(id INTEGER PRIMARY KEY, Packet TEXT, timestamp TEXT, src_ip TEXT, dst_ip TEXT, request TEXT)''')
        conn.commit()
        
    except Error as e:
        print(e)


def selectSessionsEvidenceDetails(conn, id):
    cursor = conn.cursor()
    cursor.execute('''SELECT Packet, timestamp, src_ip, dst_ip, request FROM sessionsEvidenceTable WHERE id=?''', (id,)) 
    row = cursor.fetchone()
    return row


#------------------#
#   DNS DATABASE   #
#------------------#
def createDNSEvidenceTable(conn):
    try:
        cursor = conn.cursor() # Get a cursor object
        cursor.execute('''CREATE TABLE dnsEvidenceTable(id INTEGER PRIMARY KEY, dns TEXT, response TEXT, protocol TEXT)''')
        conn.commit()
        
    except Error as e:
        print(e)


def selectDNSEvidenceDetails(conn, id):
    cursor = conn.cursor()
    cursor.execute('''SELECT dns, response, protocol FROM dnsEvidenceTable WHERE id=?''', (id,)) 
    row = cursor.fetchone()
    return row


#--------------------------#
#   CREDENTIALS DATABASE   #
#--------------------------#
def createCredentialsEvidenceTable(conn):
    try:
        cursor = conn.cursor() # Get a cursor object
        cursor.execute('''CREATE TABLE credentialsEvidenceTable(id INTEGER PRIMARY KEY, frameNum TEXT, srcHost TEXT, dstHost TEXT)''')
        conn.commit()
        
    except Error as e:
        print(e)


def selectCredentialsEvidenceDetails(conn, id):
    cursor = conn.cursor()
    cursor.execute('''SELECT frameNum, srcHost, dstHost FROM credentialsEvidenceTable WHERE id=?''', (id,)) 
    row = cursor.fetchone()
    return row