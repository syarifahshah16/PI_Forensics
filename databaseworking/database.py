#!/usr/bin/python

# References:
# https://www.pythoncentral.io/introduction-to-sqlite-in-python/


 
import sqlite3
from sqlite3 import Error
 
 
def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by the db_file
    :param db_file: database file
    :return: Connection object or None
    """
    try:
        conn = sqlite3.connect(db_file, check_same_thread=False) # we don't check for same thread (so that we can use multithreading)
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

def insertCaseDetails(conn, details):
    sql = ''' INSERT INTO CaseInfo(InvestigatorName, CaseNum, CaseName, CaseFolder, CaseDb, CaseDesc, Datetime)
              VALUES(?,?,?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, details)
    return cur.lastrowid

def insertEvidenceDetails(conn, details):
    sql = ''' INSERT INTO EvidenceInfo(CaseID, EvidenceName, EvidenceDatetime, Md5, EvidencePath, EvidenceSize)
              VALUES(?,?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, details)
    return cur.lastrowid

def insertDeletedFiles(conn, details):
    sql = ''' INSERT INTO DeletedFiles(fileType, status, inode, filePath, ctime, crtime, atime, mtime, size, uid, gid, image)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, details)
    return cur.lastrowid

def select_deleted_files(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM DeletedFiles")
    rows = cur.fetchall()
    return rows

def insertBookmarks(conn, details):
    sql = ''' INSERT INTO Bookmarks(fileName, ctime, crtime, atime, mtime, uid, gid, md5, size, parentPath, extension, image)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute(sql, details)
    return cur.lastrowid

def selectBookmarks(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM Bookmarks")
    rows = cur.fetchall()
    return rows

def chkUniqueBookmark(conn, fileName, parentPath):
    sql = "SELECT COUNT(*) FROM Bookmarks WHERE fileName = '{file}' AND parentPath = '{parent}'".format(file=fileName, parent=parentPath)
    cur = conn.cursor()
    cur.execute(sql)
    row = cur.fetchone()
    if row[0] == 0:
        return True
    else:
        return False

def deleteBookmarkItem(conn, fileName, parentPath):
    sql = "DELETE FROM Bookmarks WHERE fileName = '{file}' AND parentPath = '{parent}'".format(file=fileName, parent=parentPath)
    cur = conn.cursor()
    cur.execute(sql)
    
def select_case_details(conn):
    
    cur = conn.cursor()
    cur.execute("SELECT * FROM CaseInfo")
    rows = cur.fetchall()
    return rows

def select_evidence_details(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM EvidenceInfo")
    rows = cur.fetchall()
    return rows

def select_evidencepath(conn):
    cur = conn.cursor()
    cur.execute("SELECT EvidencePath FROM EvidenceInfo")
    rows = cur.fetchall()
    return rows

def select_image_partitions(conn):
    cur = conn.cursor()
    cur.execute("SELECT start, length, desc FROM tsk_vs_parts")
    rows = cur.fetchall()
    return rows
 
def select_image_info(conn):
    cur = conn.cursor()
    cur.execute("SELECT name, size, md5 FROM tsk_image_names n, tsk_image_info i WHERE n.obj_id = i.obj_id")
    rows = cur.fetchall()
    return rows

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
 
def search_file_name(conn, search):
    cur = conn.cursor()
    cur.execute("SELECT name, size, ctime, crtime, atime, mtime, uid, gid, md5, parent_path, extension FROM tsk_files WHERE name LIKE '%{search}%'".format(search=search))
    rows = cur.fetchall()
    return rows 

def createFilesEvidenceTable(conn):
    try:
        cursor = conn.cursor() # Get a cursor object
        cursor.execute('''CREATE TABLE filesEvidenceTable(id INTEGER PRIMARY KEY, frameNum TEXT, filePath TEXT, srcHost TEXT, srcPort TEXT, dstHost TEXT, dstPort TEXT, protocol TEXT, filename TEXT, ext TEXT, size TEXT)''')
        conn.commit()
        
    except Error as e:
        print(e)


def selectFilesEvidenceDetails(conn, id):
    cursor = conn.cursor()
    cursor.execute('''SELECT frameNum, filePath, srcHost, srcPort, dstHost, dstPort, protocol, filename, ext, size FROM filesEvidenceTable WHERE id=?''', (id,)) # note trailing comma as we're passing a tuple with a single value
    row = cursor.fetchone()
    return row

    
def createSessionsEvidenceTable(conn):
    try:
        cursor = conn.cursor() # Get a cursor object
        cursor.execute('''CREATE TABLE sessionsEvidenceTable(id INTEGER PRIMARY KEY, Packet TEXT, timestamp TEXT, src_ip TEXT, dst_ip TEXT, request TEXT)''')
        conn.commit()
        
    except Error as e:
        print(e)


def selectSessionsEvidenceDetails(conn, id):
    cursor = conn.cursor()
    cursor.execute('''SELECT Packet, timestamp, src_ip, dst_ip, request FROM sessionsEvidenceTable WHERE id=?''', (id,)) # note trailing comma as we're passing a tuple with a single value
    row = cursor.fetchone()
    return row

#---------------------------------#
#          NOT COMPLETED          #
#---------------------------------#

def createDNSEvidenceTable(conn):
    try:
        cursor = conn.cursor() # Get a cursor object
        cursor.execute('''CREATE TABLE dnsEvidenceTable(id INTEGER PRIMARY KEY, dnsname TEXT, response TEXT, protocol TEXT)''')
        conn.commit()
        
    except Error as e:
        print(e)


def selectDNSEvidenceDetails(conn, id):
    cursor = conn.cursor()
    cursor.execute('''SELECT dns, response, protocol FROM dnsEvidenceTable WHERE id=?''', (id,)) # note trailing comma as we're passing a tuple with a single value
    row = cursor.fetchone()
    return row


"""def createCredentialsEvidenceTable(conn):
    try:
        cursor = conn.cursor() # Get a cursor object
        cursor.execute('''CREATE TABLE credentialsEvidenceTable(id INTEGER PRIMARY KEY, Packet TEXT, timestamp TEXT, src_ip TEXT, dst_ip TEXT, request TEXT)''')
        conn.commit()
        
    except Error as e:
        print(e)


def selectCredentialsEvidenceDetails(conn, id):
    cursor = conn.cursor()
    cursor.execute('''SELECT Packet, timestamp, src_ip, dst_ip, request FROM credentialsEvidenceTable WHERE id=?''', (id,)) # note trailing comma as we're passing a tuple with a single value
    row = cursor.fetchone()
    return row"""


      
