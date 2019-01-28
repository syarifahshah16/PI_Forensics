import wx
import wx.aui
import os
import SummaryPCAPTab, FileTab, ImagesTab, SessionsTab, DNSTab, CredentialsTab        
import NewCaseDialog, mainmenu, search, searchTab
#import connectdb
import database as connectdb

#https://pypi.org/project/dpkt/
import dpkt
import socket
import _thread

import threading 
import datetime, time
import re
import hashlib


#begin wxGlade: dependencies
#end wxGlade

#begin wxGlade: extracode
#end wxGlade


#globals
fileCentric = True 
openTabs = [0]
caseDbPath = None

class mainFrame(wx.Frame):
    def __init__(self, parent):
        # begin wxGlade: mainFrame.__init__
        wx.Frame.__init__(self, parent=parent)
        self.SetSize((1280, 720))
        
        #---------------------#
        #   Menu Bar Design   #
        #---------------------#
        self.frame_menubar = wx.MenuBar()
        wxglade_tmp_menu = wx.Menu()
        item = wxglade_tmp_menu.Append(wx.ID_ANY, "New Case", "")
        self.Bind(wx.EVT_MENU, self.onNewCase, id=item.GetId())
        item = wxglade_tmp_menu.Append(wx.ID_ANY, "Open Case", "")
        self.Bind(wx.EVT_MENU, self.onOpenCase, id=item.GetId())
        wxglade_tmp_menu.AppendSeparator()
        itemAddEvidenceBtn = wxglade_tmp_menu.Append(wx.ID_ANY, "Add PCAP File", "")                                      
        self.Bind(wx.EVT_MENU, self.onAddEvidence, id=itemAddEvidenceBtn.GetId())     
        wxglade_tmp_menu.AppendSeparator()
        item = wxglade_tmp_menu.Append(wx.ID_ANY, "Quit", "")
        self.Bind(wx.EVT_MENU, self.onQuit, id=item.GetId())
        self.frame_menubar.Append(wxglade_tmp_menu, "File")
        wxglade_tmp_menu = wx.Menu()
        item = wxglade_tmp_menu.Append(wx.ID_ANY, "Clear GUI", "")
        self.Bind(wx.EVT_MENU, self.onClearGUI, id=item.GetId())
        item = wxglade_tmp_menu.Append(wx.ID_ANY, "Process HTML Report", "")
        self.Bind(wx.EVT_MENU, self.on_html_report, id=item.GetId())
        item = wxglade_tmp_menu.Append(wx.ID_ANY, "Process PCAP Hash", "")
        self.Bind(wx.EVT_MENU, self.on_md5_hash, id=item.GetId())
        self.frame_menubar.Append(wxglade_tmp_menu, "Tools")
        self.SetMenuBar(self.frame_menubar)

        #------------------------#
        #   Main Window Design   #
        #------------------------#
        #splitter window
        self.window_1 = wx.SplitterWindow(self, wx.ID_ANY)

        #left panel
        self.windowLeftPanel = wx.Panel(self.window_1, wx.ID_ANY)
        self.tree_ctrl_1 = wx.TreeCtrl(self.windowLeftPanel, wx.ID_ANY, style=wx.TR_HAS_BUTTONS | wx.TR_MULTIPLE)
        
        #right panel
        self.windowRightPanel = wx.Panel(self.window_1, wx.ID_ANY)
        self.searchBtn = wx.Button(self.windowRightPanel, id=wx.ID_ANY, label="Search", pos=wx.DefaultPosition, size=(100,-1), style=0, validator=wx.DefaultValidator)
       
        self.auiNotebook = wx.aui.AuiNotebook(self.windowRightPanel)
        self.paneltest = wx.Panel(self.auiNotebook, wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize, wx.TAB_TRAVERSAL)
        
        #bind events
        self.Bind(wx.EVT_TREE_ITEM_ACTIVATED, self.onItemSel, self.tree_ctrl_1)
        self.Bind(wx.EVT_BUTTON, self.onSearchBtn, self.searchBtn)
        self.Bind(wx.aui.EVT_AUINOTEBOOK_PAGE_CLOSE, self.onAuiClose, self.auiNotebook)

        #properties
        self.SetTitle("Forensic Pi")
        self.tree_ctrl_1.SetBackgroundColour(wx.Colour(240, 240, 240))
        self.windowLeftPanel.SetMinSize((180, -1))
        self.windowRightPanel.SetMinSize((980, -1))
        self.window_1.SetMinimumPaneSize(20)

        #layout
        mainSizer = wx.BoxSizer(wx.VERTICAL)
        
        #left panel sizer
        panel1Sizer = wx.BoxSizer(wx.HORIZONTAL)
        panel1Sizer.Add(self.tree_ctrl_1, 1, wx.EXPAND, 0)
        self.windowLeftPanel.SetSizer(panel1Sizer)
        
        #right panel sizer
        self.panel2Sizer = wx.BoxSizer(wx.VERTICAL)
        self.panel2Sizer.Add(self.searchBtn, 0, wx.ALIGN_RIGHT , 0)
        self.panel2Sizer.Add(self.auiNotebook, 1, wx.EXPAND, 0)
        self.windowRightPanel.SetSizer(self.panel2Sizer)
        
        #splitter
        self.window_1.SplitVertically(self.windowLeftPanel, self.windowRightPanel)
        mainSizer.Add(self.window_1, 1, wx.EXPAND, 0)
       
        self.SetSizer(mainSizer)
        self.Layout()
        
        # database
        self.conn = None
        #self.evidence = None
        self.evidenceDetails = None


    def recreateTree(self, caseDbFile):
        self.tree_ctrl_1.Freeze()
        self.tree_ctrl_1.DeleteAllItems()
        global caseName
        for x in caseDetails:
            caseName = str(x[2]) + "_" + x[3]

        #adds the name of case as root item in treectrl
        root = self.tree_ctrl_1.AddRoot(caseName)                                   
        self.tree_ctrl_1.AppendItem(root, "Summary")
                                                   
        self.tree_ctrl_1.AppendItem(root, "Bookmarks")
        self.tree_ctrl_1.AppendItem(root, "File")
        self.tree_ctrl_1.AppendItem(root, "Images")
        self.tree_ctrl_1.AppendItem(root, "Sessions")
        self.tree_ctrl_1.AppendItem(root, "DNS")
        self.tree_ctrl_1.AppendItem(root, "Credentials")

        self.tree_ctrl_1.ExpandAll()
        self.tree_ctrl_1.Thaw()


    #------------------------#
    #   Menu Bar Functions   #
    #------------------------#    
    def onNewCase(self, event):  
        dialog = NewCaseDialog.newCase(None)
        dialog.Center()
        dialog.ShowModal()
        dbPath = dialog.getCaseDb()
        
        global caseDetails, caseDbPath
        try:
            #connects to new case database
            self.conn = connectdb.create_connection(dbPath) 
            #get InvestigatorName, CaseNum, CaseName, CaseFolder, CaseDb, CaseDesc, Datatime from case database
            caseDetails = connectdb.select_case_details(self.conn) 
            self.recreateTree(dbPath)
            caseDbPath = dbPath
            
        except:
            pass 
        
        dialog.Destroy()
        

    def onOpenCase(self, event):  
        #creates a filedialog that only allow user to select .db files
        openFileDialog = wx.FileDialog(self, "Open", "", "","*.db",         
                                       wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) 
 
        openFileDialog.ShowModal()                      
        global caseDbPath
        #get path selected in filedialog
        caseDbPath  = openFileDialog.GetPath()                              
        
        global caseDetails, openTabs
        try:
            #try to connect to case database and get case and evidence details
            self.conn = connectdb.create_connection(caseDbPath)
            caseDetails = connectdb.select_case_details(self.conn)#conn)
            #get EvidenceName, EvidenceDbPath, EvidenceDatatime and Md5 from case database
            self.evidenceDetails = connectdb.select_evidence_details(self.conn)     
            self.addAuiTab("Summary", self.evidenceDetails)                      
            #opens summary page 
            openTabs.append("Summary")                          
            self.recreateTree(caseDbPath)
        except:
            #ignore if try: fails
            pass                                                            
        openFileDialog.Destroy()


    def onAddEvidence(self, event):
        global caseDetails, evidencePath, openFileDialog
        try:
            caseDetails                                                     
        #if caseDetails not defined
        except NameError:                                                   
            print("Case not opened")                                        
        #if caseDetails is defined
        else:                                                               
            #creates a filedialog that only allow user to select .pcap files 
            openFileDialog = wx.FileDialog(self, "Open", "", "","*.pcap",     
                                        wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)
    
            openFileDialog.ShowModal()                         
            global caseDir, caseDbPath, evidencePath, fileName

            #evidencePath includes filename                                   
            evidencePath = openFileDialog.GetPath()

            #get the filename of the pcap
            fileName = os.path.basename(evidencePath)

            #create loading dialog
            self._dialog = wx.ProgressDialog("Loading", "Uploading PCAP", 100)  
            LoadingDialog(self._dialog)

            #---------------------#
            #   Multi-Threading   #     #https://www.tutorialspoint.com/python3/python_multithreading.htm  
            #---------------------#

            _thread.start_new_thread(self.onAddEvidencePcapExtract, (evidencePath, openFileDialog,) )
            _thread.start_new_thread(self.onAddSessionsEvidence, (evidencePath, openFileDialog,) )

        openFileDialog.Destroy() # close PCAP file

             
    def onQuit(self, event):
        #close database connection
        connectdb.close_connection(self.conn) 
        self.Close()
        self.Destroy()


    def onClearGUI(self, event):  
        self.Close()
        self.Destroy()

    def on_html_report(self, event):  
        global fileName
        directoryfiledialog = wx.DirDialog (None, "Choose directory", "",
                                wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST)
        if directoryfiledialog.ShowModal() == wx.ID_OK:
            #get path of selected directory
            creaderpath = directoryfiledialog.GetPath()                         
            #get directory name
            directoryname = directoryfiledialog.GetPath()     

            print(directoryname)
            #run the chaosreader cmd
            crd = ['chaosreader', fileName, '--dir', directoryname]             
            process = Popen(crd, stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()

            #print out full path so that user knows exactly where the directory is
            print("Report successfully made in " +creaderpath) 


    def on_md5_hash(self, event):
        global evidencePath   
        md5_hash = hashlib.md5()
        print(evidencePath)
        f = open(evidencePath, 'rb')
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            md5_hash.update(byte_block)
        print(md5_hash.hexdigest())
        pcapMD5 = md5_hash.hexdigest()

        wx.MessageBox('MD5 HASH: ' +pcapMD5 , 'MD5 HASH', wx.OK | wx.ICON_INFORMATION)
            
    #-------------------------------#
    #   End of Menu Tab Functions   #
    #-------------------------------#


    #----------------------------#
    #   Notebook Tab Functions   #
    #----------------------------#   
    def onAddEvidencePcapExtract(self, evidencePath, openFileDialog):
        #lock.acquire()
        #global caseDbPath, evidencePath, openFileDialog

        global caseDbPath

        if (None == caseDbPath):
            print("Error: onAddEvidencePcapExtract - global caseDbPath invalid!")
            return False

        #http://www.kroosec.com/2012/10/a-look-at-pcap-file-format.html?m=1
        #https://programtalk.com/python-examples/dpkt.ethernet.Ethernet/
        #https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#Response_fields
        #https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
        #http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session
        
        #rb is for opening non-text files
        f = open(evidencePath, 'rb')
        #open pcap with dpkt "Reader" class
        pcap = dpkt.pcap.Reader(f)

        #for frame number
        identifier = 0
        #for number of actual file transfers
        httpFileTransferCount = 0;
        
        #make our own connection to the database (and make sure to close it when finished)
        #https://stackoverflow.com/questions/6296055/serializing-sqlite3-in-python
        addEvidenceDbConn = connectdb.create_connection(caseDbPath)
        
        #create an empty list into to temporarily store the data to be written to the database
        filesPreBufList = []; 
        
        for ts, buf in pcap:
            identifier = identifier + 1
            idStr = "\nPacket identifier: " + str(identifier)
            #print(idStr)
            
            #default values: alternative to doing if-else
            #if cannot find a value, take it as empty instead of giving an error
            protocol      = "HTTP "
            ext           = ""
            size          = ""
            fileName      = ""
            evidencePath  = ""
            
            #pasing packet data to dpkt's Ethernet class + decode eth object
            eth = dpkt.ethernet.Ethernet(buf)
            #print("Ethernet type code: ", eth.type)

            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                #print("IP packet type detected. Extracting values...")
                #to contain IP address in binary
                ip_hdr = eth.data       #ip_hdr.src / ip_hdr.dst
                ip     = eth.ip         #IP object
                tcp    = ip.data        #TCP object
                
                #frame number (a sequential number)
                #identifies every Ethernet entry within the PCAP
                frameNumber  = identifier
                
                #--------------------------#
                #   Server to Web Client   #
                #--------------------------#
                #signifies source IP address in binary
                src_ip_addr_bin = ip_hdr.src
                #convert binary to ASCII string using socket package
                src_host_str = socket.inet_ntoa(src_ip_addr_bin)
                
                #check for TCP packets
                if ip_hdr.p == dpkt.ip.IP_PROTO_TCP:
                    #look at source port of TCP header
                    src_port = tcp.sport
                    #print("Source port: ", src_port)
                    
                    #if the source port is 80 or 443, looking at a Response message
                    if (80 == int(src_port)) and (len(tcp.data) > 0):
                        try:                               
                            #file size comes from HTTP Response content-length
                            http = dpkt.http.Response(tcp.data)
                            content_length = http.headers['content-length'] if 'content-length' in http.headers else ""
                            size = str(content_length)
                            #print("Content length: ", size)
                            protocol = protocol + (http.headers['transfer-encoding'] if 'transfer-encoding' in http.headers else "")
                            
                        except Exception:
                            print(idStr)
                            print("Exception in Response direction")
                            
                    #if SSL
                    elif (443 == int(src_port)) and (len(tcp.data) > 0 ): 
                        #https://dpkt.readthedocs.io/en/latest/_modules/dpkt/ssl.html
                        #https://gist.github.com/strizhechenko/3b70da47d317f8f8875d39edbfc5d7fc
                        #https://tools.ietf.org/html/rfc5246#section-7.4.2
                        #https://tls.ulfheim.net/
                        #https://tls.ulfheim.net/certificate.html
                        
                        try:
                            protocol = "TLS Certificate"
                            
                            tls = dpkt.ssl.TLS(tcp.data)
                            if len(tls.records) >= 1:
                                for i in range (0, len(tls.records)):
                                    handshake = dpkt.ssl.TLSHandshake(tls.records[i].data)
                                    if handshake.type == 11:
                                        certificateClassInst = handshake.data
                                        #certificate is str type TODO multiple certificates
                                        certificate = certificateClassInst.certificates[0] 
                                        data = certificate
                                        
                                        idx = 0
                                        lenData = len(data)
                                        #print("Data length: " + str(lenData))
                                        found = False
                                        while (idx < (lenData - 2)):
                                            Byte1 = data[idx]
                                            Byte2 = data[idx + 1]
                                            #print("Byte 1: " + str(hex(Byte1)) + " Byte 2: " + str(hex(Byte2)))
                                            if (Byte1 == 0x30) and (Byte2 == 0x82): #cert seq or cert info seq
                                                inc = 4
                                            elif (Byte1 == 0x30) and (Byte2 == 0x22): #iss seq
                                                inc = 2
                                            elif (Byte1 == 0x30) and (Byte2 == 0x2b): #subj seq
                                                inc = 2
                                            elif (Byte1 == 0x30) and (Byte2 == 0x4e): #iss seq
                                                inc = 2
                                            else:
                                                inc = Byte2 + 2 #length (+2 to include Byte1 and Byte2)
                                                
                                            #safety check
                                            if inc == 0:
                                                #from while-loop
                                                break 
                                            
                                            if (Byte1 == 0x30) and (Byte2 == 0x81): #start of rdn seq - look for common name
                                                #print("start of rdn seq found")
                                                for i in range (idx +2, len(data) - 7):
                                                    Byte1 = data[i]
                                                    Byte2 = data[i + 1]
                                                    Byte5 = data[i + 4]
                                                    Byte6 = data[i + 5]
                                                    Byte7 = data[i + 6]
                                                    if (Byte1 == 0x30) and (Byte5 == 0x55) and (Byte6 == 0x04) and (Byte7 == 0x03):
                                                        #print("common name found")
                                                        comNameLen = data[i + 8]
                                                        #i + 9 + comName gives us characters up to i + 9 + comName -1 !
                                                        comName = data[i + 9: i + 9 + comNameLen] 
                                                        #print("Common name: " + str(comName))
                                                        src_host_str = src_host_str + " [" + str(comName) + "]"
                                                        found = True
                                            
                                            idx = idx + inc
                                            if True == found:
                                                #from while-loop
                                                break 
                                            
                                        if False == found:
                                            print(idStr)
                                            print("common name not found")

                        except Exception:
                            print(idStr)
                            print("Exception in SSL web server to client direction")
                        
                else:
                    print(idStr)
                    print("Protocol is not TCP")
                
                #print("Source host: ", src_host_str)
                
                #--------------------------#
                #   Web Client to Server   #
                #--------------------------#
                #signifies destination IP address in binary
                dst_ip_addr_bin = ip_hdr.dst
                #covert binary to ASCII string using socket package
                dst_host_str = socket.inet_ntoa(dst_ip_addr_bin)
                
                #check for TCP packets
                if ip_hdr.p == dpkt.ip.IP_PROTO_TCP:
                    #look at destination port of TCP header
                    dst_port = tcp.dport
                    #print("Destination port: ", dst_port)
                    
                    #if the desitnation port is 80 or 443, looking at a Request message
                    if (80 == int(dst_port)) and (len(tcp.data) > 0): # if HTTP
                        try:      
                            http = dpkt.http.Request(tcp.data)
                            
                            host = http.headers['host'] if 'host' in http.headers else None
                            dst_host_str = dst_host_str + " [" + str(host) + "]"
                            
                            #fileName is from uri field in HTTP Request
                            uri = http.uri
                            evidencePath = str(uri)
                            fileName = os.path.basename(evidencePath)
                            
                            #process extension
                            ext = os.path.splitext(fileName)[1][1:]
                            #assuming extension can't be more than 4 characters in length
                            if len(ext) > 4: 
                                ext = ext[:4]
                            #assuming extension can't end with '?'
                            if ext[3] == '?': 
                                ext = ext[:3]
                            if ext[2] == '?':
                                ext = ext[:2]
                            #assuming extension can contain only letters
                            if False == ext.isalpha(): 
                                ext = " "
                            
                            #user_agent field to get machine name + operating system
                            user_agent = http.headers['user-agent'] if 'user-agent' in http.headers else None
                            src_host_str = src_host_str + " [" + str(user_agent) + "]"
                            protocol = protocol + (http.headers['transfer-encoding'] if 'transfer-encoding' in http.headers else "")
                            
                            #if fileName is not empty, add to actual file transfers count
                            if fileName != "":
                                httpFileTransferCount = httpFileTransferCount + 1
                            
                        except Exception:
                            print(idStr)
                            print("Exception in Request direction")
                            
                    #if SSL
                    elif (443 == int(dst_port)) and (len(tcp.data) > 0 ): 
                        try:
                            src_host_str = src_host_str + " (Other)"
                            protocol = "TLS Certificate"
                            
                        except Exception:
                            print(idStr)
                            print("Exception in SSL web client to server direction")
                    
                else:
                    print(idStr)
                    print("Protocol is not TCP")
                    
                #print("Desintation host: ", dst_host_str)
                                                     
                #-----------------------------------#                                      
                #   Output to Database Pre-Buffer   #
                #-----------------------------------#
                #only show packets that are to do with file transfers (via port 80 or port 443)
                if (src_port == 80) or (src_port == 443) or (dst_port == 80) or (dst_port == 443): 
                    #flag that we've got evidence
                    self.evidenceDetails = 1 
                
                    #append extracted data to the temporary buffer so that we can separate PCAP extraction from database interaction
                    #list of tuples
                    filesPreBufList.append( (str(frameNumber), str(evidencePath), str(src_host_str), str(src_port), str(dst_host_str), str(dst_port), str(protocol), str(fileName), str(ext), str(size) ) ) 
                
            else:
                print(idStr)
                print("Unsupported packet type. Values not extracted.")
        
        #transfer data (tuples) from buffer to database
        #http://specminor.org/2017/01/09/improve-sqlite-write-speed-python.html
        numRows = len(filesPreBufList)
        #print("Rows: " + str(numRows))
        
        #step size 10
        for i in range (0, numRows, 20): 
            cursor = addEvidenceDbConn.cursor()
            #switch to asynchronous mode for better speed
            cursor.execute("PRAGMA synchronous = OFF")
            cursor.execute("BEGIN TRANSACTION")
            #must be same value as for i step size above
            #every 20 rows of data, will break and commit
            for j in range (i, i + 20): 
                if j >= numRows:
                    #from for-loop
                    break 
                    
                #row tuple
                r = filesPreBufList[j] 

                #insert values into table
                cursor.execute('''INSERT INTO filesEvidenceTable(frameNum, filePath, srcHost, srcPort, dstHost, dstPort, protocol, filename, ext, size) VALUES(?,?,?,?,?,?,?,?,?,?)''',
                       (r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]))
            
            #wait till commit before writing to disk (saves time)
            addEvidenceDbConn.commit()

        print ("\nPCAP extraction finished.\n")
        print ("Packets captured: ", str(identifier))
        print ("HTTP file transfer count: ", httpFileTransferCount)

        #close database connection
        addEvidenceDbConn.close()
        #close PCAP file BUT there's an error "RuntimeError: wrapped C/C++ object of type FileDialog has been deleted"
        openFileDialog.Destroy() 
        
        #status = OK
        return True 

        #lock.release()

    def onAddSessionsEvidence(self, evidencePath, openFileDialog):
        #lock.acquire()     
        #global caseDbPath, evidencePath, openFileDialog

        global caseDbPath

        if (None == caseDbPath):
            print("Error: runFiles - global caseDbPath invalid!")
            return False


        #rb is for opening non-text files
        f = open(evidencePath, 'rb')
        pcap = dpkt.pcap.Reader(f)

        # For each packet in the pcap process the contents
        identifier = 0

        addEvidenceDbConn = connectdb.create_connection(caseDbPath)
        
        sessionsPreBufList = []; 

        for timestamp, buf in pcap:

            #print out the timestamp in UTC
            #print ("Timestamp" , str(datetime.datetime.utcfromtimestamp(timestamp)))
                    
            identifier = identifier + 1
            Packet  = identifier

            # Unpack the Ethernet frame (mac src/dst, ethertype)
            eth = dpkt.ethernet.Ethernet(buf)
            #print ('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

            # Make sure the Ethernet frame contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                print ('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
                continue

            # Now unpack the data within the Ethernet frame (the IP packet)
            # Pulling out src, dst, length, fragment info, TTL, and Protocol
            ip_hdr = eth.data

            # Check for TCP in the transport layer
            if isinstance(ip_hdr.data, dpkt.tcp.TCP):

                # Set the TCP data
                tcp = ip_hdr.data

                # Now see if we can parse the contents as a HTTP request
                try:
                    request = dpkt.http.Request(tcp.data)
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    continue

            #pulling out the source ip from the eth.data
            src_ip_addr_bin = ip_hdr.src
            #conversion to readable (i think)
            src_ip = socket.inet_ntoa(src_ip_addr_bin)

            #pulling out the dest ip from the eth.data
            dst_ip_addr_bin = ip_hdr.dst
            #conversion to readable (i think)
            dst_ip = socket.inet_ntoa(dst_ip_addr_bin)

            #puling out the protocol
            proto = ip_hdr.get_proto(ip_hdr.p).__name__

            self.evidenceDetails = 1 # flag that we've got evidence
            sessionsPreBufList.append( (str(Packet),  str(datetime.datetime.utcfromtimestamp(timestamp)), str(src_ip), str(dst_ip), str(request) ) ) # list of tuples

        # transfer data (tuples) from buffer to database
        # http://specminor.org/2017/01/09/improve-sqlite-write-speed-python.html
        numRows = len(sessionsPreBufList)
        #print("Rows: " + str(numRows))
        for i in range (0, numRows, 20): # step size 10
            cursor = addEvidenceDbConn.cursor()
            cursor.execute("PRAGMA synchronous = OFF")
            cursor.execute("BEGIN TRANSACTION")
            for j in range (i, i + 20): # must be same value as for i step size above
                if j >= numRows:
                    break # from for-loop
                    
                r = sessionsPreBufList[j] # row tuple

                cursor.execute('''INSERT INTO sessionsEvidenceTable(Packet, timestamp, src_ip, dst_ip, request) VALUES(?,?,?,?,?)''',
                       (r[0], r[1], r[2], r[3], r[4]))
            
            addEvidenceDbConn.commit()

        print ("\nSessions extraction finished.\n")

        addEvidenceDbConn.close()
        openFileDialog.Destroy() # close PCAP file
        
        return True # status = OK
        #lock.release()

    #-----------------------#
    #   TO BE ADDED LATER   #
    #-----------------------#
    #def onAddDNSEvidence(self, evidencePath, openFileDialog):
    #def onAddCredentialsEvidence(self, evidencePath, openFileDialog):


    #-----------------------------------#
    #   End of Notebook Tab Functions   #
    #-----------------------------------#   
    
    #-----------------------#
    #   Aui Tab Functions   #
    #-----------------------#
    def checkOpenedTab(self, tabName):                     
        global openTabs

        #check if tab is opened in aui
        openedTab = set(openTabs)
        if tabName not in openedTab:
            openTabs.append(tabName)
            return True
        else:
            return False


    def addAuiTab(self, tabName, evidenceDetails):
        global caseDir
        for x in caseDetails:
            caseDir = x[4]

        if tabName == "Summary":
            self.auiNotebook.AddPage(SummaryTab.TabPanel(self.auiNotebook, caseDetails, evidenceDetails), tabName, False, wx.NullBitmap)

        if tabName == "File":
            #create loading dialog
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  
            #start loading 
            LoadingDialog(self._dialog)                                                                    
            #calls and open a aui tab from pcapFilesTab.py
            self.auiNotebook.AddPage(FileTab.FilesTabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) 
            LoadingDialog.endLoadingDialog(self)
            
            #just added a page so the page we want to access is the last one
            window = self.auiNotebook.GetPage(self.auiNotebook.GetPageCount() - 1) 

            #get the PCAP data from the database and display in the GUI (Files Tab)
            global fileCentric
            _thread.start_new_thread(self.filesDataDbToGui, (window, fileCentric,) )
            #self.filesDataDbToGui, (window, fileCentric,) 

        if tabName == "Images":
            #create loading dialog
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  
            #start loading 
            LoadingDialog(self._dialog)     
            #calls and open a aui tab from pcapImagesTab.py
            self.auiNotebook.AddPage(ImagesTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) 
            LoadingDialog.endLoadingDialog(self)    

        if tabName == "Sessions":
            #create loading dialog
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  
            #start loading 
            LoadingDialog(self._dialog)     
            #calls and open a aui tab from pcapSessionsTab.py
            self.auiNotebook.AddPage(SessionsTab.SessionsTabPanel(self.auiNotebook, caseDir), tabName, False, wx.NullBitmap) 
            LoadingDialog.endLoadingDialog(self)    

            #just added a page so the page we want to access is the last one
            window = self.auiNotebook.GetPage(self.auiNotebook.GetPageCount() - 1) 

            #get the PCAP data from the database and display in the GUI (Sessions Tab)
            _thread.start_new_thread(self.sessionsDataDbToGui, (window,) )
            #self.sessionsDataDbToGui, (window,) 

        if tabName == "DNS":
            #create loading dialog
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  
            #start loading 
            LoadingDialog(self._dialog)     
            #calls and open a aui tab from pcapDNSTab.py
            self.auiNotebook.AddPage(DNSTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) 
            LoadingDialog.endLoadingDialog(self)    

            #just added a page so the page we want to access is the last one
            #window = self.auiNotebook.GetPage(self.auiNotebook.GetPageCount() - 1) 

            #get the PCAP data from the database and display in the GUI (Files Tab)
            #_thread.start_new_thread(self.dnsDataDbToGui, (window,) )
            #self.dnsDataDbToGui, (window,) 

        if tabName == "Credentials":
            #create loading dialog
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  
            #start loading 
            LoadingDialog(self._dialog)     
            #calls and open a aui tab from pcapCredentialsTab.py
            self.auiNotebook.AddPage(CredentialsTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) 
            LoadingDialog.endLoadingDialog(self)    

            #just added a page so the page we want to access is the last one
            #window = self.auiNotebook.GetPage(self.auiNotebook.GetPageCount() - 1) 

            #get the PCAP data from the database and display in the GUI (Files Tab)
            #_thread.start_new_thread(self.credentialsDataDbToGui, (window,) )
            #self.credentialsDataDbToGui, (window,) 

        if tabName == "Bookmarks":
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)
            LoadingDialog(self._dialog)
            
            #commented-out as AnalyzedDataTab undefined
            #self.auiNotebook.AddPage(AnalyzedDataTab.TabPanel(self.auiNotebook, tabName, evidenceDetails, caseDir, caseDbPath), tabName, False, wx.NullBitmap)  #calls and open a aui tab from SummaryTab.py
            
            LoadingDialog.endLoadingDialog(self)

        #commented-out because AnalyzedDataTab doesn't exist, and evidenceDbInfo isn't used.
        """for x in evidenceDetails:                  
            evidenceDbConn = connectdb.create_connection(x[2])                      #connects to tsk database
            evidenceDbInfo = connectdb.select_image_info(evidenceDbConn)            #get name, size and md5 from tsk database
            evidencePart  = connectdb.select_image_partitions(evidenceDbConn)       #get partition info from tsk database
            count = 0
            for i in evidencePart:
                count += 1
                if tabName == "Vol{count} {desc}: {start}-{end})".format(count=count, desc=str(i[2]), start=str(i[0]), end=str(i[1])):
                    self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)
                    LoadingDialog(self._dialog)
                    self.auiNotebook.AddPage(AnalyzedDataTab.TabPanel(self.auiNotebook, tabName, evidenceDetails, caseDir, caseDbPath), tabName, False, wx.NullBitmap)
                    LoadingDialog.endLoadingDialog(self)"""


    def filesDataDbToGui(self, window, fileCentric):
        #packet-centric output
        if(False == fileCentric) : 
            #get the PCAP data from the database and display in the GUI (Files Tab)
            index = 1
            #if click packet-centric button for example [TODO]
            while (True):
                #connect and select evidence
                row = connectdb.selectFilesEvidenceDetails(self.conn, index)
                if ( () == row or None == row ):
                    #from while-loop (no more data)
                    break 
                
                #post to sequence in pcapFilesTab.py    
                FileTab.FilesTabPanel.addPcapDetails(window, row)
                index = index + 1
              
        #file-centric output  
        else: 
            #packet index
            index = 1 
            fileIndex = 1

            #column position constants
            sourceHostCol = 2
            destHostCol   = 4
            destPortCol   = 5
            filenameCol   = 7
            sizeCol       = 9
            
            #if column positions are right
            while (True):
                #connect and select evidence
                rowTuple = connectdb.selectFilesEvidenceDetails(self.conn, index)
                               
                #if row is empty or nothing               
                if ( () == rowTuple or None == rowTuple ):
                    print("End of data")
                    #from while-loop (no more data)
                    break 
                    
                #if http port or ssl
                if (int(rowTuple[destPortCol]) == 80) or (int(rowTuple[destPortCol]) == 443): 
                    #if fileName not empty
                    if (rowTuple[filenameCol] != ""): 
                        #look for corresponding Response containng file size
                        #look through next 10 rows for file size info
                        #each row corresponds to a tcp packet, so there are several packets per file transfer
                        for j in range(index + 1, index +10): 
                            #fileSize not in web client to server, but is in the packets passing on the other direction
                            rowForSizeTuple = connectdb.selectFilesEvidenceDetails(self.conn, j)
                            
                            #if row is empty or nothing   
                            if ( () == rowTuple or None == rowTuple ):
                                #from while-loop (no more data)
                                break 
         
                            #get just the ip address from each host string (ignoring any subsequent characters)
                            #.group() is a regex that looks for 4 numbers separated by dots
                            #digits must be between 1-3 in length
                            destHost          = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rowTuple[destHostCol]).group()
                            sourceHost        = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rowTuple[sourceHostCol]).group()
                            forSizeDestHost   = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rowForSizeTuple[destHostCol]).group()
                            forSizeSourceHost = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', rowForSizeTuple[sourceHostCol]).group()
                            
                            #compare server and web-client ip addresses to see if we have corresponding HTTP Request and Response packets
                            #Request packet source IP address = Response packet destination IP address
                            if  (forSizeDestHost   == sourceHost)\
                            and (forSizeSourceHost == destHost):
                                
                                #once found the corresponding Response packet
                                #if the Response contains a file size then get it
                                if (rowForSizeTuple[sizeCol] != ""): 
                                    rowTuple = (rowTuple[:sizeCol]) + (rowForSizeTuple[sizeCol],) + rowTuple[sizeCol + 1:]
                                #from for-loop (as found the Response packet)
                                break 
                
                        #put fileIndex into frame number column
                        rowTuple = (fileIndex,) + rowTuple[1:] 
                        fileIndex = fileIndex + 1
                        FileTab.FilesTabPanel.addPcapDetails(window, rowTuple)

                index = index + 1


    def sessionsDataDbToGui(self, window,):
        index = 1
        #unsure of while loop: TOFIND
        while (True):
            row = connectdb.selectSessionsEvidenceDetails(self.conn, index)
            #if row is empty or nothing
            if ( () == row or None == row ):
                #from while-loop (no more data)
                break 
                    
            SessionsTab.SessionsTabPanel.addSessionsDetails(window, row)
            index = index + 1


    #--------------------------------------------------------#
    #   CURRENTLY NOT USED BC FOCUSSING ON FILES + SESSIONS  #
    #--------------------------------------------------------#
    def dnsDataDbToGui(self, window,):
        index = 1
        #unsure of while loop: TOFIND
        while (True):
            row = connectdb.selectDNSEvidenceDetails(self.conn, index)
            #if row is empty or nothing
            if ( () == row or None == row ):
                #from while-loop (no more data)
                break 
                    
            DNSTab.DNSTabPanel.addDNSDetails(window, row)
            index = index + 1


    def credentialsDataDbToGui(self, window,):
        index = 1
        #unsure of while loop: TOFIND
        while (True):
            row = connectdb.selectCredentialsEvidenceDetails(self.conn, index)
            #if row is empty or nothing
            if ( () == row or None == row ):
                #from while-loop (no more data)
                break 
                    
            CredentialsTab.CredentialsTabPanel.addCredentialsDetails(window, row)
            index = index + 1


    def onItemSel(self, event):  
        temp = event.GetItem()          #gets selected item from treectrl
        print("temp: ", temp)
        tabName = self.tree_ctrl_1.GetItemText(temp)    
        print("{name} selected".format(name=tabName))

        try:
            caseDetails                 #checks if caseDetails is defined
        except:                         #if not defined
            print("Case not opened")
        else:                           #if defined
            try:                    
                self.evidenceDetails #evidenceDetails
            except:
                print("No evidence found")
            else:
                if self.checkOpenedTab(tabName) == True:        #check if selected item is open 
                    self.addAuiTab(tabName, self.evidenceDetails)    #open aui tab
                else: 
                    print('Tab already open')



    def onAuiClose(self, event):
        global openTabs
        
        temp = event.GetSelection()
        tabName = self.auiNotebook.GetPageText(temp)
        self.auiNotebook.RemovePage(temp)
        print("Closing " + tabName + " tab")
        openTabs.remove(tabName)                    #remove closed tab from openTabs
        # TODO work out how to refresh the tab which was in the background

    
    
    def onSearchBtn(self, event):
        try:
            caseDetails
        except:
            print("Case not open")
        else:
            dlg = search.searchDialog(None)         #calls searchDialog() from search.py
            dlg.Center()
            dlg.ShowModal()
            searchItem = dlg.searchItems()          #calls searchItem() to get search and search option

            searchReturn = []
            if searchItem[1] == "Normal Search":
                for x in self.evidenceDetails:
                    conn = connectdb.create_connection(x[2])                            #connect to tsk database
                    searchResults = connectdb.search_file_name(conn, searchItem[0])     #search in tsk database
                    if searchResults != []:
                        for i in searchResults:
                            i = i + (x[1],)                                             #adds image location to end of result
                            searchReturn.append(i)                                      #append each result

                self._dialog = wx.ProgressDialog("Search", "Searching for {val}".format(val=searchItem[0]), 100)
                LoadingDialog(self._dialog)
                self.auiNotebook.AddPage(searchTab.searchTabPanel(self.auiNotebook, searchReturn, caseDir), "Search ("+searchItem[0]+")", False, wx.NullBitmap) #call and add searchTab aui page
                LoadingDialog.endLoadingDialog(self)
            else:
                print("Regular Expression")

            dlg.Destroy()

        

class LoadingDialog():
    def __init__(self, _dialog):
        self._dialog = _dialog
        self._dialog.Center()
        self._dialog.Pulse()
        self.run()
     
    def run(self):
        count = 0
        while True:
            self._dialog.Update(count)
            if count == 100:
                break
            count += 2
        
    def endLoadingDialog(self):
        self._dialog.Destroy()



class MyApp(wx.App):
    def OnInit(self):
        self.ForensicPi = mainFrame(None)
        self.SetTopWindow(self.ForensicPi)
        self.ForensicPi.Show()
        self.ForensicPi.Center()        
        return True
# end of class MyApp



if __name__ == "__main__":
    forensicPi = None
    forensicPi = MyApp(0)
    if None != forensicPi:
        forensicPi.MainLoop()
    else:
        print("Error in __main__")

