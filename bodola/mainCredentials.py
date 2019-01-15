#basic imports
import wx
import wx.aui
import os

#imports for notebook tabs
import summaryTab, pcapCredentialsTab, pcapDNSTab, pcapFilesTab,  pcapSessionsTab        
import newCaseDialog, mainmenu, search, searchTab
import connectdb

#imports for files
import dpkt
import socket

#import for sessions
import datetime, time

# begin wxGlade: dependencies
# end wxGlade

# begin wxGlade: extracode
# end wxGlade

openTabs = [0]

class mainFrame(wx.Frame):
    def __init__(self, parent):
        # begin wxGlade: mainFrame.__init__
        wx.Frame.__init__(self, parent=parent)
        self.SetSize((1280, 720))
        
        #------------------#
        #   design codes   #
        #------------------#
        self.frame_menubar = wx.MenuBar()
        wxglade_tmp_menu = wx.Menu()
        item = wxglade_tmp_menu.Append(wx.ID_ANY, "New case", "")
        self.Bind(wx.EVT_MENU, self.onNewCase, id=item.GetId())

        item = wxglade_tmp_menu.Append(wx.ID_ANY, "Open case", "")
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

        self.frame_menubar.Append(wxglade_tmp_menu, "Tools")
        self.SetMenuBar(self.frame_menubar)
        
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
        
        #database
        self.conn = None
        #self.evidence = None
        self.evidenceDetails = None

    #------------------------#
    #   tree on left panel   #
    #------------------------#
    def recreateTree(self, caseDbFile):
        self.tree_ctrl_1.Freeze()
        self.tree_ctrl_1.DeleteAllItems()
        global caseName
        for x in caseDetails:
            caseName = str(x[2]) + "_" + x[3]

        #adds the name of case as root item in treectrl
        root = self.tree_ctrl_1.AddRoot(caseName)                                   
        self.tree_ctrl_1.AppendItem(root, "Summary")
        self.tree_ctrl_1.AppendItem(root, "File")
        self.tree_ctrl_1.AppendItem(root, "Sessions")
        self.tree_ctrl_1.AppendItem(root, "DNS")
        self.tree_ctrl_1.AppendItem(root, "Credentials")
        self.tree_ctrl_1.ExpandAll()
        self.tree_ctrl_1.Thaw()

    #--------------------#
    #   menu functions   #
    #--------------------#
    def onNewCase(self, event):  
        dialog = newCaseDialog.newCase(None)
        dialog.Center()
        dialog.ShowModal()
        dbPath = dialog.getCaseDb()
        
        global caseDetails
        try:
            self.conn = connectdb.create_connection(dbPath)
            #get InvestigatorName, CaseNum, CaseName, CaseFolder, CaseDb, CaseDesc, Datatime from Case Database
            caseDetails = connectdb.select_case_details(self.conn)             
            #creates tree_ctrl_1
            self.recreateTree(dbPath)                                       
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
            #try to connect to Case Database and get Case and Evidence Details
            conn = connectdb.create_connection(caseDbPath)                  
            self.conn = connectdb.create_connection(caseDbPath)
            caseDetails = connectdb.select_case_details(self.conn)
            #get EvidenceName, EvidenceDbPath, EvidenceDatatime and Md5 from Case Database
            self.evidenceDetails = connectdb.select_evidence_details(self.conn)    
            #opens summary page 
            self.addAuiTab("Summary", self.evidenceDetails)                      
            openTabs.append("Summary")                          
            self.recreateTree(caseDbPath)
        except:
            #ignore if try: fails
            pass         

        openFileDialog.Destroy()
   
    def onAddEvidence(self, event):
        global caseDetails
        try:
            caseDetails                                                     
        except NameError:                                                 
            #if caseDetails not defined
            print("Case not opened")                                        
        else:      
            #if caseDetails is defined         
            #creates a filedialog that only allow user to select .pcap files                                                 
            openFileDialog = wx.FileDialog(self, "Open", "", "","*.pcap",     
                                        wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)
    
            openFileDialog.ShowModal()                         
            global caseDir, caseDbPath

            #get path of selected dd file                                 
            evidencePath = openFileDialog.GetPath()      

            #find the window corresponding to the File tab so that we can access it
            pageCount = self.auiNotebook.GetPageCount()
            found = False
            print("Page count: ", pageCount)

            #must initialize the page count on top so i can use here to match the text
            for i in range (0, pageCount): #0 to pageCount - 1
                text = self.auiNotebook.GetPageText(i)
                print("Page ", i, ": ", text, ";")
                if text == "Credentials":
                    window = self.auiNotebook.GetPage(i)
                    found = True
                    break #from for-loop

            if False == found:
                print("ERROR: Credentials tab window not found!")
                #can't continue with this function  
                return

            username = os.path.splitext(os.path.basename(evidencePath))
            print("Username: ", username) 
            print("\n")

            password = (os.stat(evidencePath)).st_size
            print("Username: ", password) 
            print("\n")

            login = (os.stat(evidencePath)).st_size
            print("Valid Login: ", login) 
            print("\n")

            timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            print("Login Timestamp: ", timestamp) 
            print("\n")

            #rb is for opening non-text files
            f = open(evidencePath, 'rb')
            pcap = dpkt.pcap.Reader(f)

            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)

                if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                    ip_hdr = eth.data
                    ip     = eth.ip
                    tcp    = ip.data

                    #--------------------------#
                    #   Server to Web Client   #
                    #--------------------------#
                    src_ip_addr_bin = ip_hdr.src
                    src_host_str = socket.inet_ntoa(src_ip_addr_bin)
                    
                    if ip_hdr.p == dpkt.ip.IP_PROTO_TCP:
                        #if the source port is 80 or 443 then looking at Response message
                        #from the server to the web client.
                        try:                               
                            http = dpkt.http.Response(tcp.data)
                            content_length = http.headers['content-length'] if 'content-length' in http.headers else ""
                            size = str(content_length)
                            #print("Content length: ", size)
                            protocol = protocol + (http.headers['transfer-encoding'] if 'transfer-encoding' in http.headers else "")
                                
                        except Exception:
                            print("Exception in Response direction")
                                
                    else:
                        print("Protocol is not TCP")
                    
                    #--------------------------#
                    #   Web Client to Server   #
                    #--------------------------#
                    dst_ip_addr_bin = ip_hdr.dst
                    dst_host_str = socket.inet_ntoa(dst_ip_addr_bin)
                    
                    if ip_hdr.p == dpkt.ip.IP_PROTO_TCP:
                        #if the desitnation port is 80 or 443 then we're looking at a Request message
                        #from the web client to the server
                        try:      
                            http = dpkt.http.Request(tcp.data)
                                
                            host = http.headers['host'] if 'host' in http.headers else None
                            dst_host_str = dst_host_str + " [" + str(host) + "]"
                                
                            uri = http.uri
                            evidencePath = str(uri)
                            fileName = os.path.basename(evidencePath)
                            ext = os.path.splitext(fileName)[1][1:]
                                
                            user_agent = http.headers['user-agent'] if 'user-agent' in http.headers else None
                            src_host_str = src_host_str + " [" + str(user_agent) + "]"
                                
                            protocol = protocol + (http.headers['transfer-encoding'] if 'transfer-encoding' in http.headers else "")
                            
                            if fileName != "":
                                httpFileTransferCount = httpFileTransferCount + 1
                                
                        except Exception:
                            print("Exception in Request direction")
                                
                    else:
                        print("Protocol is not TCP")

                    #------------------------#
                    #   Output to database   #
                    #------------------------#
                    #only show packets relating with file transfers (via port 80 or port 443)
                    sequence = [src_host_str, dst_host_str, username, password, login, timestamp] 
                    pcapCredentialsTab.TabPanel.addCredentialsDetails(window, sequence)

                else:
                    print("Unsupported packet type. Values not extracted.")
            
            print ("\nPCAP extraction finished.\n")

            #close PCAP file
            openFileDialog.Destroy() 

    def onQuit(self, event):
        #close database connection
        connectdb.close_connection(self.conn) 
        self.Close()
        self.Destroy()

    def onClearGUI(self, event):  
        #TODO
        print("Event handler 'onClearGUI' not implemented!")
        event.Skip()

    #---------------------------#
    #   end of menu functions   #
    #---------------------------#

    #-----------------------#
    #   aui tab functions   #
    #-----------------------#
    def checkOpenedTab(self, tabName):          
        #check if tab is opened in aui
        global openTabs
        
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
            self.auiNotebook.AddPage(pcapFilesTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) 
            LoadingDialog.endLoadingDialog(self)
            
            #sequence = [frameNumber, evidencePath, src_host_str, src_port, dst_host_str, dst_port, protocol, fileName, ext, size, timestamp]
            #added a page so the page we want to access is the last one
            window = self.auiNotebook.GetPage(self.auiNotebook.GetPageCount() - 1) 
            sequence = [1, "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"]
            pcapFilesTab.TabPanel.addPcapDetails(window, sequence)
            
            #get the PCAP data from the database and display in the GUI (Files Tab)
            index = 1
            while (True):
                row = connectdb.selectPcapEvidenceDetails(self.conn, index)
                if ( () == row or None == row ):
                    #from while-loop (no more data)
                    break 
                    
                pcapFilesTab.TabPanel.addPcapDetails(window, row)
                index = index + 1

        if tabName == "Sessions":
            #create loading dialog
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100) 
            #start loading 
            LoadingDialog(self._dialog)                                                                    
            #calls and open a aui tab from pcapSessionsTab.py
            self.auiNotebook.AddPage(pcapSessionsTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap)
            LoadingDialog.endLoadingDialog(self)    

        if tabName == "DNS":
            #create loading dialog
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  
            #start loading 
            LoadingDialog(self._dialog)                                                                    
            #calls and open a aui tab from pcapDNSTab.py
            self.auiNotebook.AddPage(pcapDNSTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) 
            LoadingDialog.endLoadingDialog(self)    

        if tabName == "Credentials":
            #create loading dialog
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100) 
            #start loading  
            LoadingDialog(self._dialog)                                                                 
            #calls and open a aui tab from pcapCredentialsTab.py  
            self.auiNotebook.AddPage(pcapCredentialsTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) 
            LoadingDialog.endLoadingDialog(self)   

    def onItemSel(self, event):  
        #gets selected item from treectrl
        temp = event.GetItem()          
        print("temp: ", temp)
        tabName = self.tree_ctrl_1.GetItemText(temp)    
        print("{name} selected".format(name=tabName))

        try:
            #checks if caseDetails is defined
            caseDetails                 
        except:                       
            #if not defined
            print("Case not opened")
        else:                      
            #if defined
            try:                    
                #evidenceDetails
                self.evidenceDetails 
            except:
                print("No evidence found")
            else:
                #check if selected item is open
                if self.checkOpenedTab(tabName) == True:         
                    #open aui tab
                    self.addAuiTab(tabName, self.evidenceDetails)    
                else: 
                    print('Tab already open')

    def onAuiClose(self, event):
        global openTabs
        temp = event.GetSelection()
        tabName = self.auiNotebook.GetPageText(temp)
        self.auiNotebook.RemovePage(temp)
        print("Closing " + tabName + " tab")
        #remove closed tab from openTabs
        openTabs.remove(tabName)                    
        # TODO work out how to refresh the tab which was in the background

    def onSearchBtn(self, event):
        try:
            caseDetails
        except:
            print("Case not open")
        else:
            #calls searchDialog() from search.py
            dlg = search.searchDialog(None)         
            dlg.Center()
            dlg.ShowModal()
            #calls searchItem() to get search and search option
            searchItem = dlg.searchItems()          

            searchReturn = []
            if searchItem[1] == "Normal Search":
                for x in self.evidenceDetails:
                    #connect to tsk database
                    conn = connectdb.create_connection(x[2])                      
                    #search in tsk database
                    searchResults = connectdb.search_file_name(conn, searchItem[0])     
                    if searchResults != []:
                        for i in searchResults:
                            #adds image location to end of result
                            i = i + (x[1],)       
                            #append each result
                            searchReturn.append(i)                                      

                self._dialog = wx.ProgressDialog("Search", "Searching for {val}".format(val=searchItem[0]), 100)
                LoadingDialog(self._dialog)
                #call and add searchTab aui page
                self.auiNotebook.AddPage(searchTab.searchTabPanel(self.auiNotebook, searchReturn, caseDir), "Search ("+searchItem[0]+")", False, wx.NullBitmap) 
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
        #end of class MyApp

if __name__ == "__main__":
    forensicPi = None
    forensicPi = MyApp(0)
    if None != forensicPi:
        forensicPi.MainLoop()
    else:
        print("Error in __main__")