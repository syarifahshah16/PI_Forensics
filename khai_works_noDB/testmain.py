#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# generated by wxGlade 0.8.3 on Fri Aug 31 03:44:54 2018
#

import wx
import wx.aui
import os
import random
import SummaryTab, pcapFilesTab, NewCaseDialog, mainmenu, search, searchTab, pcapSessionsTab, pcapDNSTab         
import connectdb
import subprocess
import sqlite3
from sqlite3 import Error
from pathlib import Path
import datetime, time
import re
from threading import Thread

# relating to extraction of values from PCAP file
# see https://pypi.org/project/dpkt/
import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.arp import ARP
import datetime, time

import struct
import socket



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
        
        # Menu Bar
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
        item = wxglade_tmp_menu.Append(wx.ID_ANY, "Delete Data", "")
        self.Bind(wx.EVT_MENU, self.onDeleteData, id=item.GetId())
        
        """item = wxglade_tmp_menu.Append(wx.ID_ANY, "Network pcap files", "")
        self.Bind(wx.EVT_MENU, self.onSelNetworkPcapFiles, id=item.GetId())"""

        self.frame_menubar.Append(wxglade_tmp_menu, "Tools")
        self.SetMenuBar(self.frame_menubar)
        # Menu Bar end

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

    def recreateTree(self, caseDbFile):
        self.tree_ctrl_1.Freeze()
        self.tree_ctrl_1.DeleteAllItems()
        global caseName
        for x in caseDetails:
            caseName = str(x[2]) + "_" + x[3]

        root = self.tree_ctrl_1.AddRoot(caseName)                                   #adds the name of case as root item in treectrl
        self.tree_ctrl_1.AppendItem(root, "Summary")
       
        conn = connectdb.create_connection(caseDbFile)                              #connect to case database
        evidenceInfo = connectdb.select_evidence_details(conn)                      #get evidenceName, EvidenceDbPath EvidenceDatetime and Md5 from case database
                                                                                    #EvidenceDbPath = path to tsk database generated when onAddEvidence is called
        self.tree_ctrl_1.AppendItem(root, "Bookmarks")
        self.tree_ctrl_1.AppendItem(root, "File")
        self.tree_ctrl_1.AppendItem(root, "Images")
        self.tree_ctrl_1.AppendItem(root, "Sessions")
        self.tree_ctrl_1.AppendItem(root, "DNS")
        self.tree_ctrl_1.AppendItem(root, "Credentials")

        self.tree_ctrl_1.ExpandAll()
        self.tree_ctrl_1.Thaw()

    #menu functions
    def onNewCase(self, event):  
        dialog = NewCaseDialog.newCase(None)
        dialog.Center()
        dialog.ShowModal()
        dbPath = dialog.getCaseDb()
        
        global caseDetails
        try:
            conn = connectdb.create_connection(dbPath)                      #connects to new case database
            caseDetails = connectdb.select_case_details(conn)               #get InvestigatorName, CaseNum, CaseName, CaseFolder, CaseDb, CaseDesc, Datatime from case database
            self.recreateTree(dbPath)                                       #creates treectrl
        except:
            pass 
        
        dialog.Destroy()
        

    def onOpenCase(self, event):  
        openFileDialog = wx.FileDialog(self, "Open", "", "","*.db",         #creates a filedialog that only allow user to select .db files
                                       wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) 
 
        openFileDialog.ShowModal()                      
        global caseDbPath
        caseDbPath  = openFileDialog.GetPath()                              #get path selected in filedialog
        
        global caseDetails, evidenceDetails
        try:
            conn = connectdb.create_connection(caseDbPath)                  #try to connect to case database and get case and evidence details
            caseDetails = connectdb.select_case_details(conn)
            evidenceDetails = connectdb.select_evidence_details(conn)       #get EvidenceName, EvidenceDbPath, EvidenceDatatime and Md5 from case database
            self.addAuiTab("Summary", evidenceDetails)                      #opens summary page 
            openTabs.append("Summary")                          
            self.recreateTree(caseDbPath)
        except:
            pass                                                            #ignore if try: fails
        openFileDialog.Destroy()



    def ip2int(addr):
        """relating to extraction of values from PCAP file"""
        return struct.unpack("!I", socket.inet_aton(addr))[0]   


   
    def onAddEvidence(self, event):
        """relating to extraction of values from PCAP file"""
        global caseDetails
        try:
            caseDetails                                                     
        except NameError:                                                   #if caseDetails not defined
            print("Case not opened")                                        
        else:                                                               #if caseDetails is defined
            openFileDialog = wx.FileDialog(self, "Open", "", "","*.pcap",     #creates a filedialog that only allow user to select .pcap files 
                                        wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)
    
            openFileDialog.ShowModal()                         
            global caseDir, caseDbPath

            #evidencePath includes filename                                   
            evidencePath = openFileDialog.GetPath()     

            # Find the window corresponding to the File tab so that we can
            # access it
            pageCount = self.auiNotebook.GetPageCount()
            found = False
            print("Page count: ", pageCount)
            #must initialize the page count on top so i can use here to match the text
            for i in range (0, pageCount): # 0 to pageCount - 1
                text = self.auiNotebook.GetPageText(i)
                print("Page ", i, ": ", text, ";")
                if text == "Sessions":
                    window = self.auiNotebook.GetPage(i)
                    found = True
                    break # from for-loop

            if False == found:
                print("ERROR: Sessions tab window not found!")
                return # can't continue with this function                    
            
            #rb is for opening non-text files
            f = open(evidencePath, 'rb')
            pcap = dpkt.pcap.Reader(f)

            # For each packet in the pcap process the contents
            identifier = 0
            for timestamp, buf in pcap:

                """# Print out the timestamp in UTC
                print ("Timestamp" , str(datetime.datetime.utcfromtimestamp(timestamp)))"""
                    
                identifier = identifier + 1
                Packet  = identifier

                # Unpack the Ethernet frame (mac src/dst, ethertype)
                eth = dpkt.ethernet.Ethernet(buf)
                """print ('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)"""

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

                sequence = [str(Packet), str(datetime.datetime.utcfromtimestamp(timestamp)), str(src_ip), str(dst_ip), str(request)]
                pcapSessionsTab.TabPanel.addSessionsDetails(window, sequence)

            else:
                print("Unsupported packet type. Values not extracted.")
            
            print ("\nPCAP extraction finished.\n")
            print ("HTTP file transfer count: ", httpFileTransferCount)

            openFileDialog.Destroy() # close PCAP file
            

    def onQuit(self, event):  
        self.Close()
        self.Destroy()

    def onClearGUI(self, event):  
        print("Event handler 'onClearGUI' not implemented!")
        event.Skip()

    def onDeleteData(self, event):  
        print("Event handler 'onDeleteData' not implemented!")
        event.Skip()

    #end of menu functions

    #aui tab functions
    def checkOpenedTab(self, tabName):                     #check if tab is opened in aui
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
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  #create loading dialog
            LoadingDialog(self._dialog)                                                                    #start loading 
            self.auiNotebook.AddPage(FileTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) #calls and open a aui tab from DeletedFilesTab.py
            LoadingDialog.endLoadingDialog(self)    

        if tabName == "Images":
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  #create loading dialog
            LoadingDialog(self._dialog)                                                                    #start loading 
            self.auiNotebook.AddPage(ImagesTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) #calls and open a aui tab from DeletedFilesTab.py
            LoadingDialog.endLoadingDialog(self)    

        if tabName == "Sessions":
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  #create loading dialog
            LoadingDialog(self._dialog)                                                                    #start loading 
            self.auiNotebook.AddPage(pcapSessionsTab.TabPanel(self.auiNotebook, caseDir), tabName, False, wx.NullBitmap) #calls and open a aui tab from DeletedFilesTab.py
            LoadingDialog.endLoadingDialog(self)    

        if tabName == "DNS":
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  #create loading dialog
            LoadingDialog(self._dialog)                                                                    #start loading 
            self.auiNotebook.AddPage(pcapDNSTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) #calls and open a aui tab from DeletedFilesTab.py
            LoadingDialog.endLoadingDialog(self)    

        if tabName == "Credentials":
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)  #create loading dialog
            LoadingDialog(self._dialog)                                                                    #start loading 
            self.auiNotebook.AddPage(CredentialsTab.TabPanel(self.auiNotebook, tabName, caseDir), tabName, False, wx.NullBitmap) #calls and open a aui tab from DeletedFilesTab.py
            LoadingDialog.endLoadingDialog(self)    

        if tabName == "Bookmarks":
            self._dialog = wx.ProgressDialog("Loading", "Loading {tabName}".format(tabName=tabName), 100)
            LoadingDialog(self._dialog)
            self.auiNotebook.AddPage(AnalyzedDataTab.TabPanel(self.auiNotebook, tabName, evidenceDetails, caseDir, caseDbPath), tabName, False, wx.NullBitmap)  #calls and open a aui tab from SummaryTab.py
            LoadingDialog.endLoadingDialog(self)


        # TODO un-comment-out the following code once evidence exists properly
        # note: commented-out to allow File tab to be tested before database code added
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
                
    def onItemSel(self, event):  
        temp = event.GetItem()          #gets selected item from treectrl
        tabName = self.tree_ctrl_1.GetItemText(temp)    
        print("{name} selected".format(name=tabName))
        
        if self.checkOpenedTab(tabName) == True:        #check if selected item is open 
            evidenceDetails = 0 # TODO remove this line when database code has been added
            self.addAuiTab(tabName, evidenceDetails)    #open aui tab
        else: 
            print('Tab already open')
            
        # TODO un-comment-out the following code (and remove lines above) once evidence exists properly
        # note: commented-out to allow File tab to be tested before database code added
        """try:
            caseDetails                 #checks if caseDetails is defined
        except:                         #if not defined
            print("Case not opened")
        else:                           #if defined
            try:                    
                evidenceDetails
            except:
                print("No evidence found")
            else:
                if self.checkOpenedTab(tabName) == True:        #check if selected item is open 
                    self.addAuiTab(tabName, evidenceDetails)    #open aui tab
                else: 
                    print('Tab already open')"""


    def onAuiClose(self, event):
        temp = event.GetSelection()
        tabName = self.auiNotebook.GetPageText(temp)
        #self.auiNotebook.RemovePage(temp)          #mac
        print("Closing " + tabName)
        openTabs.remove(tabName)                    #remove closed tab from openTabs
    
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
                for x in evidenceDetails:
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
        mainMenuDialog = mainmenu.dialog(None)
        mainMenuDialog.Center()
        mainMenuDialog.ShowModal()
        
        return True
    

# end of class MyApp

if __name__ == "__main__":
    forensicPi = MyApp(0)
    forensicPi.MainLoop()
