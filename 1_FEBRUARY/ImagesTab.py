#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# generated by wxGlade 0.8.3 on Thu Sep  6 18:54:27 2018

import wx
import datetime
from datetime import timedelta
from pathlib import Path
import database as connectdb
import subprocess
import os
import re
# begin wxGlade: dependencies
# end wxGlade

# begin wxGlade: extracode
# end wxGlade


class TabPanel(wx.Panel):
    def __init__(self, parent, name, evidenceDetails, caseDir, caseDbPath):
        # begin wxGlade: MyFrame.__init__
        wx.Panel.__init__(self, parent=parent, id=wx.ID_ANY)

        self.notebookTab = " "
        
        self.panel_1 = wx.Panel(self, wx.ID_ANY)
        self.window_1 = wx.SplitterWindow(self.panel_1, wx.ID_ANY)
        self.window_top_pane = wx.Panel(self.window_1, wx.ID_ANY)
        self.notebook = wx.Notebook(self.window_top_pane, wx.ID_ANY)

        self.notebook_pane_Hex = wx.Panel(self.notebook, wx.ID_ANY)
        self.text_ctrl_hex = wx.TextCtrl(self.notebook_pane_Hex, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)

        self.notebook_pane_String = wx.Panel(self.notebook, wx.ID_ANY)
        self.text_ctrl_String = wx.TextCtrl(self.notebook_pane_String, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)

        #bitmap will return error type 50 if file not found/cannot be read
        self.notebook_pane_Image = wx.Panel(self.notebook, wx.ID_ANY)
        self.bitmap = wx.StaticBitmap(self.notebook_pane_Image, wx.ID_ANY)

        self.notebook_pane_IndexText = wx.Panel(self.notebook, wx.ID_ANY)
        self.text_ctrl_IndexText = wx.TextCtrl(self.notebook_pane_IndexText, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)

        self.notebook_pane_FileMetadata = wx.Panel(self.notebook, wx.ID_ANY)
        self.text_ctrl_FileMetadata = wx.TextCtrl(self.notebook_pane_FileMetadata, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.window_bottom_pane = wx.Panel(self.window_1, wx.ID_ANY)
        self.list_ctrl = wx.ListCtrl(self.window_bottom_pane, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT | wx.LC_VRULES)

        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.onListItemSel, self.list_ctrl)
        self.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, self.onNotebookPageChange, self.notebook)

        self.popupmenu = wx.Menu()
        rightClickItem = self.popupmenu.Append(-1, "View in file directory")
        self.Bind(wx.EVT_MENU, self.onViewDir, id=rightClickItem.GetId())
        self.popupmenu.AppendSeparator()
        rightClickItem = self.popupmenu.Append(-1, "Extract to")
        self.Bind(wx.EVT_MENU, self.onExtract, id=rightClickItem.GetId())
        self.popupmenu.AppendSeparator()
        
        self.Bind(wx.EVT_LIST_ITEM_RIGHT_CLICK, self.onRightClick, self.list_ctrl)

        global caseDirectory, evidenceInfo, caseDb, auiPageName
        caseDirectory = caseDir
        evidenceInfo = evidenceDetails
        caseDb = caseDbPath
        auiPageName = name

        self.__set_properties()
        self.__do_layout()
        # end wxGlade


    def __set_properties(self):
        # begin wxGlade: MyFrame.__set_properties
        #self.SetTitle("frame")
        self.list_ctrl.AppendColumn("Filename", format=wx.LIST_FORMAT_LEFT, width=200)
        self.list_ctrl.AppendColumn("Last File Change", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Date/Time Created", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Last Accessed Time", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Last Modified Time", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Uid", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Gid", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("MD5", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Size", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Parent Path", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Extension", format=wx.LIST_FORMAT_LEFT, width=-1)

        if auiPageName == "Bookmarks":                                                      
            self.list_ctrl.AppendColumn("Image", format=wx.LIST_FORMAT_LEFT, width=-1)
            self.loadBookmarks()
            rightClickItem = self.popupmenu.Append(-1, "Remove bookmark")
            self.Bind(wx.EVT_MENU, self.onRemoveBookmark, id=rightClickItem.GetId())
        else:
            #rightClickMenu
            rightClickItem = self.popupmenu.Append(-1, "Bookmark item")
            self.Bind(wx.EVT_MENU, self.OnBookmarkSelect, rightClickItem)

        self.window_1.SetMinimumPaneSize(20)

        #lookup the database and appends items returned to listctrl using load_quried_files()
        for x in evidenceInfo:                                      
            if auiPageName == "Images":
                self.load_queried_files(self.list_ctrl, "'png' OR extension = 'jpg' OR extension = 'jpeg' OR extension = 'exif' OR extension = 'tiff' OR extension = 'gif' OR extension ='bmp' OR extension = 'bpg' ", x[2])
        #end wxGlade


    def __do_layout(self):
        # begin wxGlade: MyFrame.__do_layout
        sizer_3 = wx.BoxSizer(wx.VERTICAL)
        sizer_4 = wx.BoxSizer(wx.VERTICAL)
        sizer_6 = wx.BoxSizer(wx.VERTICAL)
        sizer_5 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_12 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_11 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_10 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_9 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_8 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_7 = wx.BoxSizer(wx.HORIZONTAL)

        sizer_7.Add(self.text_ctrl_hex, 1, wx.ALL | wx.EXPAND, 0)
        self.notebook_pane_Hex.SetSizer(sizer_7)
        sizer_8.Add(self.text_ctrl_String, 1, wx.ALL | wx.EXPAND, 0)
        self.notebook_pane_String.SetSizer(sizer_8)
        sizer_12.Add(self.bitmap, 1, wx.ALL | wx.EXPAND, 0)
        self.notebook_pane_Image.SetSizer(sizer_12)
        sizer_9.Add(self.text_ctrl_IndexText, 1, wx.ALL | wx.EXPAND, 0)
        self.notebook_pane_IndexText.SetSizer(sizer_9)
        sizer_11.Add(self.text_ctrl_FileMetadata, 1, wx.ALL | wx.EXPAND, 0)
        self.notebook_pane_FileMetadata.SetSizer(sizer_11)

        self.notebook.AddPage(self.notebook_pane_Hex, "Hex")
        self.notebook.AddPage(self.notebook_pane_String, "Strings")
        self.notebook.AddPage(self.notebook_pane_Image, "Image")
        self.notebook.AddPage(self.notebook_pane_IndexText, "Index Text")
        self.notebook.AddPage(self.notebook_pane_FileMetadata, "File metadata")

        sizer_5.Add(self.notebook, 1, wx.EXPAND, 0)
        self.window_top_pane.SetSizer(sizer_5)
        sizer_6.Add(self.list_ctrl, 1, wx.ALL | wx.EXPAND, 5)
        self.window_bottom_pane.SetSizer(sizer_6)
        self.window_1.SplitHorizontally(self.window_top_pane, self.window_bottom_pane)
        sizer_4.Add(self.window_1, 1, wx.EXPAND, 0)
        self.panel_1.SetSizer(sizer_4)
        sizer_3.Add(self.panel_1, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_3)
        self.Layout()


    def onNotebookPageChange(self, event):
        temp = event.GetSelection()
        self.notebookTab = self.notebook.GetPageText(temp)


    def onListItemSel(self, event):
        #get selected item
        sel = self.list_ctrl.GetFocusedItem()                   
        #get filename of selected item from col 0
        fileName = self.list_ctrl.GetItemText(sel, 0)           
        #get parent path of selected item from col 9
        fileParentPath = self.list_ctrl.GetItemText(sel, 9)     
        filePath = fileParentPath + fileName


        if self.notebookTab == " " or self.notebookTab == "Hex":
            #loop through the directories in /Extracted/
            for x in evidenceInfo:                                                                                                              
                #if file exist 
                if Path(caseDirectory+"/Extracted/"+x[1]+filePath).is_file():                                                                   
                    #get hexdump
                    temp = subprocess.Popen(["xxd", caseDirectory+"/Extracted/"+x[1]+filePath], stdout=subprocess.PIPE).communicate()[0]        
                    #display in txtctrl
                    self.text_ctrl_hex.SetValue(temp)                                                                                           
        
        elif self.notebookTab == "Strings":
            for x in evidenceInfo:
                #adds '\' infront of ' ', '$', '()' and '[]' to escape spaces in filepaths
                fullFilePath = caseDirectory+"/Extracted/"+x[1]+filePath        
                regexfullFilePath = re.sub(r'[ ]', '\ ', fullFilePath)
                regexfullFilePath = re.sub(r'\$', '\$', regexfullFilePath)
                regexfullFilePath = re.sub(r'\(', '\(', regexfullFilePath)
                regexfullFilePath = re.sub(r'\)', '\)', regexfullFilePath)
                regexfullFilePath = re.sub(r'\[', '\[', regexfullFilePath)
                regexfullFilePath = re.sub(r'\]', '\]', regexfullFilePath)
                if Path(fullFilePath).is_file():
                    command = "xxd {path} | awk -F '{reg}' '{col}'".format(path=regexfullFilePath, reg="  ", col="{print $2 $3 $4}")
                    #gets last column of hexdump
                    process = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)                           
                    stdout, stderr = process.communicate()
                    output = stdout.strip().decode()
                    _error = stderr.strip().decode()
                    if _error == '':
                        #removes '.', '-' and '=' from hexdump
                        regex = re.sub(r'[.]{2,}|[-]{2,}|[=]{2,}', " ", output)                                                                
                        #display in txtctrl
                        self.text_ctrl_String.SetValue(regex)                                                                                   

        elif self.notebookTab == "File metadata":
            for x in evidenceInfo:
                if Path(caseDirectory+"/Extracted/"+x[1]+filePath).is_file():
                    #get exif data of selected file
                    temp = subprocess.Popen(["exiftool", caseDirectory+"/Extracted/"+x[1]+filePath], stdout=subprocess.PIPE).communicate()[0]   
                    self.text_ctrl_FileMetadata.SetValue(temp)                                  

        elif self.notebookTab == "Image":
            for x in evidenceInfo:
                if Path(caseDirectory+"/Extracted/"+x[1]+filePath).is_file():
                    #display image using bitmap if file extension matches
                    if fileName.lower().endswith(('.png', '.jpg', '.jpeg', '.exif', '.tiff', '.gif', '.bmp', '.bpg')):                          
                        self.bitmap.SetBitmap(wx.Bitmap(caseDirectory+"/Extracted/"+x[1]+filePath, wx.BITMAP_TYPE_ANY))                         
                        

        elif self.notebookTab == "Index Text":
            for x in evidenceInfo:
                if Path(caseDirectory+"/Extracted/"+x[1]+filePath).is_file():
                    if fileName.lower().endswith(('.txt', '.rtf')):
                        #read selected file if extension match
                        f = open(caseDirectory+"/Extracted/"+x[1]+filePath, "r")                                                                
                        #display in txtctrl
                        self.text_ctrl_IndexText.SetValue(f.read())                                                                             
                        f.close()

                        
    def load_queried_files(self, list_ctrl, extension, dbFilePath):
        try:
            #connect to tsk database
            conn = connectdb.create_connection(dbFilePath)                                     
            #returns with files of defined extensions
            queriedFileInfo = connectdb.select_queried_files(conn, extension)                  

            for x in queriedFileInfo:
                if x[2] != "NULL":
                    #convert seconds to datetime
                    ctime = datetime.datetime(1970, 1, 1) + timedelta(seconds=x[2])            
                else:
                    ctime = x[2]
                    
                if x[3] != "NULL":
                    crtime = datetime.datetime(1970, 1, 1) + timedelta(seconds=x[3])
                else:
                    crtime = x[3]

                if x[4] != "NULL":
                    atime = datetime.datetime(1970, 1, 1) + timedelta(seconds=x[4])
                else:
                    atime = x[4]

                if x[5] != "NULL":
                    mtime = datetime.datetime(1970, 1, 1) + timedelta(seconds=x[5])
                else:
                    mtime = x[5]
                #append to listctrl
                self.list_ctrl.Append((x[0], ctime, crtime, atime, mtime, x[6], x[7], x[8], x[1], x[9], x[10])) 
    
        except:
            pass


    def loadBookmarks(self):
        #connect to case database
        conn = connectdb.create_connection(caseDb)              
        #lookup bookmarks table
        bookmarkQuery = connectdb.selectBookmarks(conn)         
        for x in bookmarkQuery:
            #apped to listctrl
            self.list_ctrl.Append((x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11])) 


    def onRightClick(self, event):
        #show menu on right click
        self.window_bottom_pane.PopupMenu(self.popupmenu)       
        

    def OnBookmarkSelect(self, event):
        #item = self.popupmenu.FindItemById(event.GetId())      
        #get selected item 
        sel = self.list_ctrl.GetFocusedItem()                   
        fileName = self.list_ctrl.GetItemText(sel, 0)       
        parentPath = self.list_ctrl.GetItemText(sel, 9)
        filePath = parentPath+fileName
        #connect to case database
        conn = connectdb.create_connection(caseDb)              
        #check if bookmarks table has selected item
        isUnique = connectdb.chkUniqueBookmark(conn, fileName, parentPath)  
        if isUnique == True:
            _rows = []
            for x in evidenceInfo:
                _image = ''
                if Path(caseDirectory+"/Extracted/"+x[1]+filePath).is_file():
                    _image = x[1]       

                selRow = []
                for x in range(0,11):
                    temp = self.list_ctrl.GetItemText(sel, x)   
                    #adds each column of selected row into selRow
                    selRow.append(temp)                         
                #adds the image directory name to selRow
                selRow.append(_image)                           
                #add selRow to _rows
                _rows.append(selRow)                            

            with conn:
                for x in _rows:     
                    if x[11] != '':
                        #insert _rows to bookmarks table in case database
                        _fileInfo = (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11])  
                        connectdb.insertBookmarks(conn, _fileInfo)
        else:
            wx.MessageBox("Selected item already exist in Bookmarks")
        

    def onRemoveBookmark(self, event):
        #item = self.popupmenu.FindItemById(event.GetId())
        sel = self.list_ctrl.GetFocusedItem()
        fileName = self.list_ctrl.GetItemText(sel, 0)
        parentPath = self.list_ctrl.GetItemText(sel, 9)

        conn = connectdb.create_connection(caseDb)
        with conn:
            connectdb.deleteBookmarkItem(conn, fileName, parentPath)
            self.list_ctrl.DeleteItem(sel)
        

    def onViewDir(self, event):
        #item = self.popupmenu.FindItemById(event.GetId())
        sel = self.list_ctrl.GetFocusedItem()
        fileName = self.list_ctrl.GetItemText(sel, 0)
        parentPath = self.list_ctrl.GetItemText(sel, 9)
        filePath = parentPath+fileName

        _fullPath = ""
        if auiPageName == "Bookmarks":
            image = self.list_ctrl.GetItemText(sel, 11)
            _fullPath = caseDirectory+"/Extracted/"+image+parentPath
        else:
            for x in evidenceInfo:
                if Path(caseDirectory+"/Extracted/"+x[1]+filePath).is_file():
                    _fullPath = caseDirectory+"/Extracted/"+x[1]+parentPath

        #subprocess.Popen(["open", _fullPath]) #mac
        #open the directory of selected file in pcmanfm
        subprocess.Popen(["pcmanfm", _fullPath]) #rasp 


    def onExtract(self, event):
        sel = self.list_ctrl.GetFocusedItem()
        selFileName = self.list_ctrl.GetItemText(sel, 0)
        selParentPath = self.list_ctrl.GetItemText(sel, 9)
        fileSource = selParentPath+selFileName
        #opens filedialog to ask user for file save location
        extractFileDialog = wx.FileDialog(self, "Extract to...", "", selFileName, "", wx.FD_SAVE|wx.FD_OVERWRITE_PROMPT)    
        extractFileDialog.ShowModal()                         
        #get file save path        
        extractPath = extractFileDialog.GetPath()                  
        fileName = os.path.basename(extractPath)

        _fullPath = ""
        if auiPageName == "Bookmarks":
            image = self.list_ctrl.GetItemText(sel, 11)
            _fullPath = caseDirectory+"/Extracted/"+image+fileSource
        else:
            for x in evidenceInfo:
                if Path(caseDirectory+"/Extracted/"+x[1]+fileSource).is_file():
                    _fullPath = caseDirectory+"/Extracted/"+x[1]+fileSource
        extractFileDialog.Destroy()
        if _fullPath != "":
            #copy selected file from /Extracted/ to file save path
            subprocess.Popen(["cp", _fullPath, extractPath])                                                            
            print("extract from {fileSource} to {extractPath}".format(fileSource=_fullPath, extractPath=extractPath))
        # end wxGlade


# end of class MyFrame

# class TabPanel(wx.App):
#     def OnInit(self):
#         self.frame = MyFrame(None, wx.ID_ANY, "")
#         self.SetTopWindow(self.frame)
#         self.frame.Show()
#         return True

# # end of class TabPanel

# if __name__ == "__main__":
#     app = TabPanel(0)
#     app.MainLoop()
