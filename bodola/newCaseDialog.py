import wx
import os
from pathlib import Path
import connectdb
import datetime

# begin wxGlade: dependencies
# end wxGlade

# begin wxGlade: extracode
# end wxGlade

class newCase(wx.Dialog):
    def __init__(self, *args, **kwds):
        # begin wxGlade: MyDialog.__init__
        
        wx.Dialog.__init__(self, *args, **kwds)
        self.SetSize((500, 400))
        self.txtInvestigatorName = wx.TextCtrl(self, wx.ID_ANY, "")
        self.txtCaseNum = wx.TextCtrl(self, wx.ID_ANY, "")
        self.txtCaseName = wx.TextCtrl(self, wx.ID_ANY, "")
        self.txtCaseDb = wx.TextCtrl(self, wx.ID_ANY, "", style=wx.TE_READONLY)
        self.btnBrowse = wx.Button(self, wx.ID_ANY, "Browse")
        self.txtCaseFolder = wx.TextCtrl(self, wx.ID_ANY, "")
        self.txtCaseDescription = wx.TextCtrl(self, wx.ID_ANY, "", style=wx.TE_MULTILINE)
        self.btnConfirm = wx.Button(self, wx.ID_ANY, "Confirm")
        self.btnCancel = wx.Button(self, wx.ID_ANY, "Cancel")

        self.__set_properties()
        self.__do_layout()

        self.Bind(wx.EVT_BUTTON, self.onBtnBrowse, self.btnBrowse)
        self.Bind(wx.EVT_BUTTON, self.onConfirm, self.btnConfirm)
        self.Bind(wx.EVT_BUTTON, self.onClose, self.btnCancel)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.SetTitle("New Case")
        self.SetSize((500, 400))
        self.txtCaseDb.SetBackgroundColour(wx.Colour(240, 240, 240))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_1 = wx.BoxSizer(wx.VERTICAL)
        sizer_3 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_2 = wx.BoxSizer(wx.HORIZONTAL)
        grid_sizer_1 = wx.GridSizer(0, 3, 0, 0)
        label_1 = wx.StaticText(self, wx.ID_ANY, "Forensic Pi")
        label_1.SetFont(wx.Font(25, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, ""))
        sizer_1.Add(label_1, 0, wx.ALIGN_CENTER | wx.ALL, 5)
        label_2 = wx.StaticText(self, wx.ID_ANY, "Investigator name:")
        grid_sizer_1.Add(label_2, 0, wx.ALIGN_RIGHT | wx.ALL, 5)
        grid_sizer_1.Add(self.txtInvestigatorName, 0, wx.ALL | wx.EXPAND, 5)
        grid_sizer_1.Add((0, 0), 0, 0, 0)
        label_3 = wx.StaticText(self, wx.ID_ANY, "Case number:")
        grid_sizer_1.Add(label_3, 0, wx.ALIGN_RIGHT | wx.ALL, 5)
        grid_sizer_1.Add(self.txtCaseNum, 0, wx.ALL | wx.EXPAND, 5)
        grid_sizer_1.Add((0, 0), 0, 0, 0)
        label_4 = wx.StaticText(self, wx.ID_ANY, "Case name:")
        grid_sizer_1.Add(label_4, 0, wx.ALIGN_RIGHT | wx.ALL, 5)
        grid_sizer_1.Add(self.txtCaseName, 0, wx.ALL | wx.EXPAND, 5)
        grid_sizer_1.Add((0, 0), 0, 0, 0)
        label_5 = wx.StaticText(self, wx.ID_ANY, "Case folder:")
        grid_sizer_1.Add(label_5, 0, wx.ALIGN_RIGHT | wx.ALL, 5)
        grid_sizer_1.Add(self.txtCaseFolder, 0, wx.ALL | wx.EXPAND, 5)
        grid_sizer_1.Add(self.btnBrowse, 0, wx.LEFT | wx.RIGHT | wx.TOP, 9)
        label_6 = wx.StaticText(self, wx.ID_ANY, "Case database:")
        grid_sizer_1.Add(label_6, 0, wx.ALIGN_RIGHT | wx.ALL, 5)
        grid_sizer_1.Add(self.txtCaseDb, 0, wx.ALL | wx.EXPAND, 5)
        grid_sizer_1.Add((0, 0), 0, 0, 0)
        sizer_1.Add(grid_sizer_1, 1, wx.EXPAND, 0)
        label_7 = wx.StaticText(self, wx.ID_ANY, "Case description:")
        sizer_2.Add(label_7, 0, wx.ALIGN_RIGHT | wx.ALL, 5)
        sizer_2.Add(self.txtCaseDescription, 1, wx.ALL | wx.EXPAND, 5)
        sizer_1.Add(sizer_2, 1, wx.EXPAND, 0)
        sizer_3.Add(self.btnConfirm, 0, wx.ALL, 10)
        sizer_3.Add(self.btnCancel, 0, wx.ALL, 10)
        sizer_1.Add(sizer_3, 0, wx.ALIGN_CENTER, 0)
        self.SetSizer(sizer_1)
        self.Layout()
        # end wxGlade

    def onBtnBrowse(self, event):  # wxGlade: MyDialog.<event_handler>
        dirDialog = wx.DirDialog(self, 'Choose directory', '',
                    style=wx.DD_DEFAULT_STYLE)
 
        dirDialog.ShowModal()
        filePath = dirDialog.GetPath()
        dirName = os.path.dirname(filePath)
        caseName = self.txtCaseName.GetValue()
        caseNum = self.txtCaseNum.GetValue()

        self.txtCaseFolder.SetValue(dirName+"/"+caseNum+"_"+caseName)
        self.txtCaseDb.SetValue(dirName+"/"+caseNum+"_"+caseName+"/"+caseNum+"_"+caseName+".db")

        dirDialog.Destroy()

    def onConfirm(self, event):
        #create case dir
        dirPath = self.txtCaseFolder.GetValue()         #get case folder path
        casePath = Path(dirPath)
        if casePath.is_dir():                           #check if it exist
            print("dir exist")
        else:
            os.mkdir(dirPath)                           #create if does not

            #create case database
            dbFilePath = self.txtCaseDb.GetValue()      #get case database path
            my_file = Path(dbFilePath)

            #print(dbFilePath)
            if my_file.is_file():   #check if file exist
                print("file exist")
            else:
                conn = connectdb.create_connection(dbFilePath) #creates db file and connection if it does not exist
                caseInfoTable = "CREATE TABLE 'CaseInfo' ( 'CaseID' INTEGER PRIMARY KEY AUTOINCREMENT, 'InvestigatorName' TEXT, 'CaseNum' INTEGER, 'CaseName' TEXT, 'CaseFolder' TEXT, 'CaseDb' TEXT, 'CaseDesc' TEXT, 'Datetime' TEXT);"
                evidenceInfoTable = "CREATE TABLE 'EvidenceInfo' ('CaseID' INTEGER, 'EvidenceName' TEXT, 'EvidenceDbPath' TEXT, 'EvidenceDatetime' TEXT, 'Md5' TEXT);"
                bookmarksTable = "CREATE TABLE 'Bookmarks' ('fileName' TEXT, 'ctime' TEXT, 'crtime' TEXT, 'atime' TEXT, 'mtime' TEXT, 'uid' INTEGER, 'gid' INTEGER, 'md5' TEXT, 'size' INTEGER, 'parentPath' TEXT, 'extension' TEXT, 'image' TEXT);"
                connectdb.createTable(conn, caseInfoTable)      #creates CaseInfo table
                connectdb.createTable(conn, evidenceInfoTable)  #creates EvidenceInfo table
                connectdb.createTable(conn, bookmarksTable)     #creates Bookmarsk table
                connectdb.createPcapEvidenceTable(conn)

                #insert case details
                with conn:
                    caseDetails = (self.txtInvestigatorName.GetValue(), self.txtCaseNum.GetValue(), self.txtCaseName.GetValue(), self.txtCaseFolder.GetValue(), self.txtCaseDb.GetValue(), self.txtCaseDescription.GetValue(), datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    connectdb.insertCaseDetails(conn, caseDetails)  #insert case details to CaseInfo
            
        self.Close()

    def onClose(self, event):  # wxGlade: MyDialog.<event_handler>
        self.Close()

    def getCaseDb(self):
        return self.txtCaseDb.GetValue()

# end of class MyDialog

