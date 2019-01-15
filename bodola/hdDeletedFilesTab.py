import wx
from pathlib import Path
import connectdb
import subprocess
import time
import re

# begin wxGlade: dependencies
# end wxGlade

# begin wxGlade: extracode
# end wxGlade

notebookTab = ''

class TabPanel(wx.Panel):
    def __init__(self, parent, name, caseDir):
        # begin wxGlade: MyFrame.__init__
        wx.Panel.__init__(self, parent=parent, id=wx.ID_ANY)
        
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

        self.__set_properties()
        self.__do_layout()

        global caseDirectory, auiPageName
        caseDirectory = caseDir
        auiPageName = name

        self.load_queried_files(self.list_ctrl)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: MyFrame.__set_properties
        self.list_ctrl.AppendColumn("File Type", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Status", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Inode", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Filename", format=wx.LIST_FORMAT_LEFT, width=200)
        self.list_ctrl.AppendColumn("Last File Change", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Date/Time Created", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Last Accessed Time", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Last Modified Time", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Uid", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Gid", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Size", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.list_ctrl.AppendColumn("Image", format=wx.LIST_FORMAT_LEFT, width=-1)
        self.window_1.SetMinimumPaneSize(20)
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
        global notebookTab
        notebookTab = self.notebook.GetPageText(temp)
        print("Page changed " + notebookTab)

    def onListItemSel(self, event):
        sel = self.list_ctrl.GetFocusedItem()
        filePath = self.list_ctrl.GetItemText(sel, col=3)                   #get filepath of selected item from col 3
        image = self.list_ctrl.GetItemText(sel, col=11)

        if notebookTab == "" or notebookTab == "Hex":
            temp = subprocess.Popen(["xxd", caseDirectory+"/Extracted/"+image+"/"+filePath], stdout=subprocess.PIPE).communicate()[0]   #get hexdump of selected file
            self.text_ctrl_hex.SetValue(temp)                               #display return in txtctrl

        elif notebookTab == "Strings":
            fullFilePath = caseDirectory+"/Extracted/"+image+"/"+filePath
            regexfullFilePath = re.sub(r'[ ]', '\ ', fullFilePath)          #adds '\' infront of ' ', '$', '()' and '[]' to escape spaces in filepaths
            regexfullFilePath = re.sub(r'\$', '\$', regexfullFilePath)
            regexfullFilePath = re.sub(r'\(', '\(', regexfullFilePath)
            regexfullFilePath = re.sub(r'\)', '\)', regexfullFilePath)
            regexfullFilePath = re.sub(r'\[', '\[', regexfullFilePath)
            regexfullFilePath = re.sub(r'\]', '\]', regexfullFilePath)
            if Path(fullFilePath).is_file():
                command = "xxd {path} | awk -F '{reg}' '{col}'".format(path=regexfullFilePath, reg="  ", col="{print $2 $3 $4}") #get last column of hexdump
                process = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                output = stdout.strip().decode()
                _error = stderr.strip().decode()
                if _error == '':
                    regex = re.sub(r'[.]{2,}|[-]{2,}|[=]{2,}', " ", output) #removes all '.', '-' and '=' from hexdump
                    self.text_ctrl_String.SetValue(regex)                   #display in txtctrl

        elif notebookTab == "File metadata":
            temp = subprocess.Popen(["exiftool", caseDirectory+"/Extracted/"+image+"/"+filePath], stdout=subprocess.PIPE).communicate()[0] #get exif data
            self.text_ctrl_FileMetadata.SetValue(temp)

        elif notebookTab == "Image":
            if fileName.lower().endswith(('.png', '.jpg', '.jpeg', '.exif', '.tiff', '.gif', '.bmp', '.bpg')):
                self.bitmap.SetBitmap(wx.Bitmap(caseDirectory+"/Extracted/"+image+"/"+filePath, wx.BITMAP_TYPE_ANY))                       #display image using bitmap if file extension matches

        elif notebookTab == "Index Text":
            if Path(caseDirectory+"/Extracted/"+image+"/"+filePath).is_file():
                if fileName.lower().endswith(('.txt', '.rtf')):                     
                    f = open(caseDirectory+"/Extracted/"+image+"/"+filePath, "r")   #read selected file
                    self.text_ctrl_IndexText.SetValue(f.read())                     #display in txtctrl
                    f.close()

    def load_queried_files(self, list_ctrl):
        if Path(caseDirectory+"/Evidence_Database/Deleted_Files.db").is_file():     #check if Deleted_Files.db exist
            deletedFilesDb = caseDirectory+"/Evidence_Database/Deleted_Files.db"
            conn = connectdb.create_connection(deletedFilesDb)                      #connect to Deleted_Files.db
            query = connectdb.select_deleted_files(conn)                            #get all deleted files
            
            for x in query:
                self.list_ctrl.Append((x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]))   #add all to listctrl
    
        #event.skip()
        # end wxGlade

# end of class MyFrame

# class TabPanel(wx.App):
#     def OnInit(self):
#         self.frame = MyFrame(None, wx.ID_ANY, "")
#         self.SetTopWindow(self.frame)
#         self.frame.Show()
#         return True
          # end of class TabPanel

# if __name__ == "__main__":
#     app = TabPanel(0)
#     app.MainLoop()
