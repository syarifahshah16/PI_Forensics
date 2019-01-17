import wx
import datetime
from datetime import timedelta
from pathlib import Path
import connectdb
import subprocess
import os      
import re
import sys
import wx.dataview

class CredTabPanel(wx.Panel):
    def __init__(self, parent, caseDetails, evidenceDetails):
        # begin wxGlade: MyDialog.__init__
        wx.Panel.__init__(self, parent=parent)
        self.cred = wx.dataview.DataViewListCtrl(self, wx.ID_ANY)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.cred.SetMinSize((800, 800))
        self.cred.AppendTextColumn("Frame No", width=100)
        self.cred.AppendTextColumn("Client", width=200)
        self.cred.AppendTextColumn("Server", width=150)
        #self.cred.AppendTextColumn("Protocol", width=150)
        #self.cred.AppendTextColumn("Username", width=150)
        #self.cred.AppendTextColumn("Password", width=150)
        #self.cred.AppendTextColumn("Valid Login", width=150)
        #self.cred.AppendTextColumn("Online Timestamp", width=150)
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_2 = wx.BoxSizer(wx.VERTICAL)
        sizer_2.Add(self.cred, 0, wx.EXPAND, 0)
        self.SetSizer(sizer_2)
        sizer_2.Fit(self)
        self.Layout()
        # end wxGlade

    def addCredDetails(self, credrow):
        self.cred.AppendItem(credrow)