import wx
import datetime
from datetime import timedelta
import database as connectdb
import subprocess
import os      
import re
import sys
import wx.dataview

class CredentialsTabPanel(wx.Panel):
    def __init__(self, parent, caseDetails, evidenceDetails):
        # begin wxGlade: MyDialog.__init__
        wx.Panel.__init__(self, parent=parent)
        self.cred = wx.dataview.DataViewListCtrl(self, wx.ID_ANY)

        self.__set_properties()
        self.__do_layout()
        #end wxGlade


    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.cred.SetMinSize((800, 800))
        self.cred.AppendTextColumn("Frame No", width=100)
        self.cred.AppendTextColumn("Client", width=250)
        self.cred.AppendTextColumn("Server", width=250)
        self.cred.AppendTextColumn("Protocol", width=200)
        self.cred.AppendTextColumn("Username", width=200)
        self.cred.AppendTextColumn("Password", width=200)
        self.cred.AppendTextColumn("Valid Login", width=200)
        self.cred.AppendTextColumn("Online Timestamp", width=200)
        #end wxGlade


    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_2 = wx.BoxSizer(wx.VERTICAL)
        sizer_2.Add(self.cred, 0, wx.EXPAND, 0)
        self.SetSizer(sizer_2)
        sizer_2.Fit(self)
        self.Layout()
        #end wxGlade


    def addCredentialsDetails(self, credrow):
        if ( credrow == () or credrow == None ):
            print("addPcapDetails: sequence is empty")
            return
        else:
            #print("addPcapDetauls: ", sequence)
            self.cred.AppendItem(credrow)


#--------------------#
#   Data List Ctrl   #
#--------------------#
"""import wx
import datetime
from datetime import timedelta
from pathlib import Path

#import connectdb
import database as connectdb

import subprocess
import os
import re

class CredentialsTabPanel(wx.Panel):
    def __init__(self, parent, caseDetails, evidenceDetails):
        # begin wxGlade: MyDialog.__init__
        wx.Panel.__init__(self, parent=parent)
        self.list_ctrl_1 = wx.ListCtrl(self, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT | wx.LC_VRULES)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.list_ctrl_1.AppendColumn("Client", format=wx.LIST_FORMAT_LEFT, width=150)
        self.list_ctrl_1.AppendColumn("Server", format=wx.LIST_FORMAT_LEFT, width=150)
        self.list_ctrl_1.AppendColumn("Protocol", format=wx.LIST_FORMAT_LEFT, width=100)
        self.list_ctrl_1.AppendColumn("Username", format=wx.LIST_FORMAT_LEFT, width=150)
        self.list_ctrl_1.AppendColumn("Password", format=wx.LIST_FORMAT_LEFT, width=150)
        self.list_ctrl_1.AppendColumn("Valid Login", format=wx.LIST_FORMAT_LEFT, width=150)
        self.list_ctrl_1.AppendColumn("Online Timestamp", format=wx.LIST_FORMAT_LEFT, width=150)
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_6 = wx.BoxSizer(wx.VERTICAL)
        sizer_6.Add(self.list_ctrl_1, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_6)
        sizer_6.Fit(self)
        self.Layout()
        # end wxGlade"""