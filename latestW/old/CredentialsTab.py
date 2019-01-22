import wx
import datetime
from datetime import timedelta
from pathlib import Path
import connectdb
import subprocess
import os
import re

class TabPanel(wx.Panel):
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
        # end wxGlade