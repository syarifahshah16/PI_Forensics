import wx
import datetime
from datetime import timedelta
import database as connectdb
import subprocess
import os      
import re
import sys
import wx.dataview

class DNSTabPanel(wx.Panel):
    def __init__(self, parent, caseDir):
        # begin wxGlade: MyFrame.__init__
        wx.Panel.__init__(self, parent=parent)
        self.dnslist = wx.dataview.DataViewListCtrl(self, wx.ID_ANY)
        self.__set_properties()
        self.__do_layout()
        # end wxGlade


    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.dnslist.AppendTextColumn("DNS", width=193)
        self.dnslist.AppendTextColumn("IP Response", width=193)
        self.dnslist.AppendTextColumn("Protocol", width=193)
        # end wxGlade


    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_2 = wx.BoxSizer(wx.VERTICAL)
        sizer_2.Add(self.dnslist, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_2)
        sizer_2.Fit(self)
        self.Layout()
        # end wxGlade
        

    def addDNSDetails(self, row2):
        self.dnslist.AppendItem(row2)
        
