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

class SessionsTabPanel(wx.Panel):
    def __init__(self, parent, caseDir):
        # begin wxGlade: MyFrame.__init__
        wx.Panel.__init__(self, parent=parent)
        self.pcaplist = wx.dataview.DataViewListCtrl(self, wx.ID_ANY)
        

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.pcaplist.SetMinSize((800, 800))
        self.pcaplist.AppendTextColumn("Packet", width=70)
        self.pcaplist.AppendTextColumn("Time", width=210)
        self.pcaplist.AppendTextColumn("Source", width=193)
        self.pcaplist.AppendTextColumn("Destination", width=193)
        self.pcaplist.AppendTextColumn("HTTP Request", width=wx.LIST_AUTOSIZE)

        # end wxGlade/

    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_2 = wx.BoxSizer(wx.VERTICAL)
        sizer_2.Add(self.pcaplist, 0, wx.EXPAND, 0)
        self.SetSizer(sizer_2)
        sizer_2.Fit(self)
        self.Layout()
        # end wxGlade

    def addSessionsDetails(self, sequence):
        self.pcaplist.AppendItem(sequence)


        
