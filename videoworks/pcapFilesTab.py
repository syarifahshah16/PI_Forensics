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

class FilesTabPanel(wx.Panel):
    def __init__(self, parent, caseDetails, evidenceDetails):
        # begin wxGlade: MyDialog.__init__
        wx.Panel.__init__(self, parent=parent)
        self.list_ctrl_1 = wx.dataview.DataViewListCtrl(self, wx.ID_ANY)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.list_ctrl_1.SetMinSize((800, 800))
        self.list_ctrl_1.AppendTextColumn("Frame No", width=100)
        self.list_ctrl_1.AppendTextColumn("Reconstructed File Path", width=200)
        self.list_ctrl_1.AppendTextColumn("Source Host", width=150)
        self.list_ctrl_1.AppendTextColumn("S.Port", width=80)
        self.list_ctrl_1.AppendTextColumn("Destination Host", width=150)
        self.list_ctrl_1.AppendTextColumn("D.Port", width=80)
        self.list_ctrl_1.AppendTextColumn("Protocol", width=150)
        self.list_ctrl_1.AppendTextColumn("Filename", width=150)
        self.list_ctrl_1.AppendTextColumn("Extension", width=150)
        self.list_ctrl_1.AppendTextColumn("Size", width=150)
        self.list_ctrl_1.AppendTextColumn("Timestamp", width=150)
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_2 = wx.BoxSizer(wx.VERTICAL)
        sizer_2.Add(self.list_ctrl_1, 0, wx.EXPAND, 0)
        self.SetSizer(sizer_2)
        sizer_2.Fit(self)
        self.Layout()
        # end wxGlade

    def addPcapDetails(self, sequence):
        self.list_ctrl_1.AppendItem(sequence)
        
