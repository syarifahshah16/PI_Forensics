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
        self.cred.AppendTextColumn("Reconstructed File Path", width=200)
        self.cred.AppendTextColumn("Source Host", width=150)
        self.cred.AppendTextColumn("S.Port", width=80)
        self.cred.AppendTextColumn("Destination Host", width=150)
        self.cred.AppendTextColumn("D.Port", width=80)
        self.cred.AppendTextColumn("Protocol", width=150)
        self.cred.AppendTextColumn("Filename", width=150)
        self.cred.AppendTextColumn("Extension", width=150)
        self.cred.AppendTextColumn("Size", width=150)
        self.cred.AppendTextColumn("Timestamp", width=150)
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_2 = wx.BoxSizer(wx.VERTICAL)
        sizer_2.Add(self.cred, 0, wx.EXPAND, 0)
        self.SetSizer(sizer_2)
        sizer_2.Fit(self)
        self.Layout()
        # end wxGlade

    def addPcapDetails(self, sequence):
        if ( sequence == () or sequence == None ):
            print("addPcapDetails: sequence is empty")
            return
        else:
            #print("addPcapDetauls: ", sequence)
            self.cred.AppendItem(sequence)
        
