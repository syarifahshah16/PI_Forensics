import wx
import datetime
from datetime import timedelta
from pathlib import Path
import connectdb
import subprocess
import os      
import re
import sys

#from subprocess import Popen, PIPE

class TabPanel(wx.Panel):
    def __init__(self, parent):
        # begin wxGlade: MyFrame.__init__
        wx.Panel.__init__(self, parent=parent)
        self.sessionslist = wx.ListCtrl(self, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT | wx.LC_SINGLE_SEL | wx.LC_VRULES)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.sessionslist.SetMinSize((800, 800))
        self.sessionslist.AppendColumn("Packet", format=wx.LIST_FORMAT_LEFT, width=70)
        self.sessionslist.AppendColumn("Time", format=wx.LIST_FORMAT_LEFT, width=200)
        self.sessionslist.AppendColumn("Source", format=wx.LIST_FORMAT_LEFT, width=193)
        self.sessionslist.AppendColumn("Destination", format=wx.LIST_FORMAT_LEFT, width=193)
        self.sessionslist.AppendColumn("HTTP Request", format=wx.LIST_FORMAT_LEFT, width=wx.LIST_AUTOSIZE)
        """self.dnslist.AppendColumn("DNS", format=wx.LIST_FORMAT_LEFT, width=185)
        self.dnslist.AppendColumn("IP Response", format=wx.LIST_FORMAT_LEFT, width=193)
        self.dnslist.AppendColumn("Protocol", format=wx.LIST_FORMAT_LEFT, width=193)"""
        # end wxGlade/

    def __do_layout(self):
        # begin wxGlade: MyDialog.__do_layout
        sizer_2 = wx.BoxSizer(wx.VERTICAL)
        sizer_2.Add(self.sessionslist, 0, wx.EXPAND, 0)
        self.SetSizer(sizer_2)
        sizer_2.Fit(self)
        self.Layout()
        # end wxGlade

    def addSessionsDetails(self, sequence):
        self.sessionslist.Append(sequence)


    """def addPacketDetails(self, sequence, evidencePath):                  
        filename = os.path.basename(evidencePath)
        cmd = ['sudo', 'tcpdump', '-qns', '0', '-x', '-r', filename]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        self.packetsList.SetValue(stdout)"""
        