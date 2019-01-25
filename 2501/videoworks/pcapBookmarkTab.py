import wx
import datetime
from datetime import timedelta

import connectdb
import subprocess
import os      
import re
import sys
import wx.dataview as dv

class BookmarkTabPanel(wx.Panel):
    def __init__(self, parent, caseDir, evidenceDetails, caseDbPath):
        # begin wxGlade: MyFrame.__init__
        wx.Panel.__init__(self, parent=parent)
        self.pcapAddedBookM = wx.Notebook(self, wx.ID_ANY)
        self.pcapAddedBookM_Files = wx.Panel(self.pcapAddedBookM, wx.ID_ANY)
        self.filesbkm_list = wx.ListCtrl(self.pcapAddedBookM_Files, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT)
        self.pcapAddedBookM_Images = wx.Panel(self.pcapAddedBookM, wx.ID_ANY)
        self.pcapAddedBookM_Sessions = wx.Panel(self.pcapAddedBookM, wx.ID_ANY)
        self.sessionsbkm_list = wx.ListCtrl(self.pcapAddedBookM_Sessions, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT)
        self.pcapAddedBookM_DNS = wx.Panel(self.pcapAddedBookM, wx.ID_ANY)
        self.dnsbkm_list = wx.ListCtrl(self.pcapAddedBookM_DNS, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT)
        self.pcapAddedBookM_Credentials = wx.Panel(self.pcapAddedBookM, wx.ID_ANY)
        self.credbkm_list = wx.ListCtrl(self.pcapAddedBookM_Credentials, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT)

        self.__set_properties()
        self.__do_layout()
        # end wxGlade
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: MyDialog.__set_properties
        self.filesbkm_list.AppendColumn("Frame No.", format=wx.LIST_FORMAT_LEFT, width=100)
        self.filesbkm_list.AppendColumn("Reconstructed File Path", format=wx.LIST_FORMAT_LEFT, width=200)
        self.filesbkm_list.AppendColumn("Source Host", format=wx.LIST_FORMAT_LEFT, width=150)
        self.filesbkm_list.AppendColumn("S.Port", format=wx.LIST_FORMAT_LEFT, width=80)
        self.filesbkm_list.AppendColumn("Destination Host", format=wx.LIST_FORMAT_LEFT, width=150)
        self.filesbkm_list.AppendColumn("D.Port", format=wx.LIST_FORMAT_LEFT, width=80)
        self.filesbkm_list.AppendColumn("Protocol", format=wx.LIST_FORMAT_LEFT, width=150)
        self.filesbkm_list.AppendColumn("Filename", format=wx.LIST_FORMAT_LEFT, width=150)
        self.filesbkm_list.AppendColumn("Extension", format=wx.LIST_FORMAT_LEFT, width=150)
        self.filesbkm_list.AppendColumn("Size", format=wx.LIST_FORMAT_LEFT, width=150)
        self.sessionsbkm_list.AppendColumn("Packet", format=wx.LIST_FORMAT_LEFT, width=70)
        self.sessionsbkm_list.AppendColumn("Time", format=wx.LIST_FORMAT_LEFT, width=210)
        self.sessionsbkm_list.AppendColumn("Source", format=wx.LIST_FORMAT_LEFT, width=193)
        self.sessionsbkm_list.AppendColumn("Destination", format=wx.LIST_FORMAT_LEFT, width=193)
        self.sessionsbkm_list.AppendColumn("HTTP Request", format=wx.LIST_FORMAT_LEFT, width=wx.LIST_AUTOSIZE)
        self.dnsbkm_list.AppendColumn("DNS", format=wx.LIST_FORMAT_LEFT, width=193)
        self.dnsbkm_list.AppendColumn("IP Response", format=wx.LIST_FORMAT_LEFT, width=193)
        self.dnsbkm_list.AppendColumn("Protocol", format=wx.LIST_FORMAT_LEFT, width=193)
        self.credbkm_list.AppendColumn("Frame No", format=wx.LIST_FORMAT_LEFT, width=100)
        self.credbkm_list.AppendColumn("Client", format=wx.LIST_FORMAT_LEFT, width=200)
        self.credbkm_list.AppendColumn("Server", format=wx.LIST_FORMAT_LEFT, width=150)
        # end wxGlade

        # end wxGlade/

    def __do_layout(self):
        sizer_3 = wx.BoxSizer(wx.VERTICAL)
        sizer_8 = wx.BoxSizer(wx.VERTICAL)
        sizer_7 = wx.BoxSizer(wx.VERTICAL)
        sizer_6 = wx.BoxSizer(wx.VERTICAL)
        sizer_5 = wx.BoxSizer(wx.VERTICAL)
        sizer_4 = wx.BoxSizer(wx.VERTICAL)
        sizer_4.Add(self.filesbkm_list, 1, wx.EXPAND, 0)
        self.pcapAddedBookM_Files.SetSizer(sizer_4)
        sizer_5.Add((0, 0), 0, 0, 0)
        self.pcapAddedBookM_Images.SetSizer(sizer_5)
        sizer_6.Add(self.sessionsbkm_list, 1, wx.EXPAND, 0)
        self.pcapAddedBookM_Sessions.SetSizer(sizer_6)
        sizer_7.Add(self.dnsbkm_list, 1, wx.EXPAND, 0)
        self.pcapAddedBookM_DNS.SetSizer(sizer_7)
        sizer_8.Add(self.credbkm_list, 1, wx.EXPAND, 0)
        self.pcapAddedBookM_Credentials.SetSizer(sizer_8)
        self.pcapAddedBookM.AddPage(self.pcapAddedBookM_Files, "Files")
        self.pcapAddedBookM.AddPage(self.pcapAddedBookM_Images, "Images")
        self.pcapAddedBookM.AddPage(self.pcapAddedBookM_Sessions, "Sessions")
        self.pcapAddedBookM.AddPage(self.pcapAddedBookM_DNS, "DNS")
        self.pcapAddedBookM.AddPage(self.pcapAddedBookM_Credentials, "Credentials")
        sizer_3.Add(self.pcapAddedBookM, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_3)
        self.Layout()


        
