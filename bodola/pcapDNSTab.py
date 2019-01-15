import wx
import connectdb
import os
import sqlite3
from sqlite3 import Error
from subprocess import Popen, PIPE
import wx.dataview

# begin wxGlade: dependencies
# end wxGlade

# begin wxGlade: extracode
style=wx.BORDER_NONE
# end wxGlade

class TabPanel(wx.Panel):
    def __init__(self, parent, caseDir):
        # begin wxGlade: MyFrame.__init__
        wx.Panel.__init__(self, parent=parent)
        global dnslist
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
        self.Layout()
        # end wxGlade

    def addDNSDetails(self, row2):
        self.dnslist.AppendItem(row2)

# end of class TabPanel


                    
