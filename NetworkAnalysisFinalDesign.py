#!/usr/bin/env python
# -*- coding: CP1252 -*-
#
# generated by wxGlade 0.8.3 on Wed Dec 12 08:42:13 2018
#

import wx
import os
import NewCaseDialog
import connectdb
import subprocess
import sqlite3
from sqlite3 import Error
from pathlib import Path
import datetime, time

# begin wxGlade: dependencies
# end wxGlade

# begin wxGlade: extracode
# end wxGlade


class mainNetAnalysis(wx.Frame):
      def __init__(self, parent):
            # begin wxGlade: mainNetAnalysis.__init__
            wx.Frame.__init__(self, parent=parent)
            self.SetSize((879, 788))
            
            # Menu Bar
            self.mainNetAnalysis_menubar = wx.MenuBar()
            wxglade_tmp_menu = wx.Menu()
            item = wxglade_tmp_menu.Append(wx.ID_ANY, "New Case", "")
            self.Bind(wx.EVT_MENU, self.on_menu_New_Case, id=item.GetId())
            item = wxglade_tmp_menu.Append(wx.ID_ANY, "Open Case", "")
            self.Bind(wx.EVT_MENU, self.on_menu_Open_Case, id=item.GetId())
            item = wxglade_tmp_menu.Append(wx.ID_ANY, "Add PCAP File", "")
            self.Bind(wx.EVT_MENU, self.on_menu_Add_PCAP, id=item.GetId())
            item = wxglade_tmp_menu.Append(wx.ID_ANY, "Exit", "")
            self.Bind(wx.EVT_MENU, self.on_menu_File_Exit, id=item.GetId())
            self.mainNetAnalysis_menubar.Append(wxglade_tmp_menu, "File")
            wxglade_tmp_menu = wx.Menu()
            item = wxglade_tmp_menu.Append(wx.ID_ANY, "Clear GUI", "")
            self.Bind(wx.EVT_MENU, self.on_tools_clear, id=item.GetId())
            item = wxglade_tmp_menu.Append(wx.ID_ANY, "Delete Data", "")
            self.Bind(wx.EVT_MENU, self.on_tools_del, id=item.GetId())
            self.mainNetAnalysis_menubar.Append(wxglade_tmp_menu, "Tools")
            self.SetMenuBar(self.mainNetAnalysis_menubar)
            # Menu Bar end
            self.mainNetAnalysis_statusbar = self.CreateStatusBar(1, wx.STB_DEFAULT_STYLE | wx.STB_ELLIPSIZE_MIDDLE | wx.STB_ELLIPSIZE_START)
            
            # Tool Bar
            self.mainNetAnalysis_toolbar = wx.ToolBar(self, -1)
            self.SetToolBar(self.mainNetAnalysis_toolbar)
            # Tool Bar end
            self.packet_details_copy = wx.Notebook(self, wx.ID_ANY)
            self.packet_details_copy_PCAPSummary = wx.Panel(self.packet_details_copy, wx.ID_ANY)
            self.packet_details_copy_File = wx.Panel(self.packet_details_copy, wx.ID_ANY)
            self.list_ctrl_1 = wx.ListCtrl(self.packet_details_copy_File, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT | wx.LC_VRULES)
            self.packet_details_copy_Images = wx.Panel(self.packet_details_copy, wx.ID_ANY)
            self.notebook_1 = wx.Notebook(self.packet_details_copy_Images, wx.ID_ANY)
            self.text_ctrl_3 = wx.TextCtrl(self.notebook_1, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)
            self.text_ctrl_4 = wx.TextCtrl(self.notebook_1, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)
            self.text_ctrl_5 = wx.TextCtrl(self.notebook_1, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)
            self.list_ctrl_6 = wx.ListCtrl(self.packet_details_copy_Images, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT | wx.LC_VRULES)
            self.packet_details_copy_Sessions = wx.Panel(self.packet_details_copy, wx.ID_ANY)
            self.tsharktab = wx.TextCtrl(self.packet_details_copy_Sessions, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)
            self.packetsList = wx.TextCtrl(self.packet_details_copy_Sessions, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)
            self.packet_details_copy_Protocol = wx.Panel(self.packet_details_copy, wx.ID_ANY)
            self.dnslist = wx.TextCtrl(self.packet_details_copy_Protocol, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)
            self.packet_details_copy_Credentials = wx.Panel(self.packet_details_copy, wx.ID_ANY)
            self.list_ctrl_4 = wx.ListCtrl(self.packet_details_copy_Credentials, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT | wx.LC_VRULES)
            self.packet_details_copy_Keywords = wx.Panel(self.packet_details_copy, wx.ID_ANY)
            self.panel_5 = wx.Panel(self.packet_details_copy_Keywords, wx.ID_ANY)
            self.panel_6 = wx.Panel(self.packet_details_copy_Keywords, wx.ID_ANY)
            self.panel_7 = wx.Panel(self.packet_details_copy_Keywords, wx.ID_ANY)
            self.list_ctrl_5 = wx.ListCtrl(self.packet_details_copy_Keywords, wx.ID_ANY, style=wx.LC_HRULES | wx.LC_REPORT | wx.LC_VRULES)
            self.panel_1 = wx.Panel(self.packet_details_copy_Keywords, wx.ID_ANY)

            self.__set_properties()
            self.__do_layout()

            self.Bind(wx.EVT_NAVIGATION_KEY, self.packet_file_notebook)
            self.Bind(wx.EVT_NAVIGATION_KEY, self.packet_images_notebook)
            self.Bind(wx.EVT_NAVIGATION_KEY, self.packet_sessions_notebook)
            self.Bind(wx.EVT_NAVIGATION_KEY, self.packet_dns_notebook)
            self.Bind(wx.EVT_NAVIGATION_KEY, self.packet_credentials_notebook)
            self.Bind(wx.EVT_NAVIGATION_KEY, self.packet_keywords_notebook)
            # end wxGlade

      def __set_properties(self):
            # begin wxGlade: mainNetAnalysis.__set_properties
            self.SetTitle("Network Analysis")
            self.SetBackgroundColour(wx.Colour(232, 232, 232))
            self.mainNetAnalysis_statusbar.SetStatusWidths([-1])

            # statusbar fields
            mainNetAnalysis_statusbar_fields = ["Network Analysis"]
            for i in range(len(mainNetAnalysis_statusbar_fields)):
                  self.mainNetAnalysis_statusbar.SetStatusText(mainNetAnalysis_statusbar_fields[i], i)
            self.mainNetAnalysis_toolbar.Realize()
            self.list_ctrl_1.AppendColumn("Frame No.", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_1.AppendColumn("File Path", format=wx.LIST_FORMAT_LEFT, width=150)
            self.list_ctrl_1.AppendColumn("Source Host", format=wx.LIST_FORMAT_LEFT, width=150)
            self.list_ctrl_1.AppendColumn("S.port", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_1.AppendColumn("Destination Host", format=wx.LIST_FORMAT_LEFT, width=150)
            self.list_ctrl_1.AppendColumn("D.port", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_1.AppendColumn("Filename", format=wx.LIST_FORMAT_LEFT, width=150)
            self.list_ctrl_1.AppendColumn("Extension", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_1.AppendColumn("Size", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_1.AppendColumn("Timestamp", format=wx.LIST_FORMAT_LEFT, width=150)
            self.text_ctrl_3.SetMinSize((1000, 250))
            self.text_ctrl_4.SetMinSize((1000, 250))
            self.text_ctrl_5.SetMinSize((1000, 250))
            self.list_ctrl_6.AppendColumn("FIlename", format=wx.LIST_FORMAT_LEFT, width=250)
            self.list_ctrl_6.AppendColumn("MD5", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_6.AppendColumn("Size ", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_6.AppendColumn("Parent Path", format=wx.LIST_FORMAT_LEFT, width=200)
            self.list_ctrl_6.AppendColumn("Extension", format=wx.LIST_FORMAT_LEFT, width=100)
            self.tsharktab.SetMinSize((1000, 300))
            self.packetsList.SetMinSize((867, 297))
            self.packetsList.SetBackgroundColour(wx.Colour(211, 211, 211))
            self.list_ctrl_4.AppendColumn("Client", format=wx.LIST_FORMAT_LEFT, width=150)
            self.list_ctrl_4.AppendColumn("Server", format=wx.LIST_FORMAT_LEFT, width=150)
            self.list_ctrl_4.AppendColumn("Protocol", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_4.AppendColumn("Username", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_4.AppendColumn("Password", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_4.AppendColumn("Valid Login", format=wx.LIST_FORMAT_LEFT, width=100)
            self.list_ctrl_4.AppendColumn("Online Timestamp", format=wx.LIST_FORMAT_LEFT, width=165)
            self.list_ctrl_5.AppendColumn("A", format=wx.LIST_FORMAT_LEFT, width=-1)
            self.list_ctrl_5.AppendColumn("B", format=wx.LIST_FORMAT_LEFT, width=-1)
            self.list_ctrl_5.AppendColumn("C", format=wx.LIST_FORMAT_LEFT, width=-1)
            # end wxGlade

      def __do_layout(self):
            # begin wxGlade: mainNetAnalysis.__do_layout
            sizer_1 = wx.BoxSizer(wx.VERTICAL)
            sizer_7 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_8 = wx.BoxSizer(wx.VERTICAL)
            sizer_6 = wx.BoxSizer(wx.VERTICAL)
            sizer_5 = wx.BoxSizer(wx.VERTICAL)
            sizer_22 = wx.BoxSizer(wx.VERTICAL)
            sizer_3 = wx.BoxSizer(wx.VERTICAL)
            sizer_2 = wx.BoxSizer(wx.VERTICAL)
            sizer_10 = wx.BoxSizer(wx.VERTICAL)
            sizer_21 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_20 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_19 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_18 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_17 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_16 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_15 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_11 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_13 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_12 = wx.BoxSizer(wx.HORIZONTAL)
            sizer_14 = wx.BoxSizer(wx.HORIZONTAL)

            lbl_fileExtracted = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "Analysis File Extracted:")
            lbl_fileExtracted.SetMinSize((250, 21))
            lbl_fileExtracted.SetFont(wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, ""))
            sizer_14.Add(lbl_fileExtracted, 0, wx.ALL, 0)

            lbl_evidenceCount = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "0")
            sizer_14.Add(lbl_evidenceCount, 0, 0, 0)
            sizer_10.Add(sizer_14, 1, wx.EXPAND, 0)

            lbl_md5 = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "MD5 Hash Value:")
            lbl_md5.SetMinSize((250, 21))
            sizer_12.Add(lbl_md5, 0, wx.ALL, 0)

            lbl_outputMD5 = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "\n")
            sizer_12.Add(lbl_outputMD5, 0, 0, 0)
            sizer_10.Add(sizer_12, 1, wx.EXPAND, 0)

            lbl_fileSize = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "File Size:")
            lbl_fileSize.SetMinSize((250, 21))
            sizer_13.Add(lbl_fileSize, 0, 0, 0)

            lbl_outputFileSize = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "\n")
            sizer_13.Add(lbl_outputFileSize, 0, 0, 0)
            sizer_10.Add(sizer_13, 1, wx.EXPAND, 0)

            lbl_datetime = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "Date-time Added:")
            lbl_datetime.SetMinSize((250, 21))
            sizer_11.Add(lbl_datetime, 0, 0, 0)

            lbl_outputDateTime = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "\n")
            sizer_11.Add(lbl_outputDateTime, 0, 0, 0)
            sizer_10.Add(sizer_11, 1, wx.EXPAND, 0)

            lbl_caseInfo = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "Case Info")
            lbl_caseInfo.SetMinSize((250, 21))
            lbl_caseInfo.SetFont(wx.Font(12, wx.DEFAULT, wx.NORMAL, wx.BOLD, 0, ""))
            sizer_15.Add(lbl_caseInfo, 0, wx.ALL | wx.EXPAND, 0)

            lbl_outputEmpty = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "\n")
            sizer_15.Add(lbl_outputEmpty, 0, 0, 0)
            sizer_10.Add(sizer_15, 1, wx.EXPAND, 0)

            lbl_investigator = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "Investigator Name:")
            lbl_investigator.SetMinSize((250, 21))
            sizer_16.Add(lbl_investigator, 0, 0, 0)

            lbl_outputInvestigator = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "\n")
            sizer_16.Add(lbl_outputInvestigator, 0, 0, 0)
            sizer_10.Add(sizer_16, 1, wx.EXPAND, 0)

            lbl_caseNo = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "Case Number:")
            lbl_caseNo.SetMinSize((250, 21))
            sizer_17.Add(lbl_caseNo, 0, 0, 0)

            lbl_outputCaseNo = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "\n")
            sizer_17.Add(lbl_outputCaseNo, 0, 0, 0)
            sizer_10.Add(sizer_17, 1, wx.EXPAND, 0)

            lbl_caseName = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "Case Name:")
            lbl_caseName.SetMinSize((250, 21))
            sizer_18.Add(lbl_caseName, 0, 0, 0)

            lbl_outputCaseName = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "\n")
            sizer_18.Add(lbl_outputCaseName, 0, 0, 0)
            sizer_10.Add(sizer_18, 1, wx.EXPAND, 0)

            lbl_datetime2 = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "Date-time Added:")
            lbl_datetime2.SetMinSize((250, 21))
            sizer_19.Add(lbl_datetime2, 0, 0, 0)

            lbl_outputDateTime2 = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "\n")
            sizer_19.Add(lbl_outputDateTime2, 0, 0, 0)
            sizer_10.Add(sizer_19, 1, wx.EXPAND, 0)

            lbl_caseDB = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "Case Database:")
            lbl_caseDB.SetMinSize((250, 21))
            sizer_20.Add(lbl_caseDB, 0, 0, 0)

            label_21 = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "\n")
            sizer_20.Add(label_21, 0, 0, 0)
            sizer_10.Add(sizer_20, 1, wx.EXPAND, 0)

            lbl_caseDesc = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "Case Description:")
            lbl_caseDesc.SetMinSize((250, 21))
            sizer_21.Add(lbl_caseDesc, 0, 0, 0)

            label_22 = wx.StaticText(self.packet_details_copy_PCAPSummary, wx.ID_ANY, "\n")
            sizer_21.Add(label_22, 0, 0, 0)
            sizer_10.Add(sizer_21, 1, wx.EXPAND, 0)

            self.packet_details_copy_PCAPSummary.SetSizer(sizer_10)
            sizer_2.Add(self.list_ctrl_1, 1, wx.EXPAND, 0)
            self.packet_details_copy_File.SetSizer(sizer_2)
            self.notebook_1.AddPage(self.text_ctrl_3, "Hex")
            self.notebook_1.AddPage(self.text_ctrl_4, "Image")
            self.notebook_1.AddPage(self.text_ctrl_5, "FIle Metadata")
            sizer_3.Add(self.notebook_1, 1, wx.EXPAND, 0)
            sizer_3.Add(self.list_ctrl_6, 1, wx.ALL | wx.EXPAND, 5)
            self.packet_details_copy_Images.SetSizer(sizer_3)
            sizer_22.Add(self.tsharktab, 1, wx.ALL, 0)
            sizer_22.Add(self.packetsList, 0, wx.TOP, 27)
            self.packet_details_copy_Sessions.SetSizer(sizer_22)
            sizer_5.Add(self.dnslist, 1, wx.EXPAND, 0)
            self.packet_details_copy_Protocol.SetSizer(sizer_5)
            sizer_6.Add(self.list_ctrl_4, 1, wx.EXPAND, 0)
            self.packet_details_copy_Credentials.SetSizer(sizer_6)
            sizer_8.Add(self.panel_5, 1, wx.EXPAND, 0)
            sizer_8.Add(self.panel_6, 1, wx.EXPAND, 0)
            sizer_8.Add(self.panel_7, 1, wx.EXPAND, 0)
            sizer_7.Add(sizer_8, 1, wx.EXPAND, 0)
            sizer_7.Add(self.list_ctrl_5, 1, wx.EXPAND, 0)
            sizer_7.Add(self.panel_1, 1, wx.EXPAND, 0)
            self.packet_details_copy_Keywords.SetSizer(sizer_7)
            self.packet_details_copy.AddPage(self.packet_details_copy_PCAPSummary, "PCAP Summary")
            self.packet_details_copy.AddPage(self.packet_details_copy_File, "File")
            self.packet_details_copy.AddPage(self.packet_details_copy_Images, "Images")
            self.packet_details_copy.AddPage(self.packet_details_copy_Sessions, "Sessions")
            self.packet_details_copy.AddPage(self.packet_details_copy_Protocol, "DNS")
            self.packet_details_copy.AddPage(self.packet_details_copy_Credentials, "Credentials")
            self.packet_details_copy.AddPage(self.packet_details_copy_Keywords, "Keywords")
            sizer_1.Add(self.packet_details_copy, 1, wx.EXPAND, 0)

            self.SetSizer(sizer_1)
            self.Layout()
            self.Centre()
            # end wxGlade

      def on_menu_New_Case(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'on_menu_New_Case' not implemented!")
            event.Skip()

      def on_menu_Open_Case(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'on_menu_Open_Case' not implemented!")
            event.Skip()

      def on_menu_Add_PCAP(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'on_menu_Add_PCAP' not implemented!")
            event.Skip()

      def on_menu_File_Exit(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'on_menu_File_Exit' not implemented!")
            event.Skip()

      def on_tools_clear(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'on_tools_clear' not implemented!")
            event.Skip()

      def on_tools_del(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'on_tools_del' not implemented!")
            event.Skip()

      def packet_file_notebook(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'packet_file_notebook' not implemented!")
            event.Skip()

      def packet_images_notebook(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'packet_images_notebook' not implemented!")
            event.Skip()

      def packet_sessions_notebook(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'packet_sessions_notebook' not implemented!")
            event.Skip()

      def packet_dns_notebook(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'packet_dns_notebook' not implemented!")
            event.Skip()

      def packet_credentials_notebook(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'packet_credentials_notebook' not implemented!")
            event.Skip()

      def packet_keywords_notebook(self, event):  # wxGlade: mainNetAnalysis.<event_handler>
            print("Event handler 'packet_keywords_notebook' not implemented!")
            event.Skip()

# end of class mainNetAnalysis

class MyApp(wx.App):
      def OnInit(self):
            self.mainNetAnalysis = mainNetAnalysis(None)
            self.SetTopWindow(self.mainNetAnalysis)
            self.mainNetAnalysis.Show()
            return True

# end of class MyApp

if __name__ == "__main__":
      app = MyApp(0)
      app.MainLoop()
