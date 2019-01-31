#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# generated by wxGlade 0.8.3 on Thu Sep  6 00:17:50 2018
#

import wx
import connectdb
import os
import sqlite3
from sqlite3 import Error

# begin wxGlade: dependencies
# end wxGlade

# begin wxGlade: extracode
style=wx.BORDER_NONE
# end wxGlade


class SummaryTabPanel(wx.Panel):
    def __init__(self, parent, caseDetails, evidenceDetails):
        # begin wxGlade: MyFrame.__init__
        wx.Panel.__init__(self, parent=parent)
        self.SetSize((655, 673))
        self.panel_1 = wx.Panel(self, wx.ID_ANY)
        self.panel_2 = wx.ScrolledWindow(self.panel_1, wx.ID_ANY, style=wx.TAB_TRAVERSAL)
        self.txtCaseDb = wx.TextCtrl(self.panel_1, wx.ID_ANY, "", style=wx.TE_READONLY | wx.BORDER_NONE)
        self.txtCaseDesc = wx.TextCtrl(self.panel_1, wx.ID_ANY, "", style=wx.TE_MULTILINE | wx.TE_READONLY)

        global evidenceInfo
        for x in caseDetails:
            try:
                conn = connectdb.create_connection(x[5])     #call to get evidence database from evidence table
                evidenceInfo = connectdb.select_evidence_details(conn)

            except Error as e:
                print(e)
    

        self.__set_properties()
        self.__do_layout(caseDetails, evidenceDetails)

        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: MyFrame.__set_properties
        self.panel_2.SetScrollRate(10, 10)
        self.txtCaseDb.SetBackgroundColour(wx.Colour(229, 229, 229))
        self.txtCaseDesc.SetMinSize((252, 150))
        self.txtCaseDesc.SetBackgroundColour(wx.Colour(229, 229, 229))
        # end wxGlade

    def __do_layout(self, caseDetails, evidenceDetails):
        # begin wxGlade: MyFrame.__do_layout
        sizer_1 = wx.BoxSizer(wx.VERTICAL)
        sizer_9 = wx.BoxSizer(wx.VERTICAL)
        sizer_12 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_14 = wx.BoxSizer(wx.VERTICAL)
        caseInfoGridSizer = wx.FlexGridSizer(6, 2, 0, 0)
        sizer_13 = wx.BoxSizer(wx.VERTICAL)
        evidenceMainSizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer_2 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_10 = wx.BoxSizer(wx.HORIZONTAL)
        lblSummary = wx.StaticText(self.panel_1, wx.ID_ANY, "Summary")
        lblSummary.SetFont(wx.Font(20, wx.DEFAULT, wx.NORMAL, wx.LIGHT, 0, ""))
        sizer_10.Add(lblSummary, 1, wx.ALL, 5)
        sizer_9.Add(sizer_10, 0, wx.EXPAND, 0)
        static_line_1 = wx.StaticLine(self.panel_1, wx.ID_ANY)
        sizer_9.Add(static_line_1, 0, wx.BOTTOM | wx.EXPAND | wx.TOP, 5)
        
        lblExtraction = wx.StaticText(self.panel_1, wx.ID_ANY, "Extractions: ")
        lblExtraction.SetFont(wx.Font(15, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, ""))
        sizer_2.Add(lblExtraction, 0, 0, 0)
        lblEvidenceCount = wx.StaticText(self.panel_1, wx.ID_ANY, "0")
        lblEvidenceCount.SetFont(wx.Font(15, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, ""))
        sizer_2.Add(lblEvidenceCount, 0, 0, 0)
        sizer_9.Add(sizer_2, 0, wx.EXPAND, 0)

        
            # for x in imageInfo:
            #     x = list(x)
            #     self.addEvidence(evidenceMainSizer, x[0], x[1], x[2])
        global evidenceAddDate
        for x in evidenceDetails:
            evidenceAddDate = x[3]

        global evidenceAddHash
        for x in evidenceDetails:
            evidenceAddHash = x[4]


        evidenceCount = 0
        evidenceCount += 1
        lblEvidenceCount.SetLabel(str(evidenceCount))

        self.panel_2.SetSizer(evidenceMainSizer)
        sizer_9.Add(self.panel_2, 1, wx.EXPAND, 0)
        lblDeviceInfo = wx.StaticText(self.panel_1, wx.ID_ANY, "Case Info:")
        lblDeviceInfo.SetFont(wx.Font(15, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, ""))
        sizer_13.Add(lblDeviceInfo, 0, wx.ALL | wx.EXPAND, 5)
        static_line_2 = wx.StaticLine(self.panel_1, wx.ID_ANY)
        sizer_13.Add(static_line_2, 0, wx.BOTTOM | wx.EXPAND | wx.TOP, 5)
        label_5 = wx.StaticText(self.panel_1, wx.ID_ANY, "Investigator Name:")
        caseInfoGridSizer.Add(label_5, 0, 0, 0)
        lblInvestigatorName = wx.StaticText(self.panel_1, wx.ID_ANY, "")
        caseInfoGridSizer.Add(lblInvestigatorName, 0, 0, 0)
        label_6 = wx.StaticText(self.panel_1, wx.ID_ANY, "Case Number:")
        caseInfoGridSizer.Add(label_6, 0, 0, 0)
        lblCaseNum = wx.StaticText(self.panel_1, wx.ID_ANY, "")
        caseInfoGridSizer.Add(lblCaseNum, 0, 0, 0)
        label_13 = wx.StaticText(self.panel_1, wx.ID_ANY, "Case Name:")
        caseInfoGridSizer.Add(label_13, 0, 0, 0)
        lblCaseName = wx.StaticText(self.panel_1, wx.ID_ANY, "")
        caseInfoGridSizer.Add(lblCaseName, 0, 0, 0)
        label_11 = wx.StaticText(self.panel_1, wx.ID_ANY, "Date added:")
        caseInfoGridSizer.Add(label_11, 0, 0, 0)
        lblDateTime = wx.StaticText(self.panel_1, wx.ID_ANY, "")
        caseInfoGridSizer.Add(lblDateTime, 0, 0, 0)
        label_9 = wx.StaticText(self.panel_1, wx.ID_ANY, "Case Database:")
        caseInfoGridSizer.Add(label_9, 0, 0, 0)
        caseInfoGridSizer.Add(self.txtCaseDb, 0, wx.ALL | wx.EXPAND, 5)
        label_10 = wx.StaticText(self.panel_1, wx.ID_ANY, "Case Description:")
        caseInfoGridSizer.Add(label_10, 0, 0, 0)
        caseInfoGridSizer.Add(self.txtCaseDesc, 1, wx.ALL | wx.EXPAND, 5)
        caseInfoGridSizer.AddGrowableCol(1)

        for x in caseDetails:                           #sets the case info
            lblInvestigatorName.SetLabel(x[1])
            lblCaseNum.SetLabel(str(x[2]))
            lblCaseName.SetLabel(x[3])
            lblDateTime.SetLabel(str(x[7]))
            self.txtCaseDb.SetValue(x[5])
            self.txtCaseDesc.SetValue(x[6])
            


        sizer_13.Add(caseInfoGridSizer, 1, wx.ALL | wx.EXPAND, )
        sizer_12.Add(sizer_13, 1, wx.EXPAND, 0)
        
        sizer_9.Add(sizer_12, 1, wx.EXPAND, 0)
        self.panel_1.SetSizer(sizer_9)
        sizer_1.Add(self.panel_1, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_1)
        self.Layout()
        # end wxGlade

        self.text_ctrl1 = wx.TextCtrl(self.panel_2, wx.ID_ANY, evidenceAddHash, style=wx.TE_READONLY | wx.BORDER_NONE)
        self.text_ctrl2 = wx.TextCtrl(self.panel_2, wx.ID_ANY, style=wx.TE_READONLY | wx.BORDER_NONE)
        self.text_ctrl3 = wx.TextCtrl(self.panel_2, wx.ID_ANY, evidenceAddDate, style=wx.TE_READONLY | wx.BORDER_NONE)
        

        self.text_ctrl1.SetBackgroundColour(wx.Colour(235, 235, 235))
        self.text_ctrl2.SetBackgroundColour(wx.Colour(235, 235, 235))
        self.text_ctrl3.SetBackgroundColour(wx.Colour(235, 235, 235))
        self.text_ctrl1.SetMinSize((290, 30))
        

        gridSizer = wx.FlexGridSizer(0, 2, 0, 0)
        infoSizer = wx.BoxSizer(wx.VERTICAL)
        gridSizer.Add((30, 28), 0, 0, 0)
        gridSizer.Add((0, 0), 0, 0, 0)

        lblMd5 = wx.StaticText(self.panel_2, wx.ID_ANY, "PCAP Md5 Hash:")
        infoSizer.Add(lblMd5, 0, wx.ALL, 5)
        infoSizer.Add(self.text_ctrl1, 0, wx.BOTTOM | wx.EXPAND | wx.LEFT | wx.RIGHT, 5)
        lblSize = wx.StaticText(self.panel_2, wx.ID_ANY, "PCAP Evidence Size:")
        infoSizer.Add(lblSize, 0, wx.ALL, 5)
        infoSizer.Add(self.text_ctrl2, 0, wx.BOTTOM | wx.EXPAND | wx.LEFT | wx.RIGHT, 5)
        lblDateAdded = wx.StaticText(self.panel_2, wx.ID_ANY, "Date/Time added:")
        infoSizer.Add(lblDateAdded, 0, wx.ALL, 5)
        infoSizer.Add(self.text_ctrl3, 0, wx.BOTTOM | wx.EXPAND | wx.LEFT | wx.RIGHT, 5)
        gridSizer.Add(infoSizer, 1, wx.EXPAND, 0)
        evidenceMainSizer.Add(gridSizer, 0, wx.BOTTOM | wx.EXPAND | wx.LEFT, 6)


# end of class MyFrame
