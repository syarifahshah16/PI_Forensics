import wx

# begin wxGlade: dependencies
# end wxGlade

# begin wxGlade: extracode
# end wxGlade

class searchDialog(wx.Dialog):
    def __init__(self, *args, **kwds):
        # begin wxGlade: searchDialog.__init__
       
        wx.Dialog.__init__(self, *args, **kwds)
        self.SetSize((300, 200))
        self.panel_1 = wx.Panel(self, wx.ID_ANY)
        self.search_txt_ctrl = wx.TextCtrl(self.panel_1, wx.ID_ANY, "")
        self.radio_box_1 = wx.RadioBox(self.panel_1, wx.ID_ANY, "", choices=["Normal Search", "Regular Expression"], majorDimension=1, style=wx.RA_SPECIFY_ROWS)

        self.searchBtn = wx.Button(self.panel_1, wx.ID_ANY, "Search")
        self.cancelBtn = wx.Button(self.panel_1, wx.ID_ANY, "Cancel")

        self.__set_properties()
        self.__do_layout()

        self.Bind(wx.EVT_RADIOBOX, self.onRadioBoxSel, self.radio_box_1)
       
        self.Bind(wx.EVT_BUTTON, self.onSearchBtn, self.searchBtn)
        self.Bind(wx.EVT_BUTTON, self.onCancelBtn, self.cancelBtn)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: searchDialog.__set_properties
        self.SetTitle("dialog")
        self.radio_box_1.SetSelection(0)
        # end wxGlade 

    def __do_layout(self):
        # begin wxGlade: searchDialog.__do_layout
        sizer_3 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_4 = wx.BoxSizer(wx.VERTICAL)
        sizer_1 = wx.BoxSizer(wx.HORIZONTAL)
        sizer_4.Add(self.search_txt_ctrl, 0, wx.ALL | wx.EXPAND, 7)
        sizer_4.Add(self.radio_box_1, 0, wx.ALIGN_CENTER, 0)
        sizer_1.Add(self.searchBtn, 0, wx.ALIGN_BOTTOM | wx.ALL, 7)
        sizer_1.Add(self.cancelBtn, 0, wx.ALIGN_BOTTOM | wx.ALL, 7)
        sizer_4.Add(sizer_1, 1, wx.ALIGN_RIGHT, 0)
        self.panel_1.SetSizer(sizer_4)
        sizer_3.Add(self.panel_1, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_3)
        self.Layout()

    def onRadioBoxSel(self, event):
        event.Skip()
        # end wxGlade

    def onSearchBtn(self, event):
        self.searchQuery = self.search_txt_ctrl.GetValue()
        sel = self.radio_box_1.GetSelection()
        self.radioOption = self.radio_box_1.GetString(sel)
        self.Close()

    def onCancelBtn(self, event):
        self.Close()

    def searchItems(self):
        return (self.searchQuery, self.radioOption)
# end of class searchDialog

# class MyApp(wx.App):
#     def OnInit(self):
#         self.dialog = searchDialog(None, wx.ID_ANY, "")
#         self.SetTopWindow(self.dialog)
#         self.dialog.ShowModal()
#         self.dialog.Destroy()
#         return True
          #end of class TabPanel

# if __name__ == "__main__":
#     app = MyApp(0)
#     app.MainLoop()
