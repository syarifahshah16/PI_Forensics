import wx
import os

# begin wxGlade: dependencies
# end wxGlade

# begin wxGlade: extracode
# end wxGlade

class mainmenu(wx.Dialog):
    def __init__(self, *args, **kwds):
        # begin wxGlade: mainmenu.__init__
        kwds["style"] = kwds.get("style", 0) | wx.DEFAULT_DIALOG_STYLE
        wx.Dialog.__init__(self, *args, **kwds)
        self.SetSize((381, 264))
        self.btnHarddiskExtraction = wx.Button(self, wx.ID_ANY, "Hard Disk Extraction")
        self.btnMobileExtraction = wx.Button(self, wx.ID_ANY, "Mobile Extraction")
        self.btnNetworkAnalysis = wx.Button(self, wx.ID_ANY, "Network Analysis")

        self.__set_properties()
        self.__do_layout()

        self.Bind(wx.EVT_BUTTON, self.onBtnHarddiskExtraction, self.btnHarddiskExtraction)
        self.Bind(wx.EVT_BUTTON, self.onBtnMobileExtraction, self.btnMobileExtraction)
        self.Bind(wx.EVT_BUTTON, self.onBtnNetworkAnalysis, self.btnNetworkAnalysis)
        # end wxGlade

    def __set_properties(self):
        # begin wxGlade: mainmenu.__set_properties
        self.SetTitle("Pi Forensics")
        self.SetSize((381, 264))
        self.btnHarddiskExtraction.SetMinSize((160, 30))
        self.btnMobileExtraction.SetMinSize((160, 30))
        self.btnNetworkAnalysis.SetMinSize((160, 30))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: mainmenu.__do_layout
        sizer_1 = wx.BoxSizer(wx.VERTICAL)
        sizer_1.Add(self.btnHarddiskExtraction, 0, wx.ALIGN_CENTER | wx.TOP, 22)
        sizer_1.Add(self.btnMobileExtraction, 0, wx.ALIGN_CENTER | wx.TOP, 41)
        sizer_1.Add(self.btnNetworkAnalysis, 0, wx.ALIGN_CENTER | wx.TOP, 42)
        self.SetSizer(sizer_1)
        self.Layout()
        # end wxGlade

    #-----------------------#
    #   Buttons on Dialog   #
    #-----------------------#
    def onBtnHarddiskExtraction(self, event):  
        os.system('python mainHD.py')

    def onBtnMobileExtraction(self, event): 
        print("Event handler 'onBtnMobileExtraction' not implemented!")
        event.Skip()

    def onBtnNetworkAnalysis(self, event): 
        os.system('python mainFiles.py')
        #os.system('python mainSessionsDNS.py')
 
    #---------------------------#
    #   End of class mainmenu   #
    #---------------------------#

class MyApp(wx.App):
    def OnInit(self):
        self.dialog = mainmenu(None, wx.ID_ANY, "")
        self.SetTopWindow(self.dialog)
        self.dialog.ShowModal()
        self.dialog.Destroy()
        return True
        #end of class MyApp

if __name__ == "__main__":
    app = MyApp(0)
    app.MainLoop()
