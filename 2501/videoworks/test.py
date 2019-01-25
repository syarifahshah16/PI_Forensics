import wx


class Frame(wx.Frame):

    def __init__(self):
        super(Frame, self).__init__(None, -1, "List copy test", size=(900, 500))

        panel = wx.Panel(self, -1)
        musicdata = {
        0 : ("Bad English", "The Price Of Love", "Rock"),
        1 : ("DNA featuring Suzanne Vega", "Tom's Diner", "Rock"),
        2 : ("George Michael", "Praying For Time", "Rock"),
        3 : ("Gloria Estefan", "Here We Are", "Rock"),
        4 : ("Linda Ronstadt", "Don't Know Much", "Rock"),
        5 : ("Michael Bolton", "How Am I Supposed To Live Without You", "Blues"),
        6 : ("Paul Young", "Oh Girl", "Rock"),
        }           

        self.listCtrl = wx.ListCtrl(panel, -1, size=(900, 400), style=wx.LC_REPORT)
        self.listCtrl.InsertColumn(0, "Column 1", width=180)
        self.listCtrl.InsertColumn(1, "Column 2", width=180)
        self.listCtrl.InsertColumn(2, "Column 3", width=180)

        items = musicdata.items()
        index = 0
        for key, data in items:
            self.listCtrl.InsertStringItem(index, data[0])
            self.listCtrl.SetStringItem(index, 1, data[1])
            self.listCtrl.SetStringItem(index, 2, data[2])
            self.listCtrl.SetItemData(index, key)
            index += 1

        self.listCtrl.Bind(wx.EVT_RIGHT_UP, self.ShowPopup)


    def ShowPopup(self, event):
        menu = wx.Menu()
        menu.Append(1, "Copy selected items")
        menu.Bind(wx.EVT_MENU, self.CopyItems, id=1)
        self.PopupMenu(menu)


    def CopyItems(self, event):
        selectedItems = []
        if self.listCtrl.IsSelected():
            selectedItems.append(self.listCtrl.GetItemText())

        clipdata = wx.TextDataObject()
        clipdata.SetText("\n".join(selectedItems))
        wx.TheClipboard.Open()
        wx.TheClipboard.SetData(clipdata)
        wx.TheClipboard.Close()

        print ("Items are on the clipboard")


app = wx.App(redirect=False)
frame = Frame()
frame.Show()
app.MainLoop()

