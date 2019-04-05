from Tkinter import *
from tkFileDialog import *
import sys
import math
import base64
from Crypto.Cipher import AES
from Crypto import Random

MAX_CHAR = 26

def editGUI(event):
    w = 250
    h = 150
    ws = event.winfo_screenwidth ()
    hs = event.winfo_screenheight ()
    x = (ws / 2) - (w / 2)
    y = (hs / 2) - (h / 2)
    event.geometry ('%dx%d+%d+%d' % (w, h, x, y))  # give dimensions
    event.config (background="#800000")
    event.resizable (0, 0)

def editSystemGUI(event):
    w = 1000
    h = 600
    ws = event.winfo_screenwidth ()
    hs = event.winfo_screenheight ()
    x = (ws / 2) - (w / 2)
    y = (hs / 2) - (h / 2)
    event.geometry ('%dx%d+%d+%d' % (w, h, x, y))  # give dimensions
    event.config (background="#000066")
    event.resizable (0, 0)

def loadFile():
    try:
        file = askopenfile (filetypes=(("Text Files", "*.txt"), ("All files", "*.*")), title='Open File', mode='r')
        fileLoad = file.read ()
        file.close ()
        return fileLoad
    except Exception:
        pass

def getOptionCaesar():
    global toplevel
    toplevel = Toplevel ()
    toplevel.wm_title("Caesar")
    editGUI(toplevel)
    encryptbuttn = Button (toplevel, text="Encrypt ", height=0, width=20, command=CaesarEncryptGUI)
    encryptbuttn.grid (row=2, column=5,rowspan=2,columnspan=2,padx=10,pady=10)
    encryptbuttn.config(background="#993333",font="Helvatica")
    decryptbuttn = Button (toplevel, text="Decrypt ", height=0, width=20, command=CeasearDecryptGUI)
    decryptbuttn.grid (row=5, column=5,rowspan=2,columnspan=2,padx=10,pady=10)
    decryptbuttn.config(background="#993333",font="Helvatica")


def getOptionVigenere():
    global toplevel4
    toplevel4 = Toplevel ()
    toplevel4.wm_title ("Vigenere")
    editGUI (toplevel4)
    encryptVbuttn = Button (toplevel4, text="Encrypt ", height=0, width=20, command=VigEncryptGUI)
    encryptVbuttn.grid (row=2, column=5,rowspan=2,columnspan=2,padx=10,pady=10)
    encryptVbuttn.config(background="#993333",font="Helvatica")
    decryptVbuttn = Button (toplevel4, text="Decrypt ", height=0, width=20, command=VigDecryptGUI)
    decryptVbuttn.grid (row=5, column=5,rowspan=2,columnspan=2,padx=10,pady=10)
    decryptVbuttn.config(background="#993333",font="Helvatica")


def getOptionRoute():
    global toplevel7
    toplevel7 = Toplevel ()
    toplevel7.wm_title ("Route")
    editGUI (toplevel7)
    encryptRbuttn = Button (toplevel7, text="Encrypt ", height=0, width=20, command=RouteEncryptGUI)
    encryptRbuttn.grid (row=2, column=5,rowspan=2,columnspan=2,padx=10,pady=10)
    encryptRbuttn.config(background="#993333",font="Helvatica")
    decryptRbuttn = Button (toplevel7, text="Decrypt ", height=0, width=20, command=RouteDecryptGUI)
    decryptRbuttn.grid (row=5, column=5,rowspan=2,columnspan=2,padx=10,pady=10)
    decryptRbuttn.config(background="#993333",font="Helvatica")

def getOptionKey():
    global toplevel11
    toplevel11 = Toplevel ()
    toplevel11.wm_title ("Key Mgt. System")
    editGUI (toplevel11)
    encryptKbuttn = Button (toplevel11, text="Encrypt ", height=0, width=20, command=keyEnGUI)
    encryptKbuttn.grid (row=2, column=5,rowspan=2,columnspan=2,padx=10,pady=10)
    encryptKbuttn.config(background="#993333",font="Helvatica")
    decryptKbuttn = Button (toplevel11, text="Decrypt ", height=0, width=20, command=keyDecGUI)
    decryptKbuttn.grid (row=5, column=5,rowspan=2,columnspan=2,padx=10,pady=10)
    decryptKbuttn.config(background="#993333",font="Helvatica")


def quit(event):
    event.destroy ()


def focus_next_entrybox(E):
    E.widget.tk_focusNext ().focus ()
    return ("break")

def loadFileIntoGUI(event):
    try:
        text=loadFile()
        event.delete("0.0",END)
        event.insert(INSERT,text)
    except Exception:
        event.delete ("0.0", END)
        event.insert (INSERT, "File NOT FOUND!!")



def CaesarEncryptGUI():
    quit (toplevel)
    global key
    global ptext
    global temp
    global toplevel2
    toplevel2 = Toplevel ()
    editSystemGUI(toplevel2)
    global cypherTxt

    cypherTxt = StringVar ()
    temp = ''
    # toplevel2.geometry("%dx%d%+d%+d" % (500, 500, 250, 125))

    key = IntVar ()

    try:
        ptext = Text (toplevel2)
        ptext.grid (row=2, column=1,padx=(0,10),pady=10)
        ptext.bind ("<Return>", focus_next_entrybox)
        ptext.focus_set ()

        inputButton = Button (toplevel2, text="Enter plaintext", command= lambda:loadFileIntoGUI (ptext))
        inputButton.grid (row=2, column=0)
        inputButton.config(background="#666699",font="Helvatica")

        labelkeysize = Label (toplevel2, text="Enter key size (between -25 and 25) :")
        labelkeysize.grid (row=4, column=0,padx=5)
        labelkeysize.config(background="#666699",font="Helvatica")

        keytext = Entry (toplevel2, textvariable=key)
        keytext.grid (row=4, column=1)

        process = Button (toplevel2, text="Encrypt ", command=lambda: CaesarActivate (key, ptext))
        process.grid (row=5, column=1,padx=(10,10),pady=10)
        process.config(background="#666699",font="Helvatica")

    except Exception:
        pass


def CaesarActivate(event, event2):
    global printLabelTxt
    key = event.get ()#
    plaintext = list (event2.get ("1.0", "end-1c"))  # getting input from the GUI & converting string to a list of characters
    try:
        basicCipherObj = basicCiphers(key,plaintext)#creates class instance
        caesarEncrypted=basicCipherObj.CaesarEncrypt()#function call
        ptext.delete("0.0",END)
        ptext.insert (INSERT, caesarEncrypted)
        saveBttn = Button (toplevel2, text="Save", command=lambda: fileSave (ptext))
        saveBttn.grid (row=6, column=1)
        saveBttn.config (background="#666699", font="Helvatica")


    except Exception:
        ptext.delete ("0.0", END)
        ptext.insert (INSERT, "Error!")




def CeasearDecryptGUI():
    quit (toplevel)
    global entext
    global plainTxt
    global enkeytext
    global detemp
    global dekey
    global toplevel3
    dekey = IntVar ()
    plainTxt = StringVar ()
    toplevel3 = Toplevel ()
    try :
        editSystemGUI(toplevel3)

        entext = Text (toplevel3)
        entext.grid (row=2, column=1,padx=(0,10),pady=10)
        entext.bind ("<Return>", focus_next_entrybox)
        entext.focus_set ()

        labelentext = Button(toplevel3, text="Enter cipher text :",command=lambda:loadFileIntoGUI(entext))
        labelentext.grid (row=2, column=0)
        labelentext.config(background="#666699",font="Helvatica")

        labelenkeysize = Label (toplevel3, text="Enter key size (between -25 and 25) :")
        labelenkeysize.grid (row=4, column=0,padx=5)
        labelenkeysize.config(background="#666699",font="Helvatica")

        enkeytext = Entry (toplevel3, textvariable=dekey)
        enkeytext.grid (row=4, column=1)

        deprocess = Button (toplevel3, text="Decrypt ", command=lambda: CaesarDecActivate (dekey, entext))
        deprocess.grid (row=5, column=1,padx=(10,10),pady=10)
        deprocess.config (background="#666699", font="Helvatica")


    except Exception:
        pass


def CaesarDecActivate(event, event2):
    key = event.get ()#getting input from GUI
    cypherMsg = list (event2.get ("1.0", "end-1c"))#getting input from GUI and conversion to list

    try:
        basicCipherObj=basicCiphers(key,cypherMsg)#creates class instance
        unencrypted = basicCipherObj.CaesarDecrypt()#function call
        entext.delete("0.0",END)
        entext.insert (INSERT, unencrypted)
        saveBttn = Button (toplevel3, text="Save", command=lambda: fileSave (entext))
        saveBttn.grid (row=6, column=1)
        saveBttn.config (background="#666699", font="Helvatica")

    except Exception:
        entext.delete ("0.0", END)
        entext.insert (INSERT, "Error!")





def VigEncryptGUI():
    quit (toplevel4)
    global vitext
    global viPlainTxt
    global encrptedTxt
    global toplevel5
    global VigKey

    toplevel5 = Toplevel ()
    editSystemGUI(toplevel5)
    try:
        vitext = Text (toplevel5,width=78)
        vitext.grid (row=2, column=1,pady=10)
        vitext.bind ("<Return>", focus_next_entrybox)
        vitext.focus_set ()

        labelentext = Button (toplevel5, text="Enter Plain Text", command=lambda: loadFileIntoGUI (vitext))
        labelentext.grid (row=2, column=0)
        labelentext.config(background="#666699",font="Helvatica")

        labelenkey = Label (toplevel5, text="Enter key (Text/Numeric/Alphanumeric) :")
        labelenkey.grid (row=4, column=0,padx=5)
        labelenkey.config(background="#666699",font="Helvatica")

        VigKey = Text (toplevel5, height=2, width=30)
        VigKey.grid (row=4, column=1)

        enprocess = Button (toplevel5, text="Encrypt ", command=lambda: vigenereActivate (VigKey, vitext))
        enprocess.grid (row=6, column=1,padx=(10,10),pady=10)
        enprocess.config(background="#666699",font="Helvatica")


    except Exception:
        pass


def vigenereActivate(event, event2):
    try:
        msg = list (event2.get ("1.0", "end-1c"))  # get the input plaintext
        key = event.get ("1.0", "end-1c").upper ()  # get input key and convert to uppercase
        basicCipherObj=basicCiphers(key,msg)#creates class instance
        encryptedMessage = basicCipherObj.VigEncrypt()#function call

        vitext.delete("0.0",END)
        vitext.insert (END, encryptedMessage)
        saveBttn = Button (toplevel5, text="Save", command=lambda: fileSave (vitext))
        saveBttn.grid (row=7, column=1)
        saveBttn.config (background="#666699", font="Helvatica")
    except Exception:
        vitext.delete ("0.0", END)
        vitext.insert (END, "Error!")







def VigDecryptGUI():
    quit (toplevel4)
    global vigCipher
    global vigCipherTxt
    global decryptedTxt
    global toplevel6
    global decryptKey
    try:
        toplevel6 = Toplevel ()
        editSystemGUI(toplevel6)

        vigCipher = Text (toplevel6,width=78)
        vigCipher.grid (row=2, column=1,pady=10)
        vigCipher.bind ("<Return>", focus_next_entrybox)
        vigCipher.focus_set ()

        labelDecText = Button (toplevel6, text="Enter Cipher Text", command=lambda: loadFileIntoGUI (vigCipher))
        labelDecText.grid (row=2, column=0)
        labelDecText.config(background="#666699",font="Helvatica")

        labeldeckey = Label (toplevel6, text="Enter key (Text/Numeric/Alphanumeric):")
        labeldeckey.grid (row=4, column=0,padx=5)
        labeldeckey.config(background="#666699",font="Helvatica")

        decryptKey = Text (toplevel6, height=2, width=30)
        decryptKey.grid (row=4, column=1)

        decprocess = Button (toplevel6, text="Decrypt", command=lambda: vigenereDecActivate (decryptKey, vigCipher))
        decprocess.grid (row=6, column=1,padx=(10,10),pady=10)
        decprocess.config(background="#666699",font="Helvatica")


    except Exception:
        pass


def vigenereDecActivate(event, event2):
    try:
        msg = list (event2.get ("1.0", "end-1c"))  # get the input plaintext
        key = event.get ("1.0", "end-1c").upper ()  # get input key and convert to uppercase
        basicCipherObj=basicCiphers(key,msg)#creates class instance
        deccryptedMessage = basicCipherObj.vigDecrypt()##function call


        vigCipher.delete("0.0",END)
        vigCipher.insert (END, deccryptedMessage)

        saveBttn = Button (toplevel6, text="Save", command=lambda: fileSave (vigCipher))
        saveBttn.grid (row=7, column=1)
        saveBttn.config (background="#666699", font="Helvatica")
    except Exception:
        vigCipher.delete ("0.0", END)
        vigCipher.insert (END, "Error!")






def RouteEncryptGUI():
    quit (toplevel7)
    global plain_message
    global routeKey
    global cells
    global toplevel8
    toplevel8 = Toplevel ()
    try:
        editSystemGUI(toplevel8)
        routeKey = IntVar ()
        cells = IntVar ()


        plain_message = Text (toplevel8)
        plain_message.grid (row=2, column=1,pady=10)
        plain_message.bind ("<Return>", focus_next_entrybox)
        plain_message.focus_set ()

        labelentext = Button (toplevel8, text="Enter plain text", command=lambda: loadFileIntoGUI (plain_message))
        labelentext.grid (row=2, column=0, padx=(10, 10), pady=10)
        labelentext.config (background="#666699", font="Helvatica")

        labelenkey = Label (toplevel8, text="Enter key(1-10) :")
        labelenkey.grid (row=4, column=1,padx=2,pady=5)
        labelenkey.config (background="#666699", font="Helvatica")

        routeEntry = Entry (toplevel8, textvariable=routeKey)
        routeEntry.grid (row=5, column=1,padx=2,pady=5)

        label_cells = Label (toplevel8, text="Enter cell count:")
        label_cells.grid (row=6, column=1,padx=2,pady=5)
        label_cells.config (background="#666699", font="Helvatica")

        cellEntry = Entry (toplevel8, textvariable=cells)
        cellEntry.grid (row=7, column=1,padx=2,pady=5)

        enbutton = Button (toplevel8, text="Encrypt ", command=lambda: routeActivate (routeKey, cells, plain_message))
        enbutton.grid (row=10, column=0,padx=(50,5))
        enbutton.config (background="#666699", font="Helvatica")

        saveBttn = Button (toplevel8, text="Save", command=lambda: fileSave (plain_message))
        saveBttn.grid (row=10, column=2)
        saveBttn.config (state="disabled",background="white", font="Helvatica")


    except Exception:
        pass

def routeActivate(event, event2, event3):
    try:
        routeTxt = event3.get ("1.0", "end-1c").upper ()  # gets input from GUI
        routeShift = event.get ()  # gets input from GUI
        routeCells = event2.get ()  # gets input from GUI
        basicCipherObj=basicCiphers(routeShift,routeTxt)#creates class instance
        routeEncrypted = basicCipherObj.RouteEncrypt (routeCells)#function call
        plain_message.delete("0.0",END)
        plain_message.insert (END, routeEncrypted)
        saveBttn = Button (toplevel8, text="Save", command=lambda: fileSave (plain_message))
        saveBttn.grid (row=10, column=2)
        saveBttn.config (state="normal",background="#666699", font="Helvatica")

    except Exception:
        plain_message.delete ("0.0", END)
        plain_message.insert (END, "Error!")



def RouteDecryptGUI():
    quit (toplevel7)
    global cipher_message
    global decryptKey
    global decryptCells
    global toplevel9
    try:
        toplevel9 = Toplevel ()
        editSystemGUI(toplevel9)
        decryptKey = IntVar ()

        cipher_message = Text (toplevel9)
        cipher_message.grid (row=2, column=1,pady=10)
        cipher_message.bind ("<Return>", focus_next_entrybox)
        cipher_message.focus_set ()

        labelentext = Button (toplevel9, text="Enter Cipher Text", command=lambda: loadFileIntoGUI (cipher_message))
        labelentext.grid (row=2, column=0, padx=(10, 10), pady=10)
        labelentext.config (background="#666699", font="Helvatica")

        labelenkey = Label (toplevel9, text="Enter key(1-10) :")
        labelenkey.grid (row=4, column=0)
        labelenkey.config (background="#666699", font="Helvatica")

        routeEntry = Entry (toplevel9, textvariable=decryptKey)
        routeEntry.grid (row=4, column=1, pady=10)

        debutton = Button (toplevel9, text="Decrypt ", command=lambda: routeDecActivate (decryptKey, cipher_message))
        debutton.grid (row=6, column=1,pady=10)
        debutton.config (background="#666699", font="Helvatica")


    except Exception:
        pass


def routeDecActivate(event, event2):
    try:
        routeTxt = event2.get ("1.0", "end-1c").upper ()  # gets input from GUI
        routeShift = event.get ()  # gets input from GUI
        basicCipherObj=basicCiphers(routeShift,routeTxt)#creates class instance
        routeDecrypted = basicCipherObj.RouteDecrypt()#function call

        cipher_message.delete("0.0",END)
        cipher_message.insert (END, routeDecrypted)

        saveBttn = Button (toplevel9, text="Save", command=lambda: fileSave (cipher_message))
        saveBttn.grid (row=7, column=1)
        saveBttn.config (background="#666699", font="Helvatica")

    except Exception:
        cipher_message.delete ("0.0", END)
        cipher_message.insert (END, "Error!")





class basicCiphers(object):
    def __init__(self,key,msg):
        self.key=key
        self.msg=msg

    def CaesarEncrypt(self):
        cypherTxtList = []  # create empty list
        if self.key >= -26 and self.key <= 26:
            for chrtr in self.msg:  # for every character in list
                if chrtr.isalpha ():  # checks if character is a letter
                    val = ord (chrtr)  # assigns the ASCII value of character to val
                    val += self.key  # add the input key to val which at the moment contains an ASCII number
                    # lines 105-115 ensures that ordinal values do not exceed the ASCII values beyond the alphabet
                    if chrtr.isupper ():  # checks if the character is in uppercase
                        if val > ord ('Z'):  # if val is greater than the ordinal table value of Z
                            val -= 26  # subtract 26 which would produce a value within the alphabetical ordinal range
                            # same theory applies till line 160
                        elif val < ord ('A'):
                            val += 26
                    if chrtr.islower ():
                        if val > ord ('z'):
                            val -= 26
                        elif val < ord ('a'):
                            val += 26
                    cypherTxtList.append (chr (val))  # append the encrypted values to the list

                else:
                    cypherTxtList.append (chrtr)  # if the character isn't a letter append it as it is

            temp = ''.join (cypherTxtList)  # convert list back to string
            return temp
        else:
            return "Invalid key!"

    def CaesarDecrypt(self):
        if self.key >= -26 and self.key <= 26:
            plainTxtList = []

            for chrtr in self.msg:
                if chrtr.isalpha ():
                    val = ord (chrtr)
                    val += -self.key  # adds the complementary value of the key
                    if chrtr.isupper ():
                        if val > ord ('Z'):
                            val -= 26
                        elif val < ord ('A'):
                            val += 26
                    if chrtr.islower ():
                        if val > ord ('z'):
                            val -= 26
                        elif val < ord ('a'):
                            val += 26
                    plainTxtList.append (chr (val))

                else:
                    plainTxtList.append (chrtr)

            temp = ''.join (plainTxtList)
            return temp
        else:
            return "Invalid Key!"

    def VigEncrypt(self):
        ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'  # create alphabet string
        encrypted = []  # create empty list

        index = 0  # create counter variable to go through the key elements

        for el in self.msg:  # for every character in the plaintext string
            val = ALPHABET.find (el.upper ())  # find character in alphabet string and assign its index to val

            if val != -1:  # if character is found in alphabet string

                val += ALPHABET.find (self.key[index])  # get the character in the key at index #
                # find the index of that character in ALPHABET
                # Add that index to val

                val %= len (ALPHABET)  # wrap-aorund,makes sure that val doesn't exceed the length of ALPHABET

                if el.isupper ():  # checks if el is uppercase
                    encrypted.append (
                        ALPHABET[val])  # if uppercase directly append to the list the letter at ALPHABET[val]
                elif el.islower ():  # if el is lowercase
                    encrypted.append (
                        ALPHABET[val].lower ())  # append to the list the letter at ALPHABET[val] in lowercase
                index += 1  # increment index by 1 to move to the next key element
                if index == len (self.key):  # ensures that index doesn't exceed the length of input  key
                    index = 0
            else:  # if the character not found in ALPHABET (not a letter)
                encrypted.append (el)  # directly append it to encrypted list

        encryptedTxt = ''.join (encrypted)  # convert list to string

        return encryptedTxt

    def vigDecrypt(self):
        ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'  # create alphabet string
        decrypted = []  # create empty list

        index = 0  # create counter variable to go through the key elements

        for el in self.msg:  # for every character in the plaintext string
            val = ALPHABET.find (el.upper ())  # find character in alphabet string and assign its index to val

            if val != -1:  # if character is found in alphabet string

                val -= ALPHABET.find (self.key[index])  # get the character in the key at index #
                # find the index of that character in ALPHABET
                # Subtract that index from val

                val %= len (ALPHABET)  # wrap-aorund,makes sure that val doesn't exceed the length of ALPHABET

                if el.isupper ():  # checks if el is uppercase
                    decrypted.append (
                        ALPHABET[val])  # if uppercase directly append to the list the letter at ALPHABET[val]
                elif el.islower ():  # if el is lowercase
                    decrypted.append (
                        ALPHABET[val].lower ())  # append to the list the letter at ALPHABET[val] in lowercase
                index += 1  # increment index by 1 to move to the next key element
                if index == len (self.key):  # ensures that index doesn't exceed the length of input  key
                    index = 0
            else:  # if the character not found in ALPHABET (not a letter)
                decrypted.append (el)  # directly append it to encrypted list

        decryptedTxt = ''.join (decrypted)  # convert list to string
        return decryptedTxt

    def RouteEncrypt(self, cellcount):
        routeCipher = []
        removeSpace = self.msg.replace (" ", "")  # removes all spaces
        textList = list (removeSpace)#coverts to list

        dif = cellcount - len (removeSpace)  # gets the difference between number of charcters in the string and the number of cells given

        try:

            for i in range (cellcount):
                if len (textList) < cellcount:
                    k = len (textList)
                    for k in range (dif):
                        textList.append ("_")  # adds spaces to fill up the shy of characters between cellcount and length of list

            for i in range (self.key):

                for j in range (i, len (textList), self.key):#j=i,j<length of textList,j+=key
                    routeCipher.append (textList[j])  # creates new list with the encrypted text
        except Exception:
            pass

        output = ''.join (routeCipher)  # converts to string
        return output

    def RouteDecrypt(self):
        removeSpace = self.msg.replace ("_", "")  # replaces all underscores in the input text

        plainTxtLst = []

        for char in range (len (removeSpace)):  # Poppulates new array with blank spaces
            plainTxtLst.append (" ")

        index = 0

        try:
            for i in range (self.key):  # loop from 0-key

                for j in range (i, len (removeSpace),
                                self.key):  # loop in the range from i - length of removeSpace with the increment of key
                    plainTxtLst[j] = (removeSpace[index])  # reversing the encryption formula
                    index += 1
        except Exception:
            pass

        output = ''.join (plainTxtLst)
        return output


def getFile():
    try:
        file= askopenfile (filetypes=(("Text Files", "*.txt"), ("All files", "*.*")), title='Open File', mode='r')
        fileLoad = file.read ()
        file.close ()
        getText.delete ("0.0", END)
        getText.insert ("end", fileLoad)
    except Exception:
        getText.delete ("0.0", END)
        getText.insert ("end", "File NOT FOUND!!!")


def FAnalyseGUI():
    global toplevel10
    global getText
    toplevel10 = Toplevel ()
    toplevel10.wm_title ("Frequency Analysis")
    w = 1000
    h = 500
    ws = root.winfo_screenwidth ()
    hs = root.winfo_screenheight ()
    x = (ws / 2) - (w / 2)
    y = (hs / 2) - (h / 2)

    toplevel10.geometry ('%dx%d+%d+%d' % (w, h, x, y))  # give dimensions
    toplevel10.config (background="#000066")
    toplevel10.resizable (0, 0)

    getText = Text (toplevel10)
    getText.grid (row=0, column=1, padx=(10, 20), pady=(10, 20))
    getText.focus_set ()
    getTextBttn= Button (toplevel10, text="Enter Cipher Text",command= lambda:loadFileIntoGUI(getText))
    getTextBttn.grid (row=0, column=2,padx=(10,20),pady=(10,20))
    getTextBttn.config(background="#666699",font="Helvatica")
    inputButton = Button (toplevel10, text="Analyse ", command=lambda: FAnalyseActivate (getText))
    inputButton.grid (row=0, column=3,padx=(10,20),pady=(10,20))
    inputButton.config (background="#666699", font="Helvatica")





def FAnalyseActivate(event):
    try:
        inputText= event.get ("1.0", "end-1c")#getting input text
        lowestEntropyString=FAnalyse(inputText)#function call




        getText.delete ("0.0", END)
        getText.insert (INSERT, lowestEntropyString)

        save = Button (toplevel10,text="Save",command=lambda:fileSave(getText))
        save.grid (row=4, column=1, padx=2, pady=2)
        save.config (background="#666699", font="Helvatica")

    except Exception:
        getText.delete ("0.0", END)
        getText.insert (INSERT, "Error!")


def FAnalyse(inputText):

    lowestEntropy = float ( sys.float_info.max)  # initialized to a large value because all entropies are positive and > than 0
    lowestEntropyString = ""

    for key in range (-26, 26):  # try each key in range
        basicCipherObj = basicCiphers (key, inputText)
        decodedMsg = basicCipherObj.CaesarDecrypt ()  # decode the input message
        entropy = returnEntropy (decodedMsg)  # get the entropy of the decoded text using the corresponding key

        if entropy < lowestEntropy:  # checks if the entropy of decoded text for that key is < than the lowest entropy calculated
            lowestEntropy = entropy  # if true,new lowest entropy is equal to entropy of the decoded message for that key

            lowestEntropyString = decodedMsg
    # the lowest entropy string, aka the string that is most likely to contain the actiual text is the decoded message for that key
    return lowestEntropyString




def returnEntropy(text):
    freq = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
            0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
            0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
            0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
            0.01974, 0.00074]  # letter frequencies
    val = 0.0

    for i in range (len (text)):
        char = text[i]  # get the character at i

        if (ord ('a') <= ord (char) and ord (char) <= ord ('z')):  # ensure the calculataion doesn't exceed the alphabet range
            val += -math.log (freq[ord (char) - ord ('a')]);  # information theory - negative logarithm of probability districbution of possible events
        elif (ord ('A') <= ord (char) and ord (char) <= ord ('Z')):
            val += -math.log (freq[ord (char) - ord ('A')]);

    return val



def checkPassword(event):

    labelTxt = StringVar ()
    numcount = 0
    lettercount=0
    try:
        length = (len (str (pw.get ())))#getting input from GUI and getting the length of the password
        a = pw.get ()#getting input from GUI
        enList = list (a)#converts pw to list
    except Exception:
        pass

    if length < 10:

        labelTxt.set ("Password MUST be at least 10 characters long!")
        pwLabel = Label (toplevel12, textvariable=labelTxt)
        pwLabel.grid (row=3, column=1,padx=5,pady=5)
        pwLabel.config (background="#666699", font="Helvatica")


    elif length > 40:
        labelTxt.set ("Password MUST NOT be MORE than 40 characters!")

        pwLabel = Label (toplevel12, textvariable=labelTxt)
        pwLabel.grid (row=3, column=1,padx=5,pady=5)
        pwLabel.config (background="#666699", font="Helvatica")

    elif length > 9 and length < 41:
        if any (char.isdigit () for char in enList):#checks if the password contains any numbers
            numcount += 1
        if numcount == 0:

            labelTxt.set ("          Password MUST contain at least ONE number!          ")
            pwLabel = Label (toplevel12, textvariable=labelTxt)
            pwLabel.grid (row=3, column=1,padx=5,pady=5)
            pwLabel.config (background="#666699", font="Helvatica")
        if any (char.isalpha () for char in enList):#checks if the password contains any letters
            lettercount += 1
        if lettercount == 0:

            labelTxt.set ("          Password MUST contain both letters and numbers!          ")
            pwLabel = Label (toplevel12, textvariable=labelTxt)
            pwLabel.grid (row=3, column=1,padx=5,pady=5)
            pwLabel.config (background="#666699", font="Helvatica")


        elif numcount != 0 and lettercount!=0:
            try:
                button.config (state="disabled",background="white")
                pw.config (state="disabled")
                labelTxt.set ("               Proceed to enter your text below:                ")

                pwLabel = Label (toplevel12, textvariable=labelTxt)
                pwLabel.grid (row=3, column=1,padx=5,pady=5)
                pwLabel.config (background="#666699", font="Helvatica")
                textFILE.config (state="normal")
                loadFileEncrypt = Button (toplevel12, text=" Enter Plain Text ", state='normal', command=lambda:loadFileIntoGUI(textFILE))
                loadFileEncrypt.grid (row=4, column=1,pady=(0,5))
                loadFileEncrypt.config (background="#666699", font="Helvatica")
                encrypBttn = Button (toplevel12, text="Encrypt :", state='normal',
                                     command=lambda: keyEncrypt (textFILE))
                encrypBttn.grid (row=6, column=1)
                encrypBttn.config (background="#666699", font="Helvatica")

                pw.bind ("<Return>", focus_next_entrybox)
            except Exception:
                pass


def deccheckPassword(event):
    global decLabelTxt
    decLabelTxt = StringVar ()
    numcount = 0
    lettercount=0
    length = (len (str (decPW.get ())))
    a = decPW.get ()
    decList = list (a)
    if length < 10:

        decLabelTxt.set ("Password MUST be at least 10 characters long!")
        # textFILE.config(state="disabled")
        # loadFile = Button (toplevel12, text="Enter plain text :", state='disabled')

        decPwLabel = Label (toplevel13, textvariable=decLabelTxt)
        decPwLabel.grid (row=3, column=1,padx=5,pady=5)
        decPwLabel.config (background="#666699", font="Helvatica")


    elif length > 40:
        decLabelTxt.set ("Password MUST NOT be MORE than 40 characters!")
        # textFILE.config (state="disabled")
        # loadFile = Button (toplevel12, text="Enter plain text :", state='disabled')
        decPwLabel = Label (toplevel13, textvariable=decLabelTxt)
        decPwLabel.grid (row=3, column=1,padx=5,pady=5)
        decPwLabel.config (background="#666699", font="Helvatica")

    elif length > 9 and length < 41:
        if any (char.isdigit () for char in decList):
            numcount += 1
        if numcount == 0:

            decLabelTxt.set ("          Password MUST contain at least ONE number!          ")
            # textFILE.config (state="disabled")
            # loadFile = Button (toplevel12, text="Enter plain text :", state='disabled')
            decPwLabel = Label (toplevel13, textvariable=decLabelTxt)
            decPwLabel.grid (row=3, column=1,padx=5,pady=5)
            decPwLabel.config (background="#666699", font="Helvatica")

        if any (char.isalpha () for char in decList):
            lettercount += 1
        if lettercount == 0:

            decLabelTxt.set ("          Password MUST contain both letters and numbers!          ")
            # textFILE.config (state="disabled")
            # loadFile = Button (toplevel12, text="Enter plain text :", state='disabled')
            decPwLabel = Label (toplevel13, textvariable=decLabelTxt)
            decPwLabel.grid (row=3, column=1,padx=5,pady=5)
            decPwLabel.config (background="#666699", font="Helvatica")


        elif numcount != 0 and lettercount!=0:
            try:
                decBtton.config (state="disabled",background="white",)

                decPW.config (state="disabled")
                decLabelTxt.set ("              Proceed to enter your text below:               ")
                decPwLabel = Label (toplevel13, textvariable=decLabelTxt)
                decPwLabel.grid (row=3, column=1,padx=5,pady=5)
                decPwLabel.config (background="#666699", font="Helvatica")
                decTxtFile.config (state="normal")
                decLoadFile = Button (toplevel13, text="Enter Cipher Text :", state='normal', command=lambda:loadFileIntoGUI(decTxtFile))
                decLoadFile.grid (row=4, column=1)
                decLoadFile.config (background="#666699", font="Helvatica")
                decBttn = Button (toplevel13, text="Decrypt :", state='normal', command=lambda: keyDecrypt (decTxtFile))
                decBttn.grid (row=6, column=1)
                decBttn.config (background="#666699", font="Helvatica")
                decPW.bind ("<Return>", focus_next_entrybox)
            except Exception:
                pass


######################-----------------Encryption Suite--------------#################################

def keyEncrypt(event):
    try:
        aesEncrypt ()
    except Exception:
        pass

def createVigenereKey(event):
    try:
        ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        secretKey = event.get ()
        val = 0
        keySize = 0
        count = 0
        keyString = ""
        secretKList = list (secretKey)
        if secretKey[0].isalpha ():  # if first element is a letter
            val = ord (secretKey[0])  # get the ASCII value of secretkey[0]
            ordList = ([int (y) for y in str (val)])  # convert ASCII value to string, split it into characters and convert them back to integers and create a list of integers
            sumOrd = sum (ordList)
            if sumOrd < 5:  # Ensures that key is long enough
                while (sumOrd < 5):
                    sumOrd += 1
            elif sumOrd > 10:  # Ensures key is not too long
                while (sumOrd > 10):
                    ordList = ([int (y) for y in str (sumOrd)])
                    sumOrd = sum (ordList)
                    if sumOrd < 5:
                        while (sumOrd < 5):
                            sumOrd += 1
            keySize = sumOrd
            for chr in secretKey[
                       :keySize]:  # loop from the beginning of the inpput key to till calculated keySize index
                if chr.isalpha ():  # if the the charcater is a letter
                    keyString += (chr.upper ())  # append in uppercase
                if not chr.isalpha ():
                    keyString += chr  # append the corresponding letter from ALPHABET list
        elif not secretKey[0].isalpha ():  # if first element is number
            index = int (secretKey[0])
            if index < 5:
                while (index < 5):
                    index += 1
            keySize = index  # keySize is equal to value of first index in integet form
            for char in secretKey[:keySize]:
                if char.isalpha ():
                    keyString += (char.upper ())
                elif char.isdigit ():
                    keyString += char#append the character as it is
    except Exception:
        pass
    return keyString

def createVigenere():
    try:
        keyString=createVigenereKey(pw)#function call
        toEncrypt=textFILE.get("1.0", "end-1c")#gets input
        basicCipherObj=basicCiphers(keyString,toEncrypt)#creates class instance
        vigenereEncrypted = basicCipherObj.VigEncrypt()#function call
    except Exception:
        pass
    return vigenereEncrypted

def columnarKeyGen(event):
    try:
        val = 0
        keySize = 0
        count = 0
        colkeyString = ""
        ALPHABET = 'ZYXWVUTSRQPONMLKJIHGFEDCBA'#reverse alpahbet
        key = list (event.get ())#gets input
        if key[9].isalpha ():#if key[9] is a letetr

            val = ord (key[9])#get ordinal value

            ordList = ([int (y) for y in str (val)])#creates an integer list from the ordinal value split to its digits
            sumOrd = sum (ordList)#get sum
            if sumOrd < 5:
                while (sumOrd < 5):
                    sumOrd += 1
            elif sumOrd > 10:
                while (sumOrd > 10):
                    ordList = ([int (y) for y in str (sumOrd)])
                    sumOrd = sum (ordList)
                    if sumOrd < 5:
                        while (sumOrd < 5):
                            sumOrd += 1

            keySize = sumOrd

            for char in key[:keySize]: # loop from the beginning of the inpput key to till calculated keySize index
                if char.isalpha ():#if character is a letter
                    colkeyString += (char.upper ())#append in uppercase
                if not char.isalpha ():
                    colkeyString += ALPHABET[int (char)]#append corresponding letter from the alphabet list

        elif not key[9].isalpha ():
            index = int (key[9])

            if index < 5:
                while (index < 5):
                    index += 1

            keySize = index


            for char in key[:keySize]:
                if char.isalpha ():
                    colkeyString += (char.upper ())
                if char.isdigit ():
                    colkeyString += ALPHABET[int (char)]
    except Exception:
        pass
    return colkeyString

def columnarKey():
    try:
        colkeyString=columnarKeyGen(pw)#get input
        encryptedTxt=createVigenere()#function call
        columnarObj=columnarCipher(colkeyString,encryptedTxt)#creates class instance
        colEncoded=columnarObj.encrypt()#function call
    except Exception:
        pass
    return colEncoded





def sort(val,keyTemp):  # orders key in alphabetical order
    temp = 0
    try:
        for i in range (val - 1):#i=0 to val -1
            for j in range (i, val):#j=1 to val
                if ord (keyTemp[i]) > ord (keyTemp[j]):
                    temp = keyTemp[i]
                    keyTemp[i] = keyTemp[j]
                    keyTemp[j] = temp
    except Exception:
        pass


def aesEncrypt():
    try:
        global secretK
        global outputTxt
        secretK = pw.get ()
        aesObj = AESCipher (secretK)
        encodedStr=columnarKey()
        encryptedTxt = aesObj.encryptAES (encodedStr)
        textFILE.delete ("0.0", END)
        textFILE.insert ("0.0", encryptedTxt)
        saveBttn = Button (toplevel12, text="Save", command=lambda: fileSave (textFILE))
        saveBttn.grid (row=7, column=1,padx=5,pady=5)
        saveBttn.config ( background="#666699", font="Helvatica")
    except Exception:
        textFILE.delete ("0.0", END)
        textFILE.insert ("0.0" ,"Bad Input!!!!!")


############################----------Decryption Suite-----########################################


def keyDecrypt(event):
    try:
     vigenereDecKey ()
    except Exception:
        pass

def aesDecrypt():
    try:
        decSecret = decPW.get ()
        aesDecObj = AESCipher (decSecret)#creaets class instance
        decTxt = aesDecObj.decryptAES (decTxtFile.get ("1.0", "end-1c"))#method call
    except Exception:
        pass
    return decTxt

def columnarDecKey():
    try:
        colkeyString = columnarKeyGen(decPW)
        decTxt =aesDecrypt()
        columnarObj=columnarCipher(colkeyString,decTxt)#creates class instance
        colString=columnarObj.decrypt()#method call
    except Exception:
        pass
    return colString


class columnarCipher(object):
    def __init__(self,keyVal,msg):
        self.keyVal=keyVal
        self.msg=msg
    def encrypt(self):
        try:
            keyArray = list (self.keyVal)
            keyTemp = list (self.keyVal)
            row = len (self.msg) / len (self.keyVal)
            if (len (self.msg) % len (self.keyVal) != 0):  # ensures that all letters of the input string will be considered
                row += 1
            col = len (self.keyVal)
            arr = [[0] * col for i in range (row)]  # populates 2D array
            enArr = [[0] * col for i in range (row)]
            k = 0
            for x in range (row):
                for y in range (col):
                    if k < len (self.msg):  # checks the value of k is less than the length of the message
                        arr[x][y] = self.msg[k]  # if true, store the value at encryptedTxt[k] in arr[x][y] location
                        k += 1
                    else:
                        arr[x][y] = ' '  # if false, store ' ' at the array
            sort (col, keyTemp)  # sorts keyTemp in in alphabetical order
            for i in range (col):
                for j in range (col):
                    if keyArray[i] == keyTemp[j]:
                        for k in range (row):
                            enArr[k][j] = arr[k][i]#creates new array with encrypted text
                        keyTemp[j] = '?'  # ensures that the values are not repeated
                        break
            encodedStr = ""
            for i in range (col):
                for j in range (row):
                    encodedStr += enArr[j][i]#array to string conversion
        except Exception:
            pass
        return encodedStr
    def decrypt(self):
        try:
            keyArray = list (self.keyVal)
            keyTemp = list (self.keyVal)
            row = len (self.msg) / len (self.keyVal)
            if (len (self.msg) % len (self.keyVal) != 0):
                row += 1
            col = len (self.keyVal)
            arr = [[0] * col for i in range (row)]
            decArr = [[0] * col for i in range (row)]
            k = 0
            for x in range (col):
                for y in range (row):
                    if k < len (self.msg):  # checks the value of k is less than the length of the message
                        arr[y][x] =self.msg[k]  # if true, store the value at encryptedTxt[k] in arr[x][y] location
                        k += 1
                    else:
                        arr[y][x] = ' '  # if false, store ' ' at the array
            sort (col, keyTemp)
            for i in range (col):
                for j in range (col):
                    if keyArray[j] == keyTemp[i]:
                        for k in range (row):
                            decArr[k][j] = arr[k][i]
                        keyArray[j] = '?'
                        break
            decString = ""
            for i in range (row):
                for j in range (col):
                    decString += decArr[i][j]
        except Exception:
            pass
        return decString


def vigenereDecKey():
    try:
        toDecrypt = columnarDecKey()
        keyString=createVigenereKey(decPW)
        basicCipherObj=basicCiphers(keyString,toDecrypt)
        finalOutput=basicCipherObj.vigDecrypt()
        decTxtFile.delete ("0.0", END)
        decTxtFile.insert (INSERT, finalOutput)
        saveBttn = Button (toplevel13, text="Save", command=lambda: fileSave (decTxtFile))
        saveBttn.grid (row=7, column=1,padx=10,pady=5)
        saveBttn.config (background="#666699", font="Helvatica")
    except Exception:
        decTxtFile.delete ("0.0", END)
        decTxtFile.insert ("0.0", "Bad Input!!!!")




####################################################################
basicString = 16
pad = lambda insString: insString + (basicString - len (insString) % basicString) * chr (basicString - len (insString) % basicString)#adds the bytes required
unpad = lambda insString: insString[:-ord (insString[len (insString) - 1:])]#removes the added bytes


class AESCipher (object):
    def __init__(self, key):
        self.key = pad (key)

    def encryptAES(self, plainMsg):
        try:
            plainMsg = pad (plainMsg)
            iv = Random.new ().read (AES.block_size)  # adds randomsness to the start of the encryption
            cipher = AES.new (self.key, AES.MODE_CBC, iv)
            return base64.b64encode (iv + cipher.encrypt (plainMsg))
        except Exception:
            print Exception


    def decryptAES(self, cipherMsg):
        try:
            cipherMsg = base64.b64decode (cipherMsg)
            iv = cipherMsg[:16]  # get first sixteen elements as the iv
            cipher = AES.new (self.key, AES.MODE_CBC, iv)
            return unpad (cipher.decrypt (cipherMsg[16:]))
        except Exception:
            print Exception


####################################################################



####################################################################





def keyEnGUI():
    global encryptionActive
    global pw
    global pwLabel
    global toplevel12
    global button
    global loadFile
    global textFILE
    global encrypBttn
    global toEncrypt



    toplevel11.destroy ()
    toplevel12 = Toplevel ()
    try:
        editSystemGUI(toplevel12)
        pwTxt = StringVar ()
        pwLabel = Label (toplevel12, text="Enter password :")
        pwLabel.grid (row=1, column=0,padx=10,pady=5)
        pwLabel.config (background="#666699", font="Helvatica")
        pw = Entry (toplevel12, textvariable=pwTxt)
        pw.grid (row=1, column=1)
        pw.focus_set ()

        textFILE = Text (toplevel12, height=20, width=80)
        textFILE.config (state="disabled")
        textFILE.grid (row=5, column=1)

        button = Button (toplevel12, text="Enter", command=lambda: checkPassword (pw))
        button.grid (row=2, column=1,pady=(0,5))
        button.config (background="#666699", font="Helvatica")


        loadFileEncrypt = Button (toplevel12, text="Enter Plain Text :", state='disabled', command=lambda:loadFileIntoGUI (textFILE))
        loadFileEncrypt.grid (row=4, column=1,pady=(0,5))
        loadFileEncrypt.config (background="white", font="Helvatica")

        encrypBttn = Button (toplevel12, text="Encrypt :", state='disabled', command=lambda: keyEncrypt (textFILE))
        encrypBttn.grid (row=6, column=1,padx=5,pady=5)
        encrypBttn.config (background="white", font="Helvatica")


    except Exception:
        pass


def keyDecGUI():
    toplevel11.destroy ()
    global toplevel13
    toplevel13 = Toplevel ()
    global decPW
    global decBttn
    global decLoadFile
    global decPwLabel
    global decTxtFile
    global decBtton
    try:
        editSystemGUI (toplevel13)
        decPwTxt = StringVar ()
        decPwLabel = Label (toplevel13, text="Enter password :")
        decPwLabel.grid (row=1, column=0, padx=10, pady=5)
        decPwLabel.config (background="#666699", font="Helvatica")
        decPW = Entry (toplevel13, textvariable=decPwTxt)
        decPW.grid (row=1, column=1, padx=5, pady=5)
        decPW.focus_set ()

        decTxtFile = Text (toplevel13, height=20, width=80)
        decTxtFile.config (state="disabled")
        decTxtFile.grid (row=5, column=1)

        decBtton = Button (toplevel13, text="Enter", command=lambda: deccheckPassword (decPW))
        decBtton.grid (row=2, column=1)
        decBtton.config (background="#666699", font="Helvatica")




        decLoadFile = Button (toplevel13, text="Enter Cipher Text ", state='disabled', command=lambda:loadFileIntoGUI (decTxtFile))
        decLoadFile.grid (row=4, column=1, padx=5, pady=5)
        decLoadFile.config (background="white", font="Helvatica")

        decBttn = Button (toplevel13, text="Decrypt :", state='disabled', command=lambda: keyDecrypt (decTxtFile))
        decBttn.grid (row=6, column=1, padx=10, pady=5)
        decBttn.config (background="white", font="Helvatica")
    except Exception:
        pass


def fileSave(event):
    try:

            text = event.get ('1.0', END + '-1c')

            with asksaveasfile (mode='w', defaultextension='.txt', title='Save the encrypted file') as f:
                f.write (text)
    except Exception:
        pass

def mainGUI():
    global root
    root = Tk ()
    root.wm_title ("Crypto")
    w = 300
    h = 280
    ws = root.winfo_screenwidth ()
    hs = root.winfo_screenheight ()
    x = (ws / 2) - (w / 2)
    y = (hs / 2) - (h / 2)

    root.geometry ('%dx%d+%d+%d' % (w, h, x, y))  # give dimensions
    root.config (background="#000066")
    root.resizable (0, 0)
    frame = Frame (root)
    frame.grid ()
    b = Button (text="Caesar  ", command=getOptionCaesar)
    b.grid (row=0, column=8,rowspan=5,columnspan=2,padx=100,pady=7)
    b.config(background="#666699",font="Helvatica")
    b2 = Button (text="Vigenere", command=getOptionVigenere)
    b2.grid (row=5, column=8,rowspan=3,columnspan=2,padx=10,pady=5)
    b2.config(background="#666699",font="Helvatica")
    b3 = Button (text="Route   ", command=getOptionRoute)
    b3.grid (row=8, column=8,rowspan=3,columnspan=2,padx=10,pady=5)
    b3.config(background="#666699",font="Helvatica")
    b4 = Button (text="Frequency Analysis  ", command=FAnalyseGUI)
    b4.grid (row=11, column=8,rowspan=3,columnspan=2,padx=10,pady=5)
    b4.config(background="#666699",font="Helvatica")
    b5 = Button (text="Key Mgt System ", command=getOptionKey)
    b5.grid (row=14, column=8,rowspan=3,columnspan=2,padx=10,pady=5)
    b5.config(background="#666699",font="Helvatica")
    root.mainloop ()


if __name__ == '__main__':
    mainGUI ()
