import tkinter as tk 
from tkinter import filedialog
from string import ascii_uppercase,ascii_lowercase
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

#MY_STRING = None


SALT = b'\xd2\xed\xb5Hz\xa0\x87\xbfl\x16s\xfe\x94/\xc7I\xfe"\xb5\xbb\xafP\xc09\xe2\xc4\xc7\x0b\x97\xf0\x94\n'
PASSWORD = "hefwuhewufeuwhduqdiajidjsai"


my_string = "hello world"

salt = b'\xd2\xed\xb5Hz\xa0\x87\xbfl\x16s\xfe\x94/\xc7I\xfe"\xb5\xbb\xafP\xc09\xe2\xc4\xc7\x0b\x97\xf0\x94\n'
password = "hefwuhewufeuwhduqdiajidjsai"
key = PBKDF2(password,salt,dkLen=32)
cipher = AES.new(key, AES.MODE_CBC)
text = my_string.encode()
encrypted_text = cipher.encrypt(pad(text,AES.block_size))

with open("/tmp/encrypted.bin","wb") as f:
    f.write(cipher.iv)
    f.write(encrypted_text)


with open("/tmp/encrypted.bin","rb") as f:
    iv = f.read(16)
    data = f.read()

cipher = AES.new(key, AES.MODE_CBC,iv = iv)
og = unpad(cipher.decrypt(encrypted_text),AES.block_size)
print("og is: ", og.decode())



#custom ROT 11
def encode(strng):
    my_string = list(strng)
    lower = list(ascii_lowercase)
    lower.extend(["(",")",".",",","$","1","2","3","4","5","6","7","8","9","0","+","-","*"," "])
    upper = list(ascii_uppercase)
    encoded_string = ""
   
    for c in my_string:
        Li = None
        Ui = None
        try:
            Li = lower.index(c) 
        except:
            Ui = upper.index(c) 

        if Li != None:
            Li += 11
            if Li > 45:
                Li -= 45            
            
            encoded_string += lower[Li]

        if Ui != None:
            Ui += 11
            if Ui > 25:
                Ui -= 25            
            
            encoded_string += upper[Ui]   
    
    return encoded_string


def decode(encoded_string):
    my_string = list(encoded_string)
    lower = list(ascii_lowercase)
    lower.extend(["(",")",".",",","$","1","2","3","4","5","6","7","8","9","0","+","-","*"," "])
    upper = list(ascii_uppercase)
    original_string = ""

    for c in my_string:
        Li = None
        Ui = None
        try:
            Li = lower.index(c) 
        except:
            Ui = upper.index(c) 

        if Li != None:
            Li -= 11
            if Li < 0:
                Li = 45 + Li           
            
            original_string += lower[Li]

        if Ui != None:
            Ui -= 11
            if Ui < 0:
                Ui = 25 + Ui            
            
            original_string += upper[Ui]   
    
    #print("original_string = ", original_string) 
    return original_string


def encrypt(my_string):
    key = PBKDF2(password,salt,dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC)
    text = my_string.encode()
    encrypted_text = cipher.encrypt(pad(text,AES.block_size))

    with open("/tmp/encrypted.bin","wb") as f:
        f.write(cipher.iv)
        f.write(encrypted_text)

    return encrypted_text

def decrypt(my_string):
    
    with open("/tmp/encrypted.bin","rb") as f:
        iv = f.read(16)
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC,iv = iv)
    og = unpad(cipher.decrypt(data),AES.block_size)
    print("og is: ", og.decode())

    return og
    

def application():

    root = tk.Tk()
    root.geometry("500x500")
    root.title("gui-encryptor-overwriter")

    canvas = tk.Canvas(root,background="light grey",width=500,height=500)
    canvas.place(x = 0, y = 0)

    text_area = tk.Text(canvas)    
    text_area.place(x = 0, y = 30)
    text_area.config(height=36,width=71)

    def file_select(event):
        if str(event) == "save":
            #print("save as")
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*"), ("Csv Files", ".csv")])

            MY_STRING = text_area.get("1.0", "end-1c")
            #print("contents of text area are: ")   
            #print(MY_STRING)  

            if file_path:
                with open(file_path,"w") as f:
                    f.write(MY_STRING)

        if str(event) == "encode":
            MY_STRING = text_area.get("1.0", "end-1c")
            encoded_string = encode(MY_STRING)
            text_area.delete("1.0", "end-1c")
            text_area.insert("1.0",encoded_string)
            
        if str(event) == "decode":
            MY_STRING = text_area.get("1.0", "end-1c")
            original_string = decode(MY_STRING)
            #print("original string decode: ",original_string)
            text_area.delete("1.0","end-1c")
            text_area.insert("1.0",original_string)

        if str(event) == "encrypt":
            MY_STRING = text_area.get("1.0", "end-1c")
            encrypted_string = encrypt(MY_STRING)
            text_area.delete("1.0","end-1c")
            text_area.insert("1.0",encrypted_string)

        if str(event) == "decrypt": 
            MY_STRING = text_area.get("1.0", "end-1c")
            original_string = decrypt(MY_STRING)
            text_area.delete("1.0","end-1c")
            text_area.insert("1.0",original_string)

        if str(event) == "open":
            file_path = filedialog.askopenfilename()
            
            if file_path:
                contents = open(file_path,"r").read()
                text_area.delete("1.0","end-1c")
                text_area.insert("1.0",contents)

        if str(event) == "overwrite":
                contents = "overwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwriteoverwrite"
                text_area.delete("1.0","end-1c")
                text_area.insert("1.0",contents)
                file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*"), ("Csv Files", ".csv")])
                with open(file_path,"w") as f:
                    f.write(contents)



    chosen_option = tk.StringVar()
    chosen_option.set("file")
    options = ["save","open"]
    dropdown1 = tk.OptionMenu(canvas, chosen_option,*(options), command= file_select)
    dropdown1.place(x = 0, y = 0)

    chosen_option2 = tk.StringVar()
    chosen_option2.set("edit")
    options2 = ["encrypt", "decrypt", "overwrite", "encode", "decode"]
    dropdown2 = tk.OptionMenu(canvas, chosen_option2, *(options2), command= file_select)
    dropdown2.place(x = 65, y = 0)

    root.mainloop()


application()