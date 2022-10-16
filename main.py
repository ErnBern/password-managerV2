import string, random, customtkinter

from cryptography.fernet import Fernet
from customtkinter import *
import tkinter.font as tkFont

clear = ''

# Creating/opening the master password file
try:
    master_pw_file = open("masterpw.txt", 'r+')
except:
    master_pw_file = open("masterpw.txt", 'x+')
master_string = master_pw_file.readlines()

reset_password = False

master_password = ''
master_key = ''
decrypted_master_password = ''

app = CTk()
customtkinter.set_appearance_mode('system')
app.title("Password Manager")
width = 400
height = 150
app.geometry(f"{width}x{height}")

app.update_idletasks()
app.update()

def gen_master_pw(password):
    global reset_password
    global first_time_run
    global master_password
    global master_key
    global master_string
    global decrypted_master_password

    if len(password) == 0:
        return
    master_key = Fernet.generate_key()
    fernet = Fernet(master_key)
    encrypted_password = fernet.encrypt(password.encode()).decode('utf-8')
    with open('masterpw.txt', 'a+') as file:
        file.write(f"{encrypted_password}\n")
    reset_password = True
    with open('masterpw.txt', 'r+') as file:
        master_string = file.readlines()
        with open('masterpw.txt', 'a+') as f:
            f.write(master_key.decode('utf8'))
        master_key = master_string[1].encode('utf-8')
        decrypted_master_password = password
    mainpage()
    return


def startup():
    global reset_password
    CTkLabel(master=app, text="Set Master Password:", height=5).pack(pady=10, padx=10)
    password = CTkEntry(master=app, width=200, placeholder_text='Password')
    password.pack(pady=10, padx=20)
    CTkButton(master=app, text="Confirm", command=lambda: gen_master_pw(password.get())).pack(pady=20, padx=10)
    return

def encrypt(message, key):
    return Fernet(key).encrypt(message).decode('utf-8')


def decrypt(message, token):
    return Fernet(token).decrypt(message).decode('utf-8')

class addPassword:
    def __init__(self, username='', email='', app='', password=''):
        self.username = username
        self.app = app
        self.password = password
        self.email = email

    def add_website(self):
        global width, height
        #Clearing the window
        for widget in app.winfo_children():
            widget.destroy()
        width = 400
        height = 175

        app.geometry(f'{width}x{height}')
        CTkLabel(master=app, text="Website/App", height=10, text_font=('default', 14)).pack(pady=10, padx=20)
        entry = CTkEntry(master=app, width=200, placeholder_text='www.example.com')
        entry.pack(pady=10, padx=20)
        confirm = CTkButton(master=app, text="Confirm", command=lambda: addPassword().set(1, entry, []))
        confirm.pack(pady=20, padx=10)

    def add_email(self, array):
        global width, height
        for widget in app.winfo_children():
            widget.destroy()
        width = 400
        height = 175

        app.geometry(f'{width}x{height}')
        CTkLabel(master=app, text="Email", height=10, text_font=('default', 14)).pack(pady=10, padx=20)
        entry = CTkEntry(master=app, width=200, placeholder_text='example@example.com')
        entry.pack(pady=10, padx=20)
        confirm = CTkButton(master=app, text="Confirm", command=lambda: addPassword().set(2, entry, array))
        confirm.pack(pady=20, padx=10)

    def add_username(self, array):
        global width, height
        for widget in app.winfo_children():
            widget.destroy()
        width = 400
        height = 175

        app.geometry(f'{width}x{height}')
        CTkLabel(master=app, text="Username", height=10, text_font=('default', 14)).pack(pady=10, padx=20)
        entry = CTkEntry(master=app, width=200, placeholder_text='Username')
        entry.pack(pady=10, padx=20)
        confirm = CTkButton(master=app, text="Confirm", command=lambda: addPassword().set(3, entry, array))
        confirm.pack(pady=20, padx=10)

    def password_confirm(self, array):
        global width, height
        for widget in app.winfo_children():
            widget.destroy()
        width = 350
        height = 150

        app.geometry(f'{width}x{height}')
        CTkLabel(master=app, text="Generate Password?", height=10).pack(pady=5, padx=20)
        yes = CTkButton(master=app, text="Yes", command=lambda: addPassword().pw_gen_len(array))
        yes.pack(pady=10, padx=10)
        no = CTkButton(master=app, text="No", command=lambda: addPassword().set_password(array), fg_color='#D10000', hover_color='#A30000')
        no.pack(pady=15, padx=10)

    def set_password(self, array):
        global width, height
        for widget in app.winfo_children():
            widget.destroy()
        width = 400
        height = 175

        app.geometry(f'{width}x{height}')
        CTkLabel(master=app, text="Password", height=10, text_font=('default', 14)).pack(pady=10, padx=20)
        entry = CTkEntry(master=app, width=200, placeholder_text='Password')
        entry.pack(pady=10, padx=20)
        confirm = CTkButton(master=app, text="Confirm", command=lambda: addPassword().set(4, entry, array))
        confirm.pack(pady=20, padx=10)
    #Getting the password length
    def pw_gen_len(self, array, invalid=False):
        def check():
            pw_length = entry.get()
            if not pw_length.isdigit() and pw_length:
                addPassword().pw_gen_len(array, True)
            if pw_length.isdigit() and pw_length:
                 addPassword().gen_options(array, pw_length)

        global width, height
        for widget in app.winfo_children():
            widget.destroy()
        width = 400
        height = 175

        app.geometry(f'{width}x{height}')
        if invalid:
            app.geometry(f'{width}x{height + 25}')
            lbl = CTkLabel(master=app, text="Invalid Length!", height=5, text_font=('default', 14))
            lbl.pack(pady=5, padx=20)
            lbl.focus()
            invalid = False
        CTkLabel(master=app, text="Password Length", height=10).pack(pady=10, padx=20)
        entry = CTkEntry(master=app, width=200, placeholder_text='16')
        entry.pack(pady=10, padx=20)
        pw_length = entry.get()
        if not pw_length.isdigit() and pw_length:
            addPassword().pw_gen_len(array, True)
        confirm = CTkButton(master=app, text="Confirm", command=check)
        confirm.pack(pady=20, padx=10)

    def set(self, type, entry, array):
        if type == 1:
            self.app = entry.get()
            array.append(self.app)
            addPassword().add_email(array)
        if type == 2:
            self.email = entry.get()
            array.append(self.email)
            addPassword().add_username(array)
        if type == 3:
            self.username = entry.get()
            array.append(self.username)
            addPassword().password_confirm(array)
        if type == 4:
            #Encrypting and writing the password to the "passwords" file
            self.password = entry.get()
            self.app = array[0]
            self.email = array[1]
            self.username = array[2]
            #If the anything is blank, set it to something random
            #So it doesn't cause an error
            if self.app == '':
                self.app = 'siaosdhaoishdoiahaosisjda;]['
            if self.email == '':
                self.email = 'siaosdhaoishdoiahaosisjda;]['
            if self.password == '':
                self.password = 'siaosdhaoishdoiahaosisjda;]['
            if self.username == '':
                self.username = 'siaosdhaoishdoiahaosisjda;]['
            with open('passwords.txt', 'rb') as file:
                passwords_array = file.readlines()
                place = len(passwords_array)
                key = passwords_array[0]
            with open('passwords.txt', 'a') as file:
                record = encrypt(f"{place} {self.app} {self.email} {self.username} {self.password}\n".encode(), key)
                file.write(f'{record}\n')
                file.close()
            mainpage()

    def gen_options(self, array, length):
        def set():
            type = rb_var.get()
            self.app = array[0]
            self.email = array[1]
            self.username = array[2]
            self.password = addPassword().generate(int(length), type)
            with open('passwords.txt', 'rb') as file:
                passwords_array = file.readlines()
                place = len(passwords_array)
                key = passwords_array[0]
            with open('passwords.txt', 'a') as file:
                record = encrypt(f"{place} {self.app} {self.email} {self.username} {self.password}\n".encode(), key)
                file.write(f'{record}\n')
                file.close()
            mainpage()
        global width, height
        for widget in app.winfo_children():
            widget.destroy()
        width = 420
        height = 400
        CTkLabel(master=app, text="Options", height=10, text_font=('default', 14)).grid(padx=120, sticky='w')
        #rb Stands For Radio Button
        rb_var = IntVar()
        opt1 = CTkRadioButton(master=app, variable=rb_var, text="Uppercase and lowercase letters", value=1, text_font=('default', 12))
        opt1.grid(pady=5, padx=10, sticky='w')
        opt2 = CTkRadioButton(master=app, variable=rb_var, text="Option 1 but with numbers", value=2, text_font=('default', 12))
        opt2.grid(pady=5, padx=10, sticky='w')
        opt3 = CTkRadioButton(master=app, variable=rb_var, text="Option 2 but with special characters", value=3, text_font=('default', 12))
        opt3.grid(pady=5, padx=10, sticky='w')
        button = CTkButton(master=app, text='Confirm', text_font=('default', 12), command=set)
        button.grid(pady=5, sticky='n')

    def generate(self, length, security_type):
        if security_type == 1:
            letters = string.ascii_letters
            return ''.join(random.choice(letters) for i in range(length))
        if security_type == 2:
            letters = string.ascii_letters + string.digits
            return ''.join(random.choice(letters) for i in range(length))
        if security_type == 3:
            letters = string.ascii_letters + string.digits + string.punctuation
            return ''.join(random.choice(letters) for i in range(length))

class deletePassword:
    def del_pw(self):
        global width, height
        for widget in app.winfo_children():
            widget.destroy()
        width = 325
        height = 175

        app.geometry(f'{width}x{height}')
        CTkLabel(master=app, text="Select Password", text_font=('default', 14)).pack(pady=5, padx=20)
        with open('passwords.txt', 'r') as file:
            passwords = file.readlines()
            #Subtracting 1 from len(passwords) since the key is stored in the same file
            passwords_len = len(passwords) - 1

        options = []
        for x in range(0, passwords_len):
            x += 1
            options.append(f"Password {x}")

        box = CTkComboBox(master=app, values=options, height=30, width=175, text_font=('default', 12))
        box.set("Select Password")
        box.pack(pady=20, padx=10)

        btn = CTkButton(master=app, text="Confirm", text_font=('default', 11), command=lambda: deletePassword().delete(box.get()))
        btn.pack(pady=10, padx=10)

    def delete(self, order):
        if order == 'Select Password': return mainpage()
        #Taking out the word "Password" to leave only the integer
        order = int(order.split('Password')[1]) - 1
        with open('passwords.txt', 'r') as file:
            enc_info = file.readlines()
            key = enc_info[0].encode('utf-8')
            file.close()
        #List with the old order
        old_info = []
        #List with the new order
        new_info = []
        for info in enc_info:
            if info.encode('utf-8') == key: continue
            #Decrypting the stored info and turing it into a list
            info_list = decrypt(info.encode('utf-8'), key).split(" ")
            old_info.append(info_list)
        password_info = old_info[order]
        old_info.remove(password_info)
        #Correcting the order
        for new_order in range(len(old_info)):
            info = old_info[new_order]
            info[0] = new_order + 1
            new_info.append(info)
        with open('passwords.txt', 'w+') as file:
            file.write(key.decode('utf-8'))
            #Writing the new info
            for info in new_info:
                record = encrypt(f'{info[0]} {info[1]} {info[2]} {info[3]}\n'.encode('utf-8'), key)
                file.write(f'{record}\n')
            file.close()
            mainpage()
#Creating the main page
def mainpage():
    global width, height
    for widget in app.winfo_children():
        widget.destroy()
    global reset_password
    if reset_password:
        reset_password = False

    CTkLabel(master=app, text="Password Manager", height=10, text_font=('default', 14)).grid(ipady=10, ipadx=50)
    add_password = CTkButton(master=app, text='New Password', command=lambda: addPassword().add_website(), width=20)
    add_password.grid(pady=10, padx=360, row=1)
    del_pw = CTkButton(master=app, text='Delete Password', command=deletePassword().del_pw, width=20, fg_color='#D10000', hover_color='#A30000')
    del_pw.grid(pady=10, padx=360, row=2)
    width = 790
    height = 220
    starting_row = 4

    CTkLabel(master=app, text='Order:', text_font=('default', 12)).grid(padx=10, column=0, row=starting_row, sticky='w')
    CTkLabel(master=app, text='App/Website:', text_font=('default', 12)).grid(padx=150, column=0, row=starting_row, sticky='w')
    CTkLabel(master=app, text='Email:', text_font=('default', 12)).grid(padx=275, column=0, row=starting_row)
    CTkLabel(master=app, text='Username:', text_font=('default', 12)).grid(padx=175,column=0, row=starting_row, sticky='e')
    CTkLabel(master=app, text='Password:', text_font=('default', 12)).grid(padx=10, column=0, row=starting_row, sticky='e')
    try:
        with open('passwords.txt', 'r') as f:
            f.close()
    except:
        pass
    info_write = open('passwords.txt', 'a+')
    info_read = open('passwords.txt', 'r')
    all_info = info_read.readlines()
    try:
        key = all_info[0].strip().encode('utf-8')
    except:
        #Making the key if it doesn't exist
        key = Fernet.generate_key().decode('utf-8')
        info_write.write(f'{key}\n')
        info_write.close()
        info_read.close()
        key = key.encode('utf-8')
    starting_row += 1
    information = []

    for info in all_info:
        if info.strip().encode('utf-8') == key: continue
        #Decrypting the information and turning it into a list
        decrypted_info = decrypt(info.strip().encode('utf-8'), key).split(" ")
        information.append(decrypted_info)
    for info in information:
        #Reverting the random values to blank
        if info[1] == 'siaosdhaoishdoiahaosisjda;][': info[1] = ''
        if info[2] == 'siaosdhaoishdoiahaosisjda;][': info[2] = ''
        if info[3] == 'siaosdhaoishdoiahaosisjda;][': info[3] = ''
        if info[4] == 'siaosdhaoishdoiahaosisjda;][': info[4] = ''
        #Writing and resizing the window
        CTkLabel(master=app, text=f"{info[0]}.").grid(padx=10, column=0, row=starting_row, sticky='w')
        CTkLabel(master=app, text=f'{info[1]}').grid(padx=150, column=0, row=starting_row, sticky='w')
        CTkLabel(master=app, text=f'{info[2]}').grid(padx=275, column=0, row=starting_row)
        CTkLabel(master=app, text=f'{info[3]}').grid(padx=175, column=0, row=starting_row, sticky='e')
        #Making the password selectable with the mouse
        pw_text = CTkTextbox(master=app, height=1, border_width=0)
        pw_text.grid(padx=30, column=0, row=starting_row, sticky='e')
        pw_text.insert("1.0", f"{info[4]}")
        #Making the textbox fit the text and disabling the text box
        size = 10
        if len(info[4]) >= 21: size = 8
        font = tkFont.Font(family='default', size=size)
        pw_width = font.measure(f"{info[4]}")
        pw_text.configure(state='disabled', width=pw_width, text_font=font)
        height += 25
        starting_row += 1
    width += 20
    app.geometry(f'{width}x{height}')

attempts = 0

if not master_string:
    startup()
    try:
        master_pw_file = open("masterpw.txt", 'r+')
    except:
        master_pw_file = open("masterpw.txt", 'x+')

if len(master_string) == 2:
    height = 200
    app.geometry(f"{width}x{height}")
    # Clearing the window
    for widget in app.winfo_children():
        widget.destroy()
    master_password = master_string[0].split('\n')[0].encode('utf-8')
    master_key = master_string[1].encode('utf-8')
    decrypted_master_password = decrypt(master_password, master_key)
    # Creating the menu where you can enter your master password
    label = CTkLabel(master=app, text="Enter Master Password:", height=5, text_font=('default', 12))
    label.pack(pady=10, padx=10)
    password = CTkEntry(master=app, width=200, height=42.5, placeholder_text='Password', text_font=('default', 12))
    password.pack(pady=10, padx=20)
    button = CTkButton(master=app, text="Confirm", width=100, height=42.5, text_font=('default', 12),
                       command=lambda: check_pw(password.get()))
    button.pack(pady=10, padx=10)

def check_pw(pw):
    global attempts
    if len(pw) == 0: return
    if pw == decrypted_master_password:
        mainpage()
    else:
        #Clearing the window
        for widget in app.winfo_children():
            widget.destroy()
        #Creating the text "Invalid Password" when you put an incorrect password
        CTkLabel(master=app, text="Invalid Password", height=5, text_font=('default', 12)).pack(pady=0, padx=10)
        label = CTkLabel(master=app, text="Enter Master Password:", height=5, text_font=('default', 12))
        label.pack(pady=10, padx=10)
        password = CTkEntry(master=app, width=200, height=42.5, placeholder_text='Password', text_font=('default', 12))
        password.pack(pady=10, padx=10)
        button = CTkButton(master=app, text="Confirm", width=100, height=42.5, text_font=('default', 12), command=lambda: check_pw(password.get()))
        button.pack(pady=10, padx=10)
        attempts += 1
        #Ends the program if the user has entered an incorrect password 10 times
        if attempts == 10:
            exit()
        password.delete(0, END)
        #Focuses on a label so the user cannot edit the placeholder text
        label.focus()

app.mainloop()
