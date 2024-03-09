import tkinter as tk

from gui_functions import GUI_Manager, CURRENT_USER, ANOTHER_USER

BACKGROUND_COLOR = '#ADD8E6'
FOREGROUND_COLOR = '#000000'


class BSK_window(tk.Tk):

    def __init__(self):
        super().__init__(className=' BSK app')
        self.config(background=BACKGROUND_COLOR)
        self.config(width=500, height=300)

        self.gui_manager = GUI_Manager(self)

        self.file_path = None
        self.private_key_path = None
        self.public_key_path = None

        self.app_title = tk.Label(self, text='BSK - User', bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR,
                                  font=('Arial', 20))
        self.app_title.place(x=20, y=5)

        # user A / B
        self.user_A = tk.Button(self, text='A', command=self.gui_manager.user_A_button)
        self.user_A.config(width=5, bg=CURRENT_USER)
        self.user_A.place(x=175, y=10)

        self.user_B = tk.Button(self, text='B', command=self.gui_manager.user_B_button)
        self.user_B.config(width=5, bg=ANOTHER_USER)
        self.user_B.place(x=225, y=10)

        # document to sign / decrypt / encrypt
        self.file_button = tk.Button(self, text='Choose file', command=self.gui_manager.choose_file)
        self.file_button.config(width=30)
        self.file_button.place(x=20, y=50)

        self.file_name = tk.Label(self, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
        self.file_name.config(text='file (*.pdf / *.txt)')
        self.file_name.place(x=20, y=75)

        # search for private key from pendrive
        self.private_key_button = tk.Button(self, text='Use private key', command=self.gui_manager.find_private_key)
        self.private_key_button.config(width=30)
        self.private_key_button.place(x=260, y=50)

        self.private_key_info = tk.Label(self, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
        self.private_key_info.config(text='NOT FOUND')
        self.private_key_info.place(x=260, y=75)

        # choose public key
        self.public_key_button = tk.Button(self, text='Choose public key', command=self.gui_manager.choose_public_key)
        self.public_key_button.config(width=30)
        self.public_key_button.place(x=20, y=125)

        self.public_key_info = tk.Label(self, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
        self.public_key_info.config(text='NOT FOUND')
        self.public_key_info.place(x=20, y=150)

        # verify
        self.verify_button = tk.Button(self, text='Verify', command=self.gui_manager.verify_file)
        self.verify_button.config(width=30)
        self.verify_button.place(x=260, y=125)

        self.verify_info = tk.Label(self, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
        self.verify_info.config(text='Choose XML signature file')
        self.verify_info.place(x=260, y=150)

        # sign
        self.sign_button = tk.Button(self, text='Sign', command=self.gui_manager.sign_file)
        self.sign_button.config(width=20)
        self.sign_button.place(x=20, y=200)

        # encrypt
        self.encrypt_button = tk.Button(self, text='Encrypt', command=self.gui_manager.encrypt_file)
        self.encrypt_button.config(width=20)
        self.encrypt_button.place(x=175, y=200)

        # decrypt
        self.decrypt_button = tk.Button(self, text='Decrypt', command=self.gui_manager.decrypt_file)
        self.decrypt_button.config(width=20)
        self.decrypt_button.place(x=330, y=200)
