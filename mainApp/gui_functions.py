import datetime
import tkinter as tk
import os
import re
import xml.dom.minidom
import psutil

from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


CURRENT_USER = '#00FF00'  # green
ANOTHER_USER = '#FF0000'  # red
ACTIVE_BUTTON = '#FFFFFF'  # white
INACTIVE_BUTTON = '#BBBBBB'  # gray


class GUI_Manager:

    def __init__(self, gui):
        self.gui = gui

    def get_private_key(self):
        # get user's pin and clear the input
        pin = simpledialog.askstring('Insert PIN', 'Insert your PIN number')
        pin = re.findall("[0-9]+", pin)[0]

        # read encrypted key (.pem format)
        with open(f"{self.gui.private_key_path}", "rb") as private_key_file:
            encrypted_private_key = private_key_file.read()

        # generate hash for pin
        key_hash = hashes.Hash(hashes.SHA256())
        key_hash.update(pin.encode('utf-8'))
        key = key_hash.finalize()

        try:
            # decrypt private key
            private_key = serialization.load_pem_private_key(
                encrypted_private_key,
                password=key,
                backend=default_backend()
            )
        except:
            messagebox.showerror('Error!', 'The private key is broken or the PIN is incorrect!')
            return None

        return private_key

    def get_public_key(self):

        with open(f"{self.gui.public_key_path}", "r") as public_key_file:
            public_key_format = public_key_file.read()

        public_key_format = public_key_format.encode('utf-8')
        public_key = serialization.load_pem_public_key(
            public_key_format,
            backend=default_backend()
        )

        return public_key

    def choose_file(self):
        file_path = filedialog.askopenfilename(filetypes=(("Text files", "*.txt*"), ("PDF files", "*.pdf*")))
        print(file_path)
        file_extension = file_path.split('.')[-1]
        if file_extension in ['pdf', 'txt']:
            file_name = file_path.split('/')[-1]
            self.gui.file_path = file_path
            self.gui.file_name.config(text=file_name)
        else:
            self.gui.file_path = None
            self.gui.file_name.config(text='file (*.pdf / *.txt)')
            messagebox.showwarning('Warning', 'Wrong file!')

    @staticmethod
    def find_pendrive_path():
        pendrives = []
        drives = psutil.disk_partitions()
        for drive in drives:
            if drive.opts == 'rw,removable':
                pendrives.append(drive.device)
        return pendrives

    def find_private_key(self):
        pendrives_path = self.find_pendrive_path()
        for pendrive_path in pendrives_path:
            private_key_path = pendrive_path + 'private_key.pem'
            if os.path.exists(private_key_path):
                self.gui.private_key_path = private_key_path
                self.gui.private_key_info.config(text=private_key_path)
                return private_key_path
        self.gui.private_key_path = None
        self.gui.private_key_info.config(text='NOT FOUND')
        messagebox.showwarning('Warning', 'The pendrive or the private key was not found!')
        return None

    def choose_public_key(self):
        key_path = filedialog.askopenfilename(filetypes=(("PEM files", "*.pem*"),))
        print(key_path)
        file_extension = key_path.split('.')[-1]
        if file_extension == 'pem':
            file_name = key_path.split('/')[-1]
            self.gui.public_key_path = key_path
            self.gui.public_key_info.config(text=file_name)
        else:
            self.gui.public_key_path = None
            self.gui.public_key_info.config(text='NOT FOUND')
            messagebox.showwarning('Warning', 'Wrong file!')

    def verify_document(self, public_key_path, document_path, signature_path):
        #
        # to implement verification
        #
        return True

    def verify_file(self):
        if self.gui.file_path is None:
            messagebox.showwarning('Warning', 'The file is not chosen!')
        elif self.gui.public_key_path is None:
            messagebox.showwarning('Warning', 'The public key is not found!')
        else:
            file_path = filedialog.askopenfilename(filetypes=(("XML files", "*.xml*"),))
            print(file_path)
            file_extension = file_path.split('.')[-1]
            if file_extension == 'xml':
                if self.verify_document(self.gui.public_key_path, self.gui.file_path, file_path):
                    messagebox.showinfo('Information', 'The signature verification passed!')
                else:
                    messagebox.showwarning('Information', 'The signature verification failed!')
            else:
                messagebox.showwarning('Warning', 'Wrong file!')

    def get_document_hash(self):
        with open(self.gui.file_path, 'rb') as file:
            file_content = file.read()

        # generate hash for file
        file_hash = hashes.Hash(hashes.SHA256())
        file_hash.update(file_content)
        file_hash = file_hash.finalize()

        return file_hash

    def sign_file(self):
        if self.gui.file_path is None:
            messagebox.showwarning('Warning', 'The file is not chosen!')
        elif self.gui.private_key_path is None:
            messagebox.showwarning('Warning', 'The private key is not found!')
        else:
            filename = self.gui.file_path.split('/')[-1].split('.')[0]
            file_extension = self.gui.file_path.split('.')[-1]
            file_size = os.path.getsize(self.gui.file_path)
            last_mod_time = os.path.getmtime(self.gui.file_path)
            try:
                user = os.getlogin()
            except:
                user = 'Unknown'
                print('Cannot find username')
            file_hash = self.get_document_hash()
            private_key = self.get_private_key()
            if private_key is not None:
                encrypted_file_hash = private_key.sign(
                    file_hash,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            else:
                messagebox.showerror('The private key is not valid!')
                return
            timestamp = datetime.datetime.now()

            xml_data = f"""
            <signature>
                <file>
                    <name>{filename}</name>
                    <extension>{file_extension}</extension>
                    <size>{file_size}</size>
                    <date>{last_mod_time}</date>
                </file>
                <user_name>{user}</user_name>
                <encrypted_hash>temp_value</encrypted_hash>
                <timestamp>{timestamp}</timestamp>
            </signature>
            """
            xml_data = xml.dom.minidom.parseString(xml_data)
            encrypted_hash_xml = xml_data.getElementsByTagName('encrypted_hash')[0]
            encrypted_hash_xml.firstChild.data = encrypted_file_hash

            xml_path = os.path.dirname(self.gui.file_path) + '/signature.xml'
            with open(f"{xml_path}", "w") as xml_file:
                xml_file.write(xml_data.toprettyxml())

    def encrypt_file(self):
        if self.gui.file_path is None:
            messagebox.showwarning('Warning', 'The file is not chosen!')
        elif self.gui.private_key_path is None:
            messagebox.showwarning('Warning', 'The private key is not found!')
        else:
            #
            # to implement file encryption
            #
            print("encrypt")

    def decrypt_file(self):
        if self.gui.file_path is None:
            messagebox.showwarning('Warning', 'The file is not chosen!')
        elif self.gui.public_key_path is None:
            messagebox.showwarning('Warning', 'The public key is not found!')
        else:
            #
            # to implement file decryption
            #
            print("decrypt")

    def reset_gui_variables(self):
        self.gui.file_path = None
        self.gui.file_name.config(text='file (*.pdf / *.txt)')
        self.gui.private_key_path = None
        self.gui.private_key_info.config(text='NOT FOUND')
        self.gui.public_key_path = None
        self.gui.public_key_info.config(text='NOT FOUND')

    def user_A_button(self):
        self.gui.user_A.config(bg=CURRENT_USER)
        self.gui.user_B.config(bg=ANOTHER_USER)
        self.gui.private_key_button.config(bg=ACTIVE_BUTTON, state=tk.ACTIVE)
        self.gui.sign_button.config(bg=ACTIVE_BUTTON, state=tk.ACTIVE)
        self.gui.encrypt_button.config(bg=ACTIVE_BUTTON, state=tk.ACTIVE)

        self.reset_gui_variables()

    def user_B_button(self):
        self.gui.user_B.config(bg=CURRENT_USER)
        self.gui.user_A.config(bg=ANOTHER_USER)
        self.gui.private_key_button.config(bg=INACTIVE_BUTTON, state=tk.DISABLED)
        self.gui.sign_button.config(bg=INACTIVE_BUTTON, state=tk.DISABLED)
        self.gui.encrypt_button.config(bg=INACTIVE_BUTTON, state=tk.DISABLED)

        self.reset_gui_variables()
