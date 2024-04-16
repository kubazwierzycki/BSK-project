import base64
import datetime
import os
import psutil
import re
import tkinter as tk
import xml.dom.minidom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from tkinter import filedialog, messagebox, simpledialog

CURRENT_USER = '#00FF00'  # green
ANOTHER_USER = '#FF0000'  # red
ACTIVE_BUTTON = '#FFFFFF'  # white
INACTIVE_BUTTON = '#BBBBBB'  # gray
ERROR_MESSAGE_TITLE = 'ERROR!'
WARNING_MESSAGE_TITLE = 'Warning!'
INFO_MESSAGE_TITLE = 'Information'

class GUI_Manager:

    def __init__(self, gui):
        self.gui = gui

    def is_public_key_exist(self):
        if self.gui.public_key_path is None:
            messagebox.showwarning(WARNING_MESSAGE_TITLE, 'The public key is not found!')
            return False
        return True

    def is_private_key_exist(self):
        if self.gui.private_key_path is None:
            messagebox.showwarning(WARNING_MESSAGE_TITLE, 'The private key is not found!')
            return False
        return True

    def is_file_exist(self):
        if self.gui.file_path is None:
            messagebox.showwarning(WARNING_MESSAGE_TITLE, 'The file is not chosen!')
            return False
        return True

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
            messagebox.showerror(ERROR_MESSAGE_TITLE, 'The private key is broken or the PIN is incorrect!')
            return None

        return private_key

    def get_public_key(self):

        with open(f"{self.gui.public_key_path}", "r") as public_key_file:
            public_key_pem = public_key_file.read()

        public_key_pem = public_key_pem.encode('utf-8')
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

        return public_key

    def choose_file(self):
        file_path = filedialog.askopenfilename(filetypes=(("Text files", "*.txt*"), ("PDF files", "*.pdf*")))
        file_extension = file_path.split('.')[-1]
        if file_extension in ['pdf', 'txt']:
            file_name = file_path.split('/')[-1]
            self.gui.file_path = file_path
            self.gui.file_name.config(text=file_name)
        else:
            self.gui.file_path = None
            self.gui.file_name.config(text='file (*.pdf / *.txt)')
            messagebox.showwarning(WARNING_MESSAGE_TITLE, 'Wrong file!')

    @staticmethod
    def get_pendrive_paths():
        pendrives = []
        drives = psutil.disk_partitions()
        for drive in drives:
            if drive.opts == 'rw,removable':
                pendrives.append(drive.device)
        return pendrives

    def get_private_key_path(self):
        pendrive_paths = self.get_pendrive_paths()
        for pendrive_path in pendrive_paths:
            private_key_path = pendrive_path + 'private_key.pem'
            if os.path.exists(private_key_path):
                self.gui.private_key_path = private_key_path
                self.gui.private_key_info.config(text=private_key_path)
                return private_key_path
        self.gui.private_key_path = None
        self.gui.private_key_info.config(text='NOT FOUND')
        messagebox.showwarning(WARNING_MESSAGE_TITLE, 'The pendrive or the private key was not found!')
        return None

    def choose_public_key(self):
        key_path = filedialog.askopenfilename(filetypes=(("PEM files", "*.pem*"),))
        file_extension = key_path.split('.')[-1]
        if file_extension == 'pem':
            file_name = key_path.split('/')[-1]
            self.gui.public_key_path = key_path
            self.gui.public_key_info.config(text=file_name)
        else:
            self.gui.public_key_path = None
            self.gui.public_key_info.config(text='NOT FOUND')
            messagebox.showwarning(WARNING_MESSAGE_TITLE, 'Wrong file!')

    def is_verified(self, signature_path):
        # read encrypted file hash from signature file
        try:
            signature = xml.dom.minidom.parse(signature_path)
            encrypted_hash = signature.getElementsByTagName('encrypted_hash')[0].firstChild.data
            encrypted_hash = base64.b64decode(encrypted_hash)
        except:
            messagebox.showerror(ERROR_MESSAGE_TITLE, 'Signature file is incorrect!')
            return False

        public_key = self.get_public_key()
        if public_key is None:
            return False

        try:
            public_key.verify(encrypted_hash, self.get_document_hash(), padding.PKCS1v15(), hashes.SHA256())
            return True
        except:
            return False

    def verify_file(self):
        if self.is_file_exist() and self.is_public_key_exist():
            signature_path = filedialog.askopenfilename(filetypes=(("XML files", "*.xml*"),))
            file_extension = signature_path.split('.')[-1]
            if file_extension == 'xml':
                if self.is_verified(signature_path):
                    messagebox.showinfo(INFO_MESSAGE_TITLE, 'The signature verification passed!')
                else:
                    messagebox.showwarning(WARNING_MESSAGE_TITLE, 'The signature verification failed!')
            else:
                messagebox.showwarning(WARNING_MESSAGE_TITLE, 'Wrong file!')

    def get_document_hash(self):
        with open(self.gui.file_path, 'rb') as file:
            file_content = file.read()

        # generate hash for file
        file_hash = hashes.Hash(hashes.SHA256())
        file_hash.update(file_content)
        file_hash = file_hash.finalize()

        return file_hash

    def sign_file(self):
        if self.is_file_exist() and self.is_private_key_exist():
            try:
                user = os.getlogin()
            except:
                user = 'Unknown'
                print('Cannot find username')
            file_hash = self.get_document_hash()
            private_key = self.get_private_key()
            if private_key is not None:
                encrypted_file_hash = private_key.sign(file_hash, padding.PKCS1v15(), hashes.SHA256())
                encrypted_file_hash = base64.b64encode(encrypted_file_hash).decode('utf-8')
            else:
                messagebox.showerror(ERROR_MESSAGE_TITLE, 'The private key is not valid!')
                return

            xml_data = f"""
            <signature>
                <file>
                    <name>{self.gui.file_path.split('/')[-1].split('.')[0]}</name>
                    <extension>{self.gui.file_path.split('.')[-1]}</extension>
                    <size>{os.path.getsize(self.gui.file_path)}</size>
                    <date>{os.path.getmtime(self.gui.file_path)}</date>
                </file>
                <user_name>{user}</user_name>
                <encrypted_hash>{encrypted_file_hash}</encrypted_hash>
                <timestamp>{datetime.datetime.now()}</timestamp>
            </signature>
            """
            xml_data = xml.dom.minidom.parseString(xml_data)

            xml_path = os.path.dirname(self.gui.file_path) + '/signature.xml'
            with open(f"{xml_path}", "w") as xml_file:
                xml_file.write(xml_data.toprettyxml())

            messagebox.showinfo(INFO_MESSAGE_TITLE, f'The signature was created\n{xml_path}')

    def encrypt_file(self):
        if self.is_file_exist() and self.is_public_key_exist():
            with open(f'{self.gui.file_path}', 'rb') as original_file:
                original_content = original_file.read()

            public_key = self.get_public_key()
            try:
                encrypted_content = public_key.encrypt(original_content, padding.PKCS1v15())
            except:
                messagebox.showerror(ERROR_MESSAGE_TITLE, 'The file could not be encrypted')
                return

            dir_name = os.path.dirname(self.gui.file_path)
            file_name = self.gui.file_path.split('/')[-1].split('.')[0]
            file_extension = self.gui.file_path.split('.')[-1]

            with open(f'{dir_name}/{file_name}(encrypted).{file_extension}', 'wb') as encrypted_file:
                encrypted_file.write(encrypted_content)

            messagebox.showinfo(INFO_MESSAGE_TITLE, f'The file was encrypted\n'
                                               f'{dir_name}/{file_name}(encrypted).{file_extension}')

    def decrypt_file(self):
        if self.is_file_exist() and self.is_private_key_exist():
            with open(f'{self.gui.file_path}', 'rb') as encrypted_file:
                encrypted_content = encrypted_file.read()

            private_key = self.get_private_key()
            try:
                original_content = private_key.decrypt(encrypted_content, padding.PKCS1v15())
            except:
                messagebox.showerror(ERROR_MESSAGE_TITLE, 'The file could not be decrypted')
                return

            dir_name = os.path.dirname(self.gui.file_path)
            file_name = self.gui.file_path.split('/')[-1].split('.')[0].split('(')[0]
            file_extension = self.gui.file_path.split('.')[-1]

            with open(f'{dir_name}/{file_name}(decrypted).{file_extension}', 'wb') as decrypted_file:
                decrypted_file.write(original_content)

            messagebox.showinfo(INFO_MESSAGE_TITLE, f'The file was decrypted\n'
                                               f'{dir_name}/{file_name}(decrypted).{file_extension}')

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
        self.gui.decrypt_button.config(bg=ACTIVE_BUTTON, state=tk.ACTIVE)

        self.reset_gui_variables()

    def user_B_button(self):
        self.gui.user_B.config(bg=CURRENT_USER)
        self.gui.user_A.config(bg=ANOTHER_USER)
        self.gui.private_key_button.config(bg=INACTIVE_BUTTON, state=tk.DISABLED)
        self.gui.sign_button.config(bg=INACTIVE_BUTTON, state=tk.DISABLED)
        self.gui.decrypt_button.config(bg=INACTIVE_BUTTON, state=tk.DISABLED)

        self.reset_gui_variables()
