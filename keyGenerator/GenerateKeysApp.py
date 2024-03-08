import tkinter as tk
import re
import psutil

from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

BACKGROUND_COLOR = '#ADD8E6'
FOREGROUND_COLOR = '#000000'


class GenerateKeysApp(tk.Tk):

    @staticmethod
    def find_pendrive_path():
        drives = psutil.disk_partitions()
        for drive in drives:
            if drive.opts == 'rw,removable':
                return drive.device
        return None

    def save_keys(self, pin):
        # generate, encrypt and save private key
        # default_backend() - responsible for random seed
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # generate hash for pin
        key_hash = hashes.Hash(hashes.SHA256())
        key_hash.update(pin.encode('utf-8'))
        key = key_hash.finalize()

        # encrypt private_key and change format to .pem
        encrypted_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key)
        )
        with open(f"{self.pendrive_path}private_key.pem", "wb") as private_key_file:
            private_key_file.write(encrypted_private_key)

        # generate and save public key
        public_key = private_key.public_key()
        public_key_format = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(f"{self.pendrive_path}public_key.pem", "wb") as public_key_file:
            public_key_file.write(public_key_format)

        messagebox.showinfo('Success', 'Key were generated and saved')

    def generate_keys(self):
        text = self.pin_number.get(1.0, tk.END)
        regex = re.findall("[0-9]+", text)
        if len(regex) == 1 and len(regex[0]) == len(text) - 1:
            self.pendrive_path = self.find_pendrive_path()
            if self.pendrive_path is None:
                messagebox.showwarning('Warning', 'The pendrive is not found!')
            else:
                regex = regex[0]
                self.save_keys(regex)
        else:
            messagebox.showwarning('Warning', 'The PIN number must contain only digits!')

    def __init__(self):
        super().__init__(className='BSK - generate keys')
        self.config(background=BACKGROUND_COLOR)
        self.config(width=400, height=200)

        self.app_title = tk.Label(self, text='BSK - generate keys', bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR,
                                  font=('Arial', 20))
        self.app_title.place(x=20, y=5)

        self.label = tk.Label(self, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
        self.label.config(text='PIN number:')
        self.label.place(x=20, y=70)

        self.pin_number = tk.Text(self, width=20, height=1)
        self.pin_number.place(x=100, y=70)

        # generation of keys
        self.generate_button = tk.Button(self, text='Generation of keys', command=self.generate_keys)
        self.generate_button.config(width=40)
        self.generate_button.place(x=20, y=100)

        self.pendrive_path = None
