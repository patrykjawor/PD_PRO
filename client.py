import tkinter as tk
from tkinter import ttk
from tkinter.ttk import Style
import requests
import hashlib
from os.path import exists, basename
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet
import os
import pickle
from ttkthemes import ThemedStyle


OK = [200 + e for e in range(100)]
refreshAfterUp = False

def getfilehash(filename:str):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(8192),b""):
            sha256_hash.update(block)
    return sha256_hash.hexdigest()


def write_key():
    """
    Tworzy nowy klucz i zapisuje go do pliku.
    Zwraca stworzony klucz.
    """
    key = Fernet.generate_key()
    with open("key_file.key", "wb") as key_file:
        key_file.write(key)
    return key


def read_key():
    """
    Zwraca odczytany klucz z pliku.
    """
    try:
        file = open("key_file.key","rb")
        key = file.read()
        file.close()
        return key
    except Exception:
        print("Couldn't open key file!")
        return None


def encrypt_data(data:bytearray, key:bytearray):
    """
    Zaszyfrowuje dane przekazane przez `data` z użyciem klucza przekazanego jako `key`.
    """
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_data(data:bytearray, key:bytearray):
    """
    Odszyfrowuje dane przekazane przez `data` z użyciem klucza przekazanego jako `key`.
    """
    f = Fernet(key)
    return f.decrypt(data)


options = {
    'url_scheme': 'https', # Prefix adresu - protokół
    'host': '127.0.0.1:5000', # Host docelowy z ew. nr portu
    'certfile': 'ca.crt' # Plik z CA dla aplikacji flask (Normalnie nie działa z CA dodanym do CA w Windowsie)
}

s = requests.Session() # Sesja aby zachowało ciasteczka (inaczej flask rozpoczyna nową sesję)


class App:
    def __init__(self, master:tk.Tk):
        self.master = master
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing) # Rejestruje metodę do wywołania przy zamykaniu okna.
        self.style = ThemedStyle(master)
        self.style.set_theme("arc")
        self.button_style = Style()
        self.style.configure('TButton', 
                font =
               ('Lato', 13, 'bold','italic'),
                foreground = '#4FC3F7',
                background = '#9C9C9C',
                borderwidth = 4,
                bordercolor ='black',
                relief="raised")
        # Create register form widgets
        self.register_frame = ttk.Frame(self.master)
        self.register_label = ttk.Label(self.register_frame, text='Register Form', font=('Lato', 18, 'bold'))
        self.register_username_label = ttk.Label(self.register_frame, text='Username', font=('Lato', 13))
        self.register_username_entry = ttk.Entry(self.register_frame)
        self.register_email_label = ttk.Label(self.register_frame, text='Email', font=('Lato', 13))
        self.register_email_entry = ttk.Entry(self.register_frame)
        self.register_password_label = ttk.Label(self.register_frame, text='Password', font=('Lato', 13))
        self.register_password_entry = ttk.Entry(self.register_frame, show='*')
        self.register_button = ttk.Button(self.register_frame, text='Register', command=self.register, padding=10, style='TButton')
        

        # Create login form widgets
        self.login_frame = ttk.Frame(self.master)
        self.login_label = ttk.Label(self.login_frame, text='Login Form', font=('Lato', 18, 'bold'))
        self.login_username_label = ttk.Label(self.login_frame, text='Username or Email', font=('Lato', 13))
        self.login_username_entry = ttk.Entry(self.login_frame)
        self.login_password_label = ttk.Label(self.login_frame, text='Password', font=('Lato', 13))
        self.login_password_entry = ttk.Entry(self.login_frame, show='*')
        self.login_button = ttk.Button(self.login_frame, text='Login', command=self.login, padding=10, style='TButton')

        # Add widgets to frames
        self.register_label.pack()
        self.register_username_label.pack()
        self.register_username_entry.pack()
        self.register_email_label.pack()
        self.register_email_entry.pack()
        self.register_password_label.pack()
        self.register_password_entry.pack()
        self.register_button.pack(padx=10, pady=10)

        self.login_label.pack()
        self.login_username_label.pack()
        self.login_username_entry.pack()
        self.login_password_label.pack()
        self.login_password_entry.pack()
        self.login_button.pack(padx=10, pady=10)

        # Pack frames
        self.register_frame.pack(side=tk.LEFT, padx=10)
        self.login_frame.pack(side=tk.RIGHT, padx=10)
        url = f'{options["url_scheme"]}://{options["host"]}/logged'
        response = s.get(url, verify=options['certfile'])
        if response.ok:
            if response.json()["value"] == True:
                url = f'{options["url_scheme"]}://{options["host"]}/getuser'
                response = s.get(url, verify=options["certfile"])
                username = ''
                if response.status_code in OK:
                    username = response.json()['username']
                self.show_files(username)

    def register(self):
        # Get username and password from form fields
        username = self.register_username_entry.get()
        email = self.register_email_entry.get()
        password = self.register_password_entry.get()
        # Make POST request to server
        url = f'{options["url_scheme"]}://{options["host"]}/register'
        data = {'username': username, 'email': email, 'password': password}
        response = s.post(url, data=data, verify=options["certfile"]) 

        # Display server response in a messagebox
        messagebox.showinfo(title='Register', message=response.json()['message'])

    def two_factory_form(self):
        self.login_username_entry.delete(0, tk.END)
        self.login_password_entry.delete(0, tk.END)
        self.register_username_entry.delete(0, tk.END)
        self.register_password_entry.delete(0, tk.END)

        # Hide login frame
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()

        # Create 2FA widgets
        self.factory_form = ttk.Frame(self.master)
        self.factory_label = tk.Label(self.factory_form, text='Check your email for OTP code', font=('Lato', 18, 'bold'))
        self.factory_input_label = ttk.Label(self.factory_form, text='Your OTP:', font=('Lato', 14))
        self.factory_input_entry = ttk.Entry(self.factory_form)
        self.factory_button = ttk.Button(self.factory_form, text='Authorize', command=self.authorize, style='TButton')
        # Pack new frame
        self.factory_form.pack(side=tk.LEFT, padx=10)
        # Add widgets to frame
        self.factory_label.pack()
        self.factory_input_label.pack()
        self.factory_input_entry.pack()
        self.factory_button.pack(padx=10, pady=10)

    def authorize(self):
        otp_key = self.factory_input_entry.get()
        url = f'{options["url_scheme"]}://{options["host"]}/validate'
        data = {'otp_key': otp_key}
        response = s.post(url, data=data, verify=options["certfile"])
        messagebox.showinfo(title='OTP LOGIN', message=response.json()['message'])
        if response.status_code in OK:
            url = f'{options["url_scheme"]}://{options["host"]}/getuser'
            response = s.get(url, verify=options["certfile"])
            if response.status_code in OK:
                username = response.json()['username']
                self.show_files(username)

    def login(self):
        # Get username and password from form fields
        username = self.login_username_entry.get()
        password = self.login_password_entry.get()

        # Make POST request to server
        url = f'{options["url_scheme"]}://{options["host"]}/login'
        data = {'username': username, 'password': password}
        response = s.post(url, data=data, verify=options["certfile"])
    
        # Display server response in a messagebox
        messagebox.showinfo(title='Login', message=response.json()['message'])
        if response.status_code in  OK:
            url = f'{options["url_scheme"]}://{options["host"]}/otp'
            data = {'username': username}
            response = s.post(url, data=data, verify=options["certfile"])
            if response.status_code in OK:
                self.two_factory_form()

    def show_files(self, username):
        # Reset form fields
        global refreshAfterUp # Zmienna globalna
        if refreshAfterUp == False:
            if hasattr(self,"factory_input_entry"): # Jeśli przekierowano bezpośrednio po uruchomieniu
                self.login_username_entry.delete(0, tk.END)
                self.login_password_entry.delete(0, tk.END)
                self.register_username_entry.delete(0, tk.END)
                self.register_password_entry.delete(0, tk.END)

                # Hide login frame
                self.login_frame.pack_forget()
                self.register_frame.pack_forget()

                self.factory_input_entry.delete(0, tk.END)

                #Hide 2FA frame
                self.factory_form.pack_forget()
                self.factory_label.pack_forget()
                self.factory_input_label.pack_forget()
                self.factory_input_entry.pack_forget()
                self.factory_button.pack_forget()
            
            if hasattr(self, "login_frame"): # Jeśli przekierowano bezpośrednio po uruchomieniu
                self.login_username_entry.delete(0, tk.END)
                self.login_password_entry.delete(0, tk.END)
                self.register_username_entry.delete(0, tk.END)
                self.register_password_entry.delete(0, tk.END)

                # Hide login frame
                self.login_frame.pack_forget()
                self.register_frame.pack_forget()

            # Create new frame with list of files
            self.files_frame = ttk.Frame(self.master)
            self.files_label = ttk.Label(self.files_frame, text=f'Files for user {username}', font=('Lato', 18, 'bold'))
            self.files_listbox = tk.Listbox(self.files_frame, width=50)

            # Create widgets for frame of upload and download
            self.upload_button = ttk.Button(self.files_frame, text='Upload', command=self.upload, style='TButton')
            self.download_button = ttk.Button(self.files_frame, text='Download', command=self.download, style='TButton')
            self.logout_button = ttk.Button(self.files_frame, text="Logout", command=self.logout, style="TButton")
            

            # Add files to listbox
            url = f'{options["url_scheme"]}://{options["host"]}/files'
            response = s.get(url, verify=options["certfile"])
            files = response.json()['files']
            for file in files:
                self.files_listbox.insert(tk.END, file["filename"])

            # Add widgets to frame
            self.files_label.pack()
            self.files_listbox.pack()
            self.upload_button.pack(padx=5, pady=5)
            self.download_button.pack(padx=5, pady=5)
            self.logout_button.pack(padx=5,pady=5)

            # Pack new frame
            self.files_frame.pack(side=tk.LEFT, padx=10)
            refreshAfterUp = True
        else:
            if hasattr(self, "factory_form"):
                self.factory_form.pack_forget()
            self.files_frame.pack_forget()

            # Create new frame with list of files
            self.files_frame = ttk.Frame(self.master)
            self.files_label = ttk.Label(self.files_frame, text=f'Files for user {username}', font=('Lato', 18, 'bold'))
            self.files_listbox = tk.Listbox(self.files_frame, width=50)

            # Create widgets for frame of upload and download
            self.upload_button = ttk.Button(self.files_frame, text='Upload', command=self.upload, style='TButton')
            self.download_button = ttk.Button(self.files_frame, text='Download', command=self.download, style='TButton')
            self.logout_button = ttk.Button(self.files_frame, text="Logout", command=self.logout, style="TButton")

            # Add files to listbox
            url = f'{options["url_scheme"]}://{options["host"]}/files'
            response = s.get(url, verify=options["certfile"])
            files = response.json()['files']
            for file in files:
                self.files_listbox.insert(tk.END, file["filename"])

            # Add widgets to frame
            self.files_label.pack()
            self.files_listbox.pack()
            self.upload_button.pack(padx=5, pady=5)
            self.download_button.pack(padx=5, pady=5)
            self.logout_button.pack(padx=5,pady=5)

            # Pack new frame
            self.files_frame.pack(side=tk.LEFT, padx=10)

    def upload(self):
        key = None
        if exists("key_file.key"):
            key = read_key()
        else:
            key = write_key()
        if key is None:
            messagebox.showerror("Nie udało się uzyskać klucza!")
            return
        url = f'{options["url_scheme"]}://{options["host"]}/getuser'
        response = s.get(url, verify=options["certfile"])
        if response.status_code in OK:
            username = response.json()['username']
        filename = filedialog.askopenfilename()
        if filename == '': # Jeśli użytkownik zaniechał działania.
            return
        url = f'{options["url_scheme"]}://{options["host"]}/upload'
        files = {"file": (basename(filename), encrypt_data(open(filename,"rb").read(), key))}
        metadata = {"checksum": getfilehash(filename)}
        response = s.post(url, files=files, params=metadata, verify=options["certfile"])
        if response.status_code in OK:
            messagebox.showinfo(title='Upload', message=response.json()['message'])
            self.show_files(username)
        else:
            messagebox.showerror(title='Upload', message=response.json()['message'])
            self.show_files(username)
        
    
    def download(self):
        url = f'{options["url_scheme"]}://{options["host"]}/files'
        response = s.get(url, verify=options["certfile"])
        list_files = response.json()["files"]
        try:
            filename = self.files_listbox.get(self.files_listbox.curselection()) # Pobiera to co jest aktualnie wybrane (na niebiesko w listbox)
        except Exception as e:
            print("Filename get error reason:", e)
            messagebox.showerror("Download error", "No item selected!")
            return
        for item in list_files:
            if filename == item['filename']:
                filename = item['download']
                namehash = item['download']
                print(filename)
        url = f'{options["url_scheme"]}://{options["host"]}/download/{filename}'
        response = s.get(url,verify=options["certfile"], stream=True)
        if response.ok:
            try:
                filename = response.headers.get('content-disposition')
                filename = filename[filename.find("filename") + 10:-1] # 8 filename 10 filename + ="
                directory = filedialog.askdirectory(mustexist=True)
                if directory == "":
                    directory = "."
                filename = os.path.join(directory, filename)
                file = open(filename, "wb")
                # shutil.copyfileobj(response.raw, file) # Po dodaniu szyfrowania dekodować w locie.
                file.write(decrypt_data(response.raw.read(),read_key()))
                file.close()
                url = f'{options["url_scheme"]}://{options["host"]}/checksum/{namehash}'
                response = s.get(url, verify=options["certfile"])
                if response.ok:
                    checksum = response.json()["checksum"] # Jeśli zamieniono plik na serwerze, użyto innego klucza lub podano błędną sumę kontrolną.
                    if checksum != getfilehash(filename):
                        print("Suma kontrolna niezgodna. Plik zostanie usunięty...")
                        os.remove(filename)
                        messagebox.showerror("Download error", "File has been corrupted or damaged!")
                        return
                    else:
                        print("Suma kontrolna: \033[0;32mOK\033[0m")
                        messagebox.showinfo("Download finished", "Download successfull ✅!")
                else:
                    print("Ostrzeżenie: Nie udało się pobrać sumy kontrolnej dla pliku! Brak możliwości sprawdzenia integralności danych!!")
                    messagebox.showinfo("Download finished", "Download successfull!")
                print("File saved to", filename)
                
            except Exception as e:
                print(e)
        else:
            print("Download failed", response.text)

    def logout(self):
        url = f'{options["url_scheme"]}://{options["host"]}/logout'
        response = s.post(url, verify=options['certfile'])
        if response.ok:
            messagebox.showinfo("Info", "Logout successfull!")
            if hasattr(self,"login_frame"):
                self.login_frame.pack_forget()
            if hasattr(self,"files_frame"):
                self.files_frame.pack_forget()
            if hasattr(self,"factory_form"):
                self.factory_form.pack_forget()
            if hasattr(self,"register_frame"):
                self.register_frame.pack_forget()
            self.__init__(self.master)
        else: messagebox.showerror("Logout error", f"Request failed with error code {response.status_code}")

    def on_closing(self):
        try:
            with open("cookiejar.bin", "wb") as f:
                pickle.dump(s.cookies, f)
        except Exception as e:
            print("During saving session something went wrong")

        self.master.destroy()


if __name__ == '__main__':
    if os.name == "nt":
        os.system("color")
    if exists("cookiejar.bin"):
        try:
            with open("cookiejar.bin", "rb") as f:
                s.cookies.update(pickle.load(f))
        except Exception as e:
            print("Something went wrong while restoring session:", e)
    root = tk.Tk()
    root.title("FileStasher")
    root.resizable(False,False)
    app = App(root)
    root.mainloop()