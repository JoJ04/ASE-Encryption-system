import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import DISABLED, NORMAL

Login_window = None
Signup_Window = None
FileEncDec_Window = None

#-------Login Window-------
def Open_LoginWindow():
  global Login_window

  if Signup_Window is not None and Signup_Window.winfo_exists():
    Signup_Window.destroy()

  Login_window = tk.Toplevel(root)
  Login_window.geometry("300x250")

  def Login():

      username = name_entry.get()
      password = password_entry.get()
      if auth(username, password):
          messagebox.showinfo("Login Successful", "You are now logged in")
          Login_window.destroy()
          Open_FileEncDecWindow()
      else:
          messagebox.showerror("Login Failed", "Wrong username or password")


  login_label = ttk.Label(Login_window, text="Login", font='Calibri 24 bold')
  user_name = ttk.Label(Login_window, text="Username: ")
  name_entry = ttk.Entry(Login_window)
  password= ttk.Label(Login_window, text="Password: ")
  password_entry = ttk.Entry(Login_window, show="*")
  login_button = ttk.Button(Login_window, text="Log in", command= Login)

  login_label.grid(column=0, row=0, pady=5,columnspan=2)
  user_name.grid(column=0, row=2,padx=10)
  name_entry.grid(column=1, row=2, pady=5)
  password.grid(column=0, row=3,padx=10)
  password_entry.grid(column=1, row=3, pady=5)
  login_button.grid(column=0, row=4, columnspan=2,pady=5)

#-------Signup Window-------
def Open_SignupWindow():
  global Signup_Window
  if Login_window is not None and Login_window.winfo_exists():
        Login_window.destroy()

  Signup_Window = tk.Toplevel(root)
  Signup_Window.geometry("300x250")

  def SignUp():
      username = name_entry2.get()
      password = password_entry2.get()
      if auth(username, password):
          messagebox.showerror("SignUp Failed", "username is already registered")
      else:
          if register(username, password):
              messagebox.showinfo("SignUp Successful", "You are now registered")
              Signup_Window.destroy()
              Open_FileEncDecWindow()


  signup_label = ttk.Label(Signup_Window, text="Sign UP", font='Calibri 24 bold')
  user_name2= ttk.Label(Signup_Window, text="Username:")
  name_entry2 = ttk.Entry(Signup_Window )
  password2 = ttk.Label(Signup_Window, text="Password:")
  password_entry2 = ttk.Entry(Signup_Window, show="*")
  create_button = ttk.Button(Signup_Window, text="Create account", command= lambda :SignUp())

  signup_label.grid(column=0, row=0, pady=5,columnspan=2)
  user_name2.grid(column=0, row=2,padx=10)
  name_entry2.grid(column=1, row=2, pady=5)
  password2.grid(column=0, row=3,padx=10)
  password_entry2.grid(column=1, row=3, pady=5)
  create_button.grid(column=0, row=4, columnspan=2,pady=5)


#-------File Encrypt/Decrypt and Upload Window-------
def Open_FileEncDecWindow():
    global FileEncDec_Window
    FileEncDec_Window = tk.Toplevel(root)
    FileEncDec_Window.geometry("300x225")

    file = ttk.StringVar()

    def UploadFile():
        selected_file = filedialog.askopenfilename(initialdir=" ",
                                             title="Select File",
                                             filetypes=(('Text Files', '*.txt'), ('All Files', '*.*')))
        if selected_file:
          entry_file.delete(0, "end")
          entry_file.insert(0,selected_file)
          encrypt_button.configure(state=NORMAL)
          decrypt_button.configure(state=NORMAL)
          file.set(selected_file)
          messagebox.showinfo("File Uploaded", "File Uploaded successfully!")


    def EncryptFile():
        path = file.get()
        if path:
           if encrypt_file(path):
              messagebox.showinfo("File Encrypted", "File Encrypted and Saved successfully!")
           else:
               messagebox.showerror("Failed", "File Encrypted failed!")


    def DecryptFile():
        path = file.get()
        if path:
            if decrypt_file(path):
                messagebox.showinfo("File Decrypted", "File Decrypted and Saved successfully!")
            else:
                messagebox.showerror("Failed", "File Decrypted failed!")


    file_label = ttk.Label(FileEncDec_Window, text="File:",font='Calibri 12 bold')
    entry_file = ttk.Entry(FileEncDec_Window)
    upload_button = ttk.Button(FileEncDec_Window, text="Upload file", command= UploadFile)
    encrypt_button = ttk.Button(FileEncDec_Window,text="Encrypt file", command=EncryptFile, state=DISABLED)
    decrypt_button= ttk.Button(FileEncDec_Window,text="Decrypt file", command=DecryptFile, state=DISABLED)

    file_label.grid(column=0, row=0,padx=5)
    entry_file.grid(column=1, row=0,pady=5,padx=5)
    upload_button.grid(column=0, row=1,pady=5,padx=5)
    encrypt_button.grid(column=0, row=2,pady=5,padx=5)
    decrypt_button.grid(column=0, row=3,pady=5,padx=5)



def auth(username,password):
     pass

def register(username,password):
     pass

def encrypt_file(file):
     pass

def decrypt_file(file):
     pass

#-------Main Window-------
root = ttk.Window(themename = "morph")
root.geometry("300x160")
root.title('Secure File Storage ')
space= ttk.Label(root,text="                     ")
Label1 = ttk.Label(root, text="A secure storage for your files" ,font='Calibri 14 bold')
LoginWindow_button = ttk.Button(root, text="Login", command= Open_LoginWindow)
label2 = ttk.Label(root, text="OR",font='Calibri 12 bold')
SignupWindow_button = ttk.Button(root, text="Sign up", command= Open_SignupWindow)

space.grid(column=0, row=0)
Label1.grid(column=0, row=1,columnspan=3,pady=5, padx=5 )
LoginWindow_button.grid(column=0, row=2,pady=5,padx=5)
label2.grid(column=1, row=2,pady=5,padx=5)
SignupWindow_button.grid(column=2, row=2,pady=5,padx=5)

root.mainloop()
