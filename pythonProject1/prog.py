from tkinter import *
from getpass import getpass
from tkinter import messagebox
import re
import argparse
import hashlib
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import csv

root = Tk()
root.title("sign up/log in")
root.geometry("500x300")

#verification email adress function
def validate_email(email):
    if re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return True
    return False

def email_exists(email):
    with open("user_data.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            if f"Email: {email}" in line:
                return True
    return False

#validating passwordd function
def validate_pwd(pwd):
    if len(pwd) >= 8 and any(char.isupper() for char in pwd) and any(
            char.isdigit() for char in pwd) and any(not char.isalnum() for char in pwd):
        return True
    return False

#submit btn function
def login():
    login_email = emailvalue.get()
    login_password = pwdvalue.get()

    with open("user_data.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            if f"Email: {login_email}, Password: {login_password}" in line:
                messagebox.showinfo(title="Login Success", message="You are logged in.")
                open_menu()
                break
        else:
            messagebox.showerror(title="Login Failed", message="Invalid email or password")

#saving sing up information
def getvals():
    email = emailvalue.get()
    if validate_email(emailvalue.get()) and validate_pwd(pwdvalue.get()):
        if not email_exists(email):
            print("accepted")
            with open("user_data.txt", "a") as file:
                file.write(f"Email: {emailvalue.get()}, Password: {pwdvalue.get()}\n")
            messagebox.showinfo(title="sign up success", message="your sign up was successful")
        else:
            print("email already exists")
            messagebox.showerror(title="error", message="there is already an account with this email")
    else:
        print("not valid")
        messagebox.showerror(title="error", message="invalid email or password")


#heading
Label(root, text="Sign up", font="arial 15 bold").grid(row= 0, column=3)

#field name
email = Label(root, text="email")
pwd = Label(root, text="password")

#packing fields
email.grid(row=1, column=2)
pwd.grid(row=2, column=2)

#storing variables
emailvalue = StringVar()
pwdvalue = StringVar()

#entry field
email_entry = Entry(root, textvariable=emailvalue)
pwd_entry = Entry(root, textvariable=pwdvalue, show='*')

#packing entry fields
email_entry.grid(row=1, column=3)
pwd_entry.grid(row=2, column=3)

#submit button
Button(text="Sign up", command=getvals).grid(row=6, column=3)
Button(text="login", command=login).grid(row=7, column=3)

#-----------------------------------------------

#main menu page
def open_menu():
    root.destroy()

    main_menu = Tk()
    main_menu.title("Menu")
    main_menu.geometry("500x300")

    Label(main_menu, text="menu", font=('Bold', 30)).grid(row=0, column=3)

    hash_pwd = Label(main_menu, text="hash password with sha256")
    hash_pwd.grid(row=2, column=3)

    pwdval = StringVar()
    password_entry = Entry(main_menu, textvariable=pwdval, show='*')
    password_entry.grid(row=3, column=2)

    #hashing password by sha256 function
    def hash_password():
        password = pwdval.get()
        if password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            hashed = Label(main_menu,text="your hashed password is : " + hashed_password)
            hashed.grid(row=4, column=2)
            messagebox.showinfo('Hashed Password', message=hashed_password)
            print(hashed_password)

    Button(text="Hash password", command=hash_password).grid(row=5, column=2)


    decalage = Label(main_menu, text="Decalage pas CESAR")
    decalage.grid(row=6, column=3)
    message = Label(main_menu, text="enter a message")
    message.grid(row=7, column=2)
    motval = StringVar()
    keyval = IntVar()
    mot_entry = Entry(main_menu, textvariable=motval)
    mot_entry.grid(row=8, column=2)
    key = Label(main_menu, text="enter a key")
    key.grid(row=9, column=2)
    key_entry = Entry(main_menu, textvariable=keyval)
    key_entry.grid(row=10, column=2)

    def new_letter(letter):
        try:
            num = ord(letter) + keyval.get()
            if num > 122:
                num -= 26
            return chr(num)
        except ValueError:
            messagebox.showerror(title="error", message="please enter a valid key")
            return letter

    #shift by CESAR function
    def cesar():
        alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ '
        msg = motval.get()
        msg = msg.upper()
        chiffrer = ""
        clair=""
        for i in msg:
            chiffrer+=alphabet[(alphabet.index(i)+keyval.get())%26]
        coded = Label(main_menu, text="your CESAR coded message is : " + chiffrer)
        coded.grid(row=12, column=2)
        for i in chiffrer:
            clair+=alphabet[(alphabet.index(i)-keyval.get())%26]
        decoded = Label(main_menu, text="your CESAR decoded message is : " + clair)
        decoded.grid(row=13, column=2)

    Button(text="CESAR coding", command=cesar).grid(row=11, column=2)
    def openwin():
        open_bd()

    Button(text="show dataset as dictionary", command=openwin).grid(row=14, column=2)


    #dataset window
    def open_bd():
        main_menu.destroy()
        datasett = Tk()
        datasett.title("dataset")
        datasett.geometry("500x300")
        df = pd.read_csv("dataset.csv")

        data_info = Label(datasett, text="dataset: predict students dropout and academic success")
        data_info.grid(row=1, column=2)
        dict = Label(datasett, text="your dictionary has been printed in the console :)")
        dict.grid(row=3, column=2)

        #printing the dataset as a dictionary
        with open('dataset.csv', newline='') as csvfile:
            data = csv.DictReader(csvfile)
            for row in data:
                print(row)

        #first cuve function(histogram)
        def graph1():
            plt.hist(df['Target'], 50)
            plt.show()

        #second cruve function(piechart)
        def graph2():
            target_counts = df['Target'].value_counts()
            labels = target_counts.index
            sizes = target_counts.values
            plt.pie(sizes, labels=labels, autopct='%1.1f%%')
            plt.show()

        Button(text="histogram", command=graph1).grid(row=4, column=2)
        Button(text="piechart", command=graph2).grid(row=6, column=2)



        datasett.mainloop()


    main_menu.mainloop()


root.mainloop()