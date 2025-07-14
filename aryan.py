import string
import tkinter as tk
from tkinter import messagebox

# Simulated user data storage
user_data = {}

def check_pwd(password):
    strength = 0
    remarks = ''
    lower_count = upper_count = num_count = wspace_count = special_count = 0

    for char in list(password):
        if char in string.ascii_lowercase:
            lower_count += 1
        elif char in string.ascii_uppercase:
            upper_count += 1
        elif char in string.digits:
            num_count += 1
        elif char == ' ':
            wspace_count += 1
        else:
            special_count += 1

    if lower_count >= 1:
        strength += 1
    if upper_count >= 1:
        strength += 1
    if num_count >= 1:
        strength += 1
    if wspace_count >= 1:
        strength += 1
    if special_count >= 1:
        strength += 1

    if strength == 1:
        remarks = "Very Bad Password!!! Change ASAP"
    elif strength == 2:
        remarks = "Not A Good Password!!! Change ASAP"
    elif strength == 3:
        remarks = "It's a weak password, consider changing"
    elif strength == 4:
        remarks = "It's a hard password, but can be better"
    elif strength == 5:
        remarks = "A very strong password"

    result = (f"Your password has:\n"
              f"{lower_count} lowercase characters\n"
              f"{upper_count} uppercase characters\n"
              f"{num_count} numeric characters\n"
              f"{wspace_count} whitespace characters\n"
              f"{special_count} special characters\n\n"
              f"Password Strength: {strength}\n"
              f"Hint: {remarks}")

    messagebox.showinfo("Password Strength Checker", result)

def toggle_password_visibility(entry, var):
    if var.get():
        entry.config(show='')  # Show password
    else:
        entry.config(show='*')  # Hide password

def signup():
    def signup_user():
        username = username_entry.get()
        password = password_entry.get()

        if username in user_data:
            messagebox.showerror("Signup Error", "Username already exists!")
        elif username == "" or password == "":
            messagebox.showwarning("Input Error", "Please fill all fields!")
        else:
            user_data[username] = password
            messagebox.showinfo("Signup Success", "Signup successful! You can now log in.")
            signup_window.destroy()

    signup_window = tk.Toplevel(root)
    signup_window.title("Signup")
    signup_window.geometry("300x250")

    tk.Label(signup_window, text="Username:").pack(pady=5)
    username_entry = tk.Entry(signup_window)
    username_entry.pack(pady=5)

    tk.Label(signup_window, text="Password:").pack(pady=5)
    password_entry = tk.Entry(signup_window, show='*')
    password_entry.pack(pady=5)

    show_password_var = tk.BooleanVar()
    show_password_checkbox = tk.Checkbutton(signup_window, text="Show Password", variable=show_password_var,
                                             command=lambda: toggle_password_visibility(password_entry, show_password_var))
    show_password_checkbox.pack()

    signup_button = tk.Button(signup_window, text="Signup", command=signup_user)
    signup_button.pack(pady=20)

def login():
    def login_user():
        username = username_entry.get()
        password = password_entry.get()

        if username in user_data and user_data[username] == password:
            messagebox.showinfo("Login Success", "Login successful! You can check your password strength.")
            login_window.destroy()
            password_strength_checker()  # Go to password strength checker
        else:
            messagebox.showerror("Login Error", "Invalid username or password.")

    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window.geometry("300x250")

    tk.Label(login_window, text="Username:").pack(pady=5)
    username_entry = tk.Entry(login_window)
    username_entry.pack(pady=5)

    tk.Label(login_window, text="Password:").pack(pady=5)
    password_entry = tk.Entry(login_window, show='*')
    password_entry.pack(pady=5)

    show_password_var = tk.BooleanVar()
    show_password_checkbox = tk.Checkbutton(login_window, text="Show Password", variable=show_password_var,
                                             command=lambda: toggle_password_visibility(password_entry, show_password_var))
    show_password_checkbox.pack()

    login_button = tk.Button(login_window, text="Login", command=login_user)
    login_button.pack(pady=20)

def password_strength_checker():
    def check_password():
        password = password_entry.get()
        if password:
            check_pwd(password)
        else:
            messagebox.showwarning("Input Error", "Please enter a password!")

    checker_window = tk.Toplevel(root)
    checker_window.title("Password Strength Checker")
    checker_window.geometry("400x300")

    tk.Label(checker_window, text="Enter Password:", font=("Helvetica", 14)).pack(pady=10)
    password_entry = tk.Entry(checker_window, width=30, font=("Helvetica", 12), show='*')  # Hide password by default
    password_entry.pack(pady=5)

    show_password_var = tk.BooleanVar()
    show_password_checkbox = tk.Checkbutton(checker_window, text="Show Password", variable=show_password_var,
                                             command=lambda: toggle_password_visibility(password_entry, show_password_var))
    show_password_checkbox.pack()

    check_button = tk.Button(checker_window, text="Check Password", command=check_password, width=15, bg="blue", fg="white")
    check_button.pack(pady=20)

    exit_button = tk.Button(checker_window, text="Exit", command=checker_window.destroy, width=15, bg="red", fg="white")
    exit_button.pack(pady=5)

def main():
    global root
    root = tk.Tk()
    root.title("User Authentication")
    root.geometry("300x250")
    
    welcome_label = tk.Label(root, text="Welcome! Please Login or Signup", font=("Helvetica", 14))
    welcome_label.pack(pady=10)

    login_button = tk.Button(root, text="Login", command=login, width=15)
    login_button.pack(pady=5)

    signup_button = tk.Button(root, text="Signup", command=signup, width=15)
    signup_button.pack(pady=5)

    exit_button = tk.Button(root, text="Exit", command=root.quit, width=15, bg="red", fg="white")
    exit_button.pack(pady=5)

    root.mainloop()

if __name__ == '_main_':
    main()