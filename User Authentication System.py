# Importing necessary packages

import re                                                # To implement regular expressions   
import random                                            # To implement random numbers for otp generation
import datetime                                          # To access various datetime functions
import time                                              # To access various time functions
import pickle                                            # To secure the data with incoherent symbols for safety

# Creating a class for User Authentication System

class UserAuthenticationSystem: 

    def __init__(self):
        # Initialize instance variables
        self.reg_details_user = None                    # Variable to store user Registration details
        self.login_dict = None                          # Variable to store Login details
        self.logout_dict = None                         # Variable to store Logout details
        self.email_mobile=None                          # Email which is accessed by both login and logout
    
    def main(self):                                     # Main() to call every functions...                                         
        # Main menu function to interact with users
        while True:
            print("\n===User Authentication System===\n\n1. Register\n2. Login\n3. Forgot password\n4. Exit\n")
            ch = input("Enter your choice: ")
            if ch == "1":
                self.register_user()                        # Call method to register a new user
            elif ch == "2": 
                self.login_user()                           # Call method to login a user
            elif ch == "3":
                self.forgot_password()                      # Call method to reset password
            elif ch == "4":
                print("\nExiting...")                       # Exit the program
                break
            else:                                            # If user enters invalid choice
                print("\nInvalid choice.. Please try again!")
    
    def mainmenu(self):                                         # Function to go back to mainmenu whenever                                    
        ch=input("If you want to go back main menu (yes/Press any key to continue) : ").lower()
        if ch=="yes":
            self.timer(5)                                       # Time delay for 5 sec to return back to mainmenu
            self.main()
    
    def timer(self,count):                                      # Function to implement delay functionality
        print("Please wait! Processing..")
        while count > 0:
            if count == 1:
                print(count, end="\n")                          # To avoid end delimeter '-'
            else:
                print(count, end="-")                           # To add delimeter '-'  in between numbers 
            time.sleep(1)
            count -=1
    
    def register_user(self):                                      # Function to register a new user
        print("\n===Register====\n")
        self.mainmenu()
        self.user_validation()                                                   # Validate user input
        self.otp_verify(self.email, self.mobile_number)                          # Generate and Verify OTP
        self.reg_details_user = self.user_details_dict(self.email, self.name, self.mobile_number, self.address, self.password)  # Create user details dictionary
        self.write_to_file_reg(self.reg_details_user)                            # Write user details to file
    
    def user_validation(self):                                      # Validate user input for registration
        try:
            self.email = self.valid_email()                  # Validate and store email
            self.unique_email(self.email)                    # Check if email is unique
            self.name = self.valid_name()                    # Validate and store name
            self.mobile_number = self.valid_mobile_number()  # Validate and store mobile number
            self.unique_mobile_number(self.mobile_number)    # Check if mobile number is unique
            self.address = self.valid_address()              # Validate and store address
            self.password = self.valid_password()            # Validate and store password
            self.confirm_password(self.password)             # Confirm password
        except Exception as e:
            self.error_logging("User Validation Error: " + str(e))  # Error logging
    
    # Validate email format using regular expression

    def valid_email(self):                                     
        regex = r'^\w+@[a-zA-Z]+\.[a-zA-Z]{2,3}$'
        count=0
        while count<4:
            email = input('Enter your email: ')
            if re.match(regex, email):
                ch=input("Do you want to re-enter email (yes/Press any key  to continue) : ")
                if ch=="yes":
                    count+=1
                    continue
                else:
                    return email
            else:
                print("Please enter a valid email format.")
                count+=1
        else:
            print("Limit exceeded! Please  try  again...")
            self.main()

    def unique_email(self, email):                                                      # Check if email is unique or not
        try:
            with open("User details.dat", "rb") as fp:
                while True:
                    try:
                        reg_details_dict = pickle.load(fp)                              # Load the dumped data to  dictionary
                        if 'Email' in reg_details_dict and reg_details_dict['Email'] == email:
                            print("Email has already been taken.")
                            self.email = self.valid_email()                             # Ask user to enter a new email
                            return False
                    except EOFError:
                        break
                    except Exception as e:
                        self.error_logging("Unique Email Error: " + str(e))
            return True
        except FileNotFoundError:
            return True
    
    #Validate name format using regular expression
    
    def valid_name(self):
        regex = r'^[a-zA-Z .]+$'
        count=0
        while count<4:
            name = input("Enter your name: ")
            if re.match(regex, name):
                ch=input("Do you want to re-enter name (yes/Press any key  to continue) : ")
                if ch=="yes":
                    count+=1
                    continue
                else:
                    return name
            else:
                print("Please enter a valid name format...")
                count+=1
        else:
            print("Limit exceeded! Please  try  again...")
            self.main()
    
    # Validate mobile number format using regular expression
    
    def valid_mobile_number(self):
        regex = r'^(\+91|91)?[ -]?(?!.*[0]{4})[9876]{1}\d{9}$'
        count=0
        while count<4:
            mobile_number = input("Enter your mobile number: ")
            if re.match(regex, mobile_number):
                ch=input("Do you want to re-enter mobile  number (yes/Press any key  to continue) : ")
                if ch=="yes":
                    count+=1
                    continue
                else:
                    return mobile_number
            else:
                print("Please enter a valid mobile number format..")
                count+=1
        else:
            print("Limit exceeded! Please  try  again...")
            self.main()
    
    def unique_mobile_number(self, mobile_number):                                  # Check if mobile number is unique or not
        try:
            with open("User details.dat", "rb") as fp:
                while True:
                    try:
                        reg_details_dict = pickle.load(fp)                          # Load dumped data to dictionary
                        if 'Mobile_number' in reg_details_dict and reg_details_dict['Mobile_number'] == mobile_number:
                            print("Mobile number has already been taken.")
                            self.mobile_number = self.valid_mobile_number()         # Ask user to enter a new mobile number
                            return False
                    except EOFError:
                        break
                    except Exception as e:
                        self.error_logging("Unique Mobile Number Error: " + str(e))
            return True
        except FileNotFoundError:
            return True
        
    # Validate address format using regular expression

    def valid_address(self):
        count=0
        regex = r'^\d+\s*,?\s*[a-zA-Z\s,]+\s*,?\s*[a-zA-Z\s]+\s*,?\s*[a-zA-Z\s]+\s*,?\s*\d{6}$'
        while count<4:
            address = input("Please enter the address in the format 'House Number, Street, City, State, Pincode': ")
            if re.match(regex, address.strip()):
                ch=input("Do you want to re-enter address (yes/Press any key  to continue) : ")
                if ch=="yes":
                    count+=1
                    continue
                else:
                    return address
            else:
                print("Please enter a valid address format...")
                count+=1
        else:
            print("Limit exceeded! Please  try  again...")
            self.main()
    
    # Validate password format using regular expression

    def valid_password(self):
        count=0
        regex = r'^(?=.*[a-z]{4,6})(?=.*[A-Z]{4,6})(?=.*\d{2,4})(?=.*[^a-zA-Z0-9]{1,2}).{8,}$'
        while count<4:
            password = input('Enter your password: ')
            if re.fullmatch(regex, password):
                ch=input("Do you want to re-enter Password (yes/Press any key  to continue) : ")
                if ch=="yes":
                    continue
                else:
                    return password
            else:
                print("Please enter a valid password format...")
                count+=1
        else:
            print("Limit exceeded! Please  try  again...")
            self.main()
      
    def confirm_password(self, password):                                 # Confirm password entered by user
        count = 0
        while count < 3:                                                # Maximum attempt is 3
            confirm_password = input("Confirm password: ")
            count += 1
            if confirm_password != password:                            # Checks if entered password not equals to existing password
                print("Passwords do not match! Please re-enter...")
                continue
            print("\nPassword confirmed...")                            # If equals
            break
        else:                                                           # If  attemps limit reached
            print("Password confirmation limit exceeded! Please try again...")
    
    def otp_verify(self, email, mobile_number):                         # Generate and verify OTP
        random_digit = random.randrange(100, 999)
        otp = email[0:2] + str(random_digit) + mobile_number[8:10]  # Generate OTP based on email, random 3 digit and mobile number
        self.timer(3)
        print("OTP:", otp)                                          # Display OTP for user
        count = 0
        while count < 3:                                             # Maximum  attempt is 3 
            otp_input = input("Enter the OTP: ")
            if otp_input != otp:                                     # checks if entered otp not equals to generated otp     
                print("Incorrect OTP! Please try again..")
                count += 1
                continue
            else:                                                      # If otp verified successfully
                print("\nOTP verified successfully...")
                break
        else:                                                           # If maximum attempt reached
            print("OTP verification limit exceeded! New otp will be sent...")
            self.otp_verify(self.email, self.mobile_number)             # Resend otp

    # Create dictionary with user details
 
    def user_details_dict(self, email, name, mobile_number, address, password):
        try:
            details_dict = {
                "Email": email,
                "Name": name,
                "Mobile_number": mobile_number,
                "Address": address,
                "Password": password,
                "Registration_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.timer(5)                                                   # Call timer function with 5 seconds delay
            print("Registration successful!...")
            return details_dict
        except Exception as e:
            self.error_logging("User Details Dictionary Error: " + str(e))
    
    # Write user registration details to file

    def write_to_file_reg(self, reg_details_user):
        try:
            with open("User details.dat", 'ab') as fp:              # Append in binary mode
                pickle.dump(reg_details_user, fp)                   # Dump the data in binary format
        except Exception as e:
            self.error_logging("Write to File Error: " + str(e))

    # Function to authenticate and login a user

    def login_user(self):
        print("\n===Login===\n")
        self.mainmenu()
        self.login_verification_display()                           # Verify login credentials                              
        self.write_to_file_login(self.login_dict)                   # Write login details to file
        self.logout(self.email_mobile)                              # To Logout user
        self.write_to_file_logout(self.logout_dict)                 # Writw logged out details to  file

    # To implement login verificatiions with the registered details
    
    def login_verification_display(self):
        try:
            flag = False
            while not flag:                                         # Asks email/mobile until satisfies valid credentials...
                self.email_mobile = input("Enter your email/mobile: ")       
                while True:                                         # Ask to re enter email/mobile
                    ch = input("Re-enter email (yes/Press any key to continue): ").lower()
                    if ch == "yes":
                        self.email_mobile = input("Enter your email/mobile: ")
                    else:
                        break
                password = input("Enter your password: ")             # Get password from user
                with open("User details.dat", "rb") as fp:            # Open User details.txt file in read binary mode
                    while True:
                        try:
                            reg_details_dict = pickle.load(fp)          # Load the details in a seperate dictionary for login verification
                            if ('Email' in reg_details_dict and reg_details_dict['Email'] == self.email_mobile) or ('Mobile_number' in reg_details_dict and reg_details_dict['Mobile_number'] == self.email_mobile):   # checks if entered email or mobile number is in the  registered details
                                if reg_details_dict['Password'] == password:                            # checks if entered password is matched with givenn email/mobile
                                    self.timer(5)                                                       # Call timer() with 5 sec delay
                                    print("\nLogged in successfully.")
                                    self.login_dict = {                                                 # Store the email/mobile with timestamp in a seperate dictionary
                                        "Login Details : "
                                        "login_mobile": self.email_mobile,
                                        "login_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    }
                                    flag = True
                                    break
                                else:
                                    break                           # Break inner loop to re- enter email/mobile input
                        except EOFError:
                            break
                        except Exception as e:
                            self.error_logging("Login Verification Error: " + str(e))
                if not flag:                                        # If login credentials fails
                    print("Invalid user! Please try again...")
        except Exception as e:
            self.error_logging("Login Verification Error: " + str(e))
    
    # Function to reset new password
    
    def forgot_password(self):
        try:
            self.mainmenu()                                                     # To ask if user wants to go back mainmenu
            while True:
                email_mobile = input("Enter your email/mobile: ")
                flag = False   
                with open("User details.dat", "rb+") as fp:                         # Open the file in binary read write
                    lines = []                                                      # List to store file details in readable format
                    while True:
                        try:
                            reg_details_dict = pickle.load(fp)                      # Load the data to a dictionary
                            if (reg_details_dict['Email'] == email_mobile or        # Checks if entered email/mobile equals to registered email
                                reg_details_dict['Mobile_number'] == email_mobile):             
                                self.otp_verify(reg_details_dict['Email'], reg_details_dict['Mobile_number']) # call otp_verify() to generate and verify otp
                                print("OTP verified. Please set a new password.")
                                new_password = self.valid_password()                                        #  Validate new password using valid_password()
                                self.confirm_password(new_password)                                         # To confirm password using confirm_password()
                                reg_details_dict['Password'] = new_password                                 # Sets new password in place of existing password
                                flag = True         
                            lines.append(reg_details_dict)                          # Append the dictionary one by one to the list 
                        except EOFError:
                            break
                        except Exception as e:
                            self.error_logging("Forgot Password Error: " + str(e))
                    fp.seek(0)                                                      # Sets the cursor to beginning of file
                    fp.truncate(0)                                                  # Delete only the content of file
                    for line in lines:
                        pickle.dump(line, fp)                                       # Dump the list to the file with new password
                if flag:
                    print("Password reset successful!")
                    break                                                           # Exit the while loop if password reset successful
                else:
                    print("Invalid email/mobile! Please try again.")
        except Exception as e:
            self.error_logging("Forgot Password Error: " + str(e))

    # Function to user logout

    def logout(self,email_mobile):
        # Function to log out user
        try:
            while True:
                log_out = input("\nEnter 'yes' to Log out: ").lower()               # asks if user wants to log out
                if log_out == "yes":
                    self.timer(3)                                                   # Delay for 3 sec using timer()
                    self.logout_dict = {                                            # store email/mobile with timestamp in a seperate dictionary
                                        "Logout Details : "
                                        "login_mobile": self.email_mobile,
                                        "login_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    }
                    print("User logged out successfully...")
                    break
                else:                                                               # If user does not enters yes
                    print("Invalid input! Please try again...")
                    continue
        except Exception as e:
            self.error_logging("Logout Error: " + str(e))

    def write_to_file_login(self, login_dict):                       # Write login details to file
        try:
            with open("Login details.dat", "ab") as login_fp:        # Append in binary mode
                pickle.dump(login_dict, login_fp)                   # Dump  the data in binary format
        except Exception as e:
            self.error_logging("Write to Login File Error: " + str(e))

    def write_to_file_logout(self,logout_dict):                         # Function to write logout details to file
        try:
            with open("Login details.dat","ab") as logout_fp:
                pickle.dump(logout_dict,logout_fp)                       # dump the details in a .dat file
        except Exception as e:
            self.error_logging("Write to Login File Error: " + str(e))
    
    def error_logging(self, error):                                     # Log errors to error log file
        # Log errors to error log file
        try:
            with open("Error log.txt", "a") as error_fp:
                error_fp.write(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + ": " + error + "\n")    # Write the respective error with timestamp
        except Exception as e:
            print("Error while logging: ", e)
if __name__ == "__main__":
    auth_system = UserAuthenticationSystem()                        # Creating object for the class
    auth_system.main()                                              # Call the main() method
with open("User details.dat", "rb") as load_:
    while True:    
        try:
            print(pickle.load(load_))       # Load and print each user details
        except EOFError:
            break
with open("Login details.dat","rb") as fp1:
    while True:
        try:
            print(pickle.load(fp1))         # Load and print each Login details
        except EOFError :
            break
    
