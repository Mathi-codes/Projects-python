# Importing necessary packages
import re        
import random     
import datetime   
import time       
import pickle     
# Creating a class for User Authentication System
class UserAuthenticationSystem:
    def __init__(self):
        # Initialize instance variables
        self.reg_details_user = None                    # Variable to store user registration details
        self.login_dict = None                          # Variable to store login details
        self.logout_dict = None
        self.email_mobile=None
    def main(self):
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
            else:
                print("\nInvalid choice.. Please try again!")
    def mainmenu(self):
        ch=input("If you want to go back main menu (yes/Press any key to continue) : ").lower()
        if ch=="yes":
            self.timer(5)
            self.main()
    def timer(self,count):
        print("Please wait! Processing..")
        while count > 0:
            if count == 1:
                print(count, end="\n")
            else:
                print(count, end="-")
            time.sleep(1)
            count -=1
    def register_user(self):
        # Function to register a new user
        print("\n===Register====\n")
        self.mainmenu()
        self.user_validation()                                                   # Validate user input
        self.otp_verify(self.email, self.mobile_number)                          # Generate and Verify OTP
        self.reg_details_user = self.user_details_dict(self.email, self.name, self.mobile_number, self.address, self.password)  # Create user details dictionary
        self.write_to_file_reg(self.reg_details_user)                            # Write user details to file
    def user_validation(self):
        # Validate user input for registration
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
    def valid_email(self):
    # Validate email format using regular expression
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
    def unique_email(self, email):
        # Check if email is unique or not
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
    def valid_name(self):
        # Validate name format using regular expression
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
    def valid_mobile_number(self):
        # Validate mobile number format using regular expression
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
    def unique_mobile_number(self, mobile_number):
        # Check if mobile number is unique or not
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
    def valid_address(self):
        # Validate address format using regular expression
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
    def valid_password(self):
        # Validate password format using regular expression
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
    def confirm_password(self, password):
        # Confirm password entered by user
        count = 0
        while count < 3:                                                # Maximum attempt is 3
            confirm_password = input("Confirm password: ")
            count += 1
            if confirm_password != password:
                print("Passwords do not match! Please re-enter...")
                continue
            print("\nPassword confirmed...")
            break
        else:
            print("Password confirmation limit exceeded! Please try again...")
    def otp_verify(self, email, mobile_number):
        # Generate and verify OTP
        random_digit = random.randrange(100, 999)
        otp = email[0:2] + str(random_digit) + mobile_number[8:10]  # Generate OTP based on email, random 3 digit and mobile number
        self.timer(3)
        print("OTP:", otp)                                          # Display OTP for user
        count = 0
        while count < 3:                                        # Maximum  attempt is 3 
            otp_input = input("Enter the OTP: ")
            if otp_input != otp:
                print("Incorrect OTP! Please try again..")
                count += 1
                continue
            else:
                print("\nOTP verified successfully...")
                break
        else:
            print("OTP verification limit exceeded! New otp will be sent...")
            self.otp_verify(self.email, self.mobile_number)
    def user_details_dict(self, email, name, mobile_number, address, password):
        # Create dictionary with user details
        try:
            details_dict = {
                "Email": email,
                "Name": name,
                "Mobile_number": mobile_number,
                "Address": address,
                "Password": password,
                "Registration_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.timer(5)
            print("Registration successful!...")
            return details_dict
        except Exception as e:
            self.error_logging("User Details Dictionary Error: " + str(e))
    def write_to_file_reg(self, reg_details_user):
        # Write user registration details to file
        try:
            with open("User details.dat", 'ab') as fp:              # Append in binary mode
                pickle.dump(reg_details_user, fp)                   # Dump the data in binary format
        except Exception as e:
            self.error_logging("Write to File Error: " + str(e))
    def login_user(self):
        # Function to authenticate and login a user
        print("\n===Login===\n")
        self.mainmenu()
        self.login_verification_display()                           # Verify login credentials                              
        self.write_to_file_login(self.login_dict)                   # Write login details to file
        self.logout(self.email_mobile)
        self.write_to_file_logout(self.logout_dict)

    def login_verification_display(self):
        try:
            flag = False
            while not flag:
                self.email_mobile = input("Enter your email/mobile: ")       
                while True:
                    ch = input("Re-enter email (yes/Press any key to continue): ").lower()
                    if ch == "yes":
                        self.email_mobile = input("Enter your email/mobile: ")
                    else:
                        break
                password = input("Enter your password: ")
                with open("User details.dat", "rb") as fp:
                    while True:
                        try:
                            reg_details_dict = pickle.load(fp)
                            if ('Email' in reg_details_dict and reg_details_dict['Email'] == self.email_mobile) or ('Mobile_number' in reg_details_dict and reg_details_dict['Mobile_number'] == email_mobile):
                                if reg_details_dict['Password'] == password:
                                    self.timer(5)
                                    print("\nLogged in successfully.")
                                    self.login_dict = {
                                        "Login Details : "
                                        "login_mobile": self.email_mobile,
                                        "login_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    }
                                    flag = True
                                    break
                                else:
                                    break  # Break inner loop to retry email/mobile input
                        except EOFError:
                            break
                        except Exception as e:
                            self.error_logging("Login Verification Error: " + str(e))
                if not flag:
                    print("Invalid user! Please try again...")
        except Exception as e:
            self.error_logging("Login Verification Error: " + str(e))
    def forgot_password(self):
        try:
            self.mainmenu()
            while True:
                email_mobile = input("Enter your email/mobile: ")
                flag = False   
                with open("User details.dat", "rb+") as fp:                         # Open the file in binary read write
                    lines = []
                    while True:
                        try:
                            reg_details_dict = pickle.load(fp)                      # Load the data to a dictionary
                            if (reg_details_dict['Email'] == email_mobile or 
                                reg_details_dict['Mobile_number'] == email_mobile):       
                                self.otp_verify(reg_details_dict['Email'], reg_details_dict['Mobile_number'])
                                print("OTP verified. Please set a new password.")
                                new_password = self.valid_password()
                                self.confirm_password(new_password)
                                reg_details_dict['Password'] = new_password
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
    def logout(self,email_mobile):
        # Function to log out user
        try:
            while True:
                log_out = input("\nEnter 'yes' to Log out: ").lower()
                if log_out == "yes":
                    self.timer(3)
                    self.logout_dict = {
                                        "Logout Details : "
                                        "login_mobile": self.email_mobile,
                                        "login_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    }
                    print("User logged out successfully...")
                    break
                else:
                    print("Invalid input! Please try again...")
                    continue
        except Exception as e:
            self.error_logging("Logout Error: " + str(e))
    def write_to_file_login(self, login_dict):
        # Write login details to file
        try:
            with open("Login details.dat", "ab") as login_fp:        # Append in binary mode
                pickle.dump(login_dict, login_fp)                   # Dump  the data in binary format
        except Exception as e:
            self.error_logging("Write to Login File Error: " + str(e))
    def write_to_file_logout(self,logout_dict):
        try:
            with open("Login details.dat","ab") as logout_fp:
                pickle.dump(logout_dict,logout_fp)
        except Exception as e:
            self.error_logging("Write to Login File Error: " + str(e))
    def error_logging(self, error):
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
            print(pickle.load(load_))  # Load and print each user details
        except EOFError:
            break
with open("Login details.dat","rb") as fp1:
    while True:
        try:
            print(pickle.load(fp1))
        except EOFError :
            break
    
