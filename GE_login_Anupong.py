# -------------------------------- SOA -----------------------------------------
#                                Anupong
#                                20230607
#					            SOA Assignment
#					            Simple Login for Gelos



# ----------------------Libraries----------------------------------------------
from datetime import datetime
import string
import rsa
import secrets


# ----------------------my function--------------------------------------------
def optionMenu():
    print("-" * 50)
    print("a) Login")
    print("b) Register")
    print("c) View accounts")
    print("d) Reset password")
    print("m) Menu")
    print("x) Exit")
    print("-"*50)

def loginMenu():
    print("Welcome to Login Menu")
    count = 0
    global userAccount
    userRules()                                                                                                         # Display Username rules
    passRules()                                                                                                         # Display Password rules
    while count < 3:                                                                                                    # Loop for checking 3-times login failed

        existingUser = input("Please enter your user name: ")
        existingPwd = input("Please enter your password: ")
        userAccount = validateUser(existingUser, existingPwd)                                                           # userAccount size 8 for collect info
                                                                                                                        # 0 username, # 1 password, 2 encrypted,
                                                                                                                        # 3 email, 4 last reset, 5 last login,
                                                                                                                        # 6 day after reset, 7 day after login
        if userAccount[6] >= dayToReset:                                                                                # Check if reset password
            print("Welcome back", existingUser)
            print("Your last login was", userAccount[7], "days ago")
            print("You haven't reset your password for", userAccount[6], "days")
            print("You must reset your password now")
            userAccount[5] = currentDate                                                                                # Update Last Login Date
            userAccount[1], userAccount[2] = resetPwd()
            userAccount[4] = currentDate                                                                                # Update Last Reset Date
            writeAccount(userAccount[0],userAccount[1],userAccount[2],userAccount[3],userAccount[4],userAccount[5])
            return
        elif userAccount[6] >= dayToReset - dayToNotify:                                                                # Warn if almost reset password
            print("Welcome back", existingUser)
            print("Your last login was", userAccount[7], "days ago")
            print("You haven't reset your password for", userAccount[6], "days")
            print("You should reset your password within next", dayToReset - userAccount[6], "days")
            userAccount[5] = currentDate                                                                                # Update Last Login Date
            writeAccount(userAccount[0],userAccount[1],userAccount[2],userAccount[3],userAccount[4],userAccount[5])
            return

        elif userAccount[6] >= 0:                                                                                       # Login successful
            print("Welcome back", existingUser)
            print("Your last login was", userAccount[7], "days ago")
            print("You haven't reset your password for", userAccount[6], "days")
            userAccount[5] = currentDate                                                                                # Update Last Login Date
            writeAccount(userAccount[0],userAccount[1],userAccount[2],userAccount[3],userAccount[4],userAccount[5])
            return
        else:                                                                                                           # userAccount[6] is -1
            print("Either your username or password is invalid, please try again!")
            count = count + 1
            print("You have ", 3 - count, " tries left")                                                                # Print out chances left (Optional)
            print("-"*50)
    print("-"*50)
    print("You have failed to login 3 times!. Please contact system administrator")
    print("Program has been brutally forced to shutdown, Bye!!!")
    exit()                                                                                                              # Force exit

def registerMenu():
    print("Welcome to Register Menu")
    print("-"*50)
    userRules()
    passRules()
    while True:
        newUser = input("Please choose username: ")
        for eachLine in accInfo:                                                                                        # If account data existed
            eachItem = eachLine.strip().split(",")
            if newUser == eachItem[0]:                                                                                  # Check if username has been taken
                print("This username has been taken")
                return                                                                                                  # Force to get out to main menu


        if newUser.isalnum() and len(newUser) > 5 and len(newUser) < 13:                                                # Check if username followed policies (only alpha-numeric allowed)
            newPass = input("Please choose your password or type 'a' to auto-generate password: ")
            if newPass.lower() == "a" and len(newPass) == 1:                                                            # Check if auto-gen pswd
                print("You have chosen", newPass, "system to auto-generate the password")
                newPass = ranPwd()
            elif len(newPass) < 8:                                                                                      # Check password length
                print("Your password is too short")
                break
            else:
                if validatePass(newPass) < 3:                                                                           # Check if password followed policies (3 of 4 rules)
                    print("Your password combination doesn't follow company's policies")
                    passRules()                                                                                         # Display Password rules again!
                    break

            emailAddress = input("Please enter valid email address: ")
            if "@" in emailAddress:                                                                                     # Check if email has @ (Optional)
                print("Congratulations! You have registered to the system")
                print("Your username: ",newUser)
                print("Your password: ", newPass)
                print("Your email address: ", emailAddress)
                print("Please login again if you want to access the system")
                encPwd = rsa.encrypt(newPass.encode(), pbKey).hex()                                                     # Encrypted string

                writeAccount(newUser, newPass, encPwd, emailAddress, currentDate, currentDate)                          # Write to accounts.txt
                return
            else:
                print("Your email address is not valid")

                break
        else:
            print("You haven't followed the correct username policy")
            userRules()                                                                                                 # Display Username Rules again
            break


def resetPwdMenu():
    global userAccount

    print("Welcome to Reset Password Menu")
    userAccount[1], userAccount[2] = resetPwd()                                                                         # Call reset function to return password and encrypted password
    userAccount[4] = currentDate                                                                                        # Update changed password date
    writeAccount(userAccount[0], userAccount[1], userAccount[2], userAccount[3], userAccount[4], userAccount[5])        # Write to accounts.txt

def resetPwd():
    while True:
        newPass = input("Please choose your password or type 'a' to auto-generate password: ")
        print("You have chosen: ", newPass)
        if newPass.lower() == "a" and len(newPass) == 1:                                                                # Check if auto-gen password
            print("Password will be auto-generate")
            newPass = ranPwd()                                                                                          # Call Reset Password Function
            print("Your new password is", newPass)
            break
        elif len(newPass) < 8:                                                                                          # Check if password length is ok
            print("Your password is too short")
            passRules()
        else:
            if validatePass(newPass) < 3:                                                                               # Check if password followed policies
                print("Your password combination doesn't follow company's policies")
                print("Please try again!")
                passRules()
            else:
                print("-"*50)
                print("Your new password is", newPass)
                break
    encPwd = rsa.encrypt(newPass.encode(), pbKey).hex()                                                                 # Encrypted string from keys
    return newPass, encPwd

def viewAccountMenu():
    print("Welcome to View Account Menu")
    print("Only System Administrator can access this menu")
    print("Please login with SA credentials")
    print("-"*50)
    saUser = input("Please type SA account: ")
    saPswd = input("Please type SA password: ")
    if saUser == adminUser and saPswd == adminPass:                                                                     # Check SA Credentials if they are correct
        print("*"*50)
        print("Username\t","Password\t","Encrypted\t","Email\t","Last_Login\t","Last_Password_Changed")                 # Setup header for display on screen
        for eachLine in accInfo:
            cleanLine = eachLine.strip()
            for eachItem in cleanLine.split(","):
                print(eachItem, end = "\t\t")
            print("")
    else:
        print("You haven't provided valid SA credentials")
def ranPwd():
    pwdLength = 8                                                                                                       # Constant length of auto-gen password

    randomPwd = ""
    while True:
        randomPwd = "".join([secrets.choice(allPossibleChar) for i in range(pwdLength)])                                # Random password from possible characters in length of 8 characters

        if validatePass(randomPwd) >= 3:                                                                                # Check if at least 3 of 4 conditions fulfiled
            break

    return randomPwd

def validatePass(password):
    pwdChk = [0, 0, 0, 0]
    for i in password:
        if i in nonAlphaString:                                                                                         # Check if special character
            pwdChk[0] = 1
        if i in smallAlphaChar:                                                                                         # Check if lowercase
            pwdChk[1] = 1
        if i in capAlphaChar:                                                                                           # Check if uppercase
            pwdChk[2] = 1
        if i in numChar:                                                                                                # Check if number
            pwdChk[3] = 1

    return sum(pwdChk)                                                                                                  # Return sum of checking (1-4)

def validateUser(existingUser, existingPwd):
    for eachLine in accInfo:
        eachItem = []                                                                                                   # Initialise empty list before using it
        eachItem = eachLine.strip().split(",")
        if existingUser == eachItem[0] and existingPwd == eachItem[1]:                                                  # Check if username/password are matched
            lastReset = datetime.strptime(eachItem[4], "%d/%m/%y")
            lastLogin = datetime.strptime(eachItem[5], "%d/%m/%y")
            eachItem[4] = datetime.strftime(lastReset, "%d/%m/%y")
            eachItem[5] = datetime.strftime(lastLogin, "%d/%m/%y")
            eachItem.append((currentDateTime - lastReset).days)                                                         # Days since reset password
            eachItem.append((currentDateTime - lastLogin).days)                                                         # Days since last login
            return eachItem
    eachItem = [existingUser,existingPwd,"","","","",-1,-1]                                                             # Set days to minus to indicate bad username/password
    return eachItem

def writeAccount(user, pwd, enc, email, login, change):                                                                 # Function to write new info to file
    global accInfo
    foundUser = False
    for i, eachLine in enumerate(accInfo):                                                                              # Check if existing user
        eachItem = eachLine.strip().split(",")
        if user == eachItem[0]:
            foundUser = True
            lineIndex = i                                                                                               # Get line index where username is existed
            oldLine = [user, pwd, enc, email, str(login), str(change)]
            accInfo[lineIndex] = ",".join(oldLine) + "\n"                                                               # Replace new information to index line
            with open(fileName,"w") as writeFile:
                writeFile.writelines(accInfo)
            with open(fileName, "r") as readFile:
                accInfo = readFile.readlines()                                                                          # Re-read to get latest info from file after wrote

        if len(eachLine) == 1:                                                                                          # Check if line is empty info (length = 1 for CR)
            accInfo.pop(i)                                                                                              # Pop empty item from the list
            with open(fileName,"w") as writeFile:
                writeFile.writelines(accInfo)                                                                           # Re-write info to file without empty line
            with open(fileName, "r") as readFile:
                accInfo = readFile.readlines()                                                                          # Re-read to get latest info from file after wrote

    if foundUser == False:                                                                                              # If username is new register user
        newLine = [user, pwd, enc, email, str(login), str(change)]
        with open(fileName, "r+") as writeFile:
            info = writeFile.readlines()                                                                                # Read file to move pointer to end of file
            # print(info)
            writeFile.write(",".join(newLine))                                                                          # Write new line after end of file
            writeFile.write("\n")
        with open(fileName, "r") as readFile:
            accInfo = readFile.readlines()                                                                              # Re-read to get latest info from file after wrote
    return

def userRules():
    print("Username should be at least 6 characters long but not greater than 12 characters.")
    print("Username should contain only alphanumeric characters")
    print("-"*50)
def passRules():
    print("Password should be at least 8 characters long and contain 3 out of 4 from these categories:")
    print("1. Uppercase letters (A through Z)")
    print("2. Lowercase letters (a through z)")
    print("3. Numbers (0 through 9)")
    print("4. Non-alphanumeric characters", """(~!@#$%^&*_-+=`|\(){}[]:;"'<>,.?/)""")
    print("-"*50)


# -------------------------variables-----------------------------------------------

fileName = "accounts.txt"
currentDateTime = datetime.now()
currentDate = currentDateTime.strftime("%d/%m/%y")
choice = ""
userName = ""
userAccount = ["","","","","","",0,0]
adminUser = "admin"                                                                                                     # Hardcoded for admin credentials
adminPass = "adminpass"
dayAfterResetPwd = 0
dayAfterLastLogin = 0
dayToReset = 120
dayToNotify = 10
secondToDelay = 2

nonAlphaString = string.punctuation
smallAlphaChar = string.ascii_lowercase
capAlphaChar = string.ascii_uppercase
numChar = string.digits
allPossibleChar = nonAlphaString + smallAlphaChar + capAlphaChar + numChar                                              # Concatenate with all possible characters for randomising password

pvKey, pbKey = rsa.newkeys(256)                                                                                         # Generate Keys for encryption


# ----------------------the main code--------------------------------------------------
try:                                                                                                                    # Try to open if file existed else create new file
    with open(fileName, 'r') as accFile:                                                                                # Use with command to avoid forgetting close the file
        accInfo = accFile.readlines()
except FileNotFoundError:
    with open(fileName, "w+") as accFile:
        print("No account data found!")
        print("Account data has been created\n")
        accInfo = accFile.readlines()

print("-"*50)
print("Welcome to Gelos Enterprises System")
print("Date: ", currentDateTime)

optionMenu()                                                                                                            # Option Menu selection starts from here!!
while choice.lower() != "x":                                                                                            # Do until user chose to exit [x]
    choice = input("Choose option from menu (a/b/c/d/m/x) to continue: ")
    if choice.lower() == "a":
        loginMenu()
    elif choice.lower() == "b":
        registerMenu()
    elif choice.lower() == "c":
        viewAccountMenu()
    elif choice.lower() == "d":
        if userAccount[0] == "":
            print("-" * 50)
            print("You haven't login to the system yet")
            print("Please login with valid username before choose this option\n")
        else:
            print("-" * 50)
            print("Hi", userAccount[0], "You will be redirected to reset your password now\n")
            resetPwdMenu()
    elif choice.lower() == "m":                                                                                         # To display option menu again (optional)
        optionMenu()
    elif choice.lower() == "x":
        print("You have chosen to exit the program")
        print("-" * 50)
        pass
    else:
        print("You haven't chosen the valid option")
        print("-" * 50)

logoutDateTime = datetime.now()
loginPeriod = logoutDateTime - currentDateTime                                                                          # Calculate duration in the system

print("You are in the system for: ", loginPeriod, " seconds")
print("You will be exited in 2 seconds")
while (datetime.now() - logoutDateTime).seconds < secondToDelay:                                                        # Delay seconds
    pass                                                                                                                # Do nothing, just wait until while loop is false
print("-"*50)
print("bye!!")