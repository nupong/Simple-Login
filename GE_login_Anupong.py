# -------------------------------- SOA -----------------------------------------
#                                Anupong
#                                20230531
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
            userAccount[4] = currentDate
            userAccount[5] = currentDate
            userAccount[1], userAccount[2] = resetPwd()
            writeAccount(userAccount[0],userAccount[1],userAccount[2],userAccount[3],userAccount[4],userAccount[5])
            return
        elif userAccount[6] >= dayToReset - dayToNotify:                                                                # Warn if almost reset password
            print("Welcome back", existingUser)
            print("Your last login was", userAccount[7], "days ago")
            print("You haven't reset your password for", userAccount[6], "days")
            print("You should reset your password within next", dayToReset - userAccount[6], "days")
            userAccount[5] = currentDate
            writeAccount(userAccount[0],userAccount[1],userAccount[2],userAccount[3],userAccount[4],userAccount[5])
            return

        elif userAccount[6] >= 0:                                                                                       # Login successful
            print("Welcome back", existingUser)
            print("Your last login was", userAccount[7], "days ago")
            print("You haven't reset your password for", userAccount[6], "days")
            userAccount[5] = currentDate
            writeAccount(userAccount[0],userAccount[1],userAccount[2],userAccount[3],userAccount[4],userAccount[5])
            return
        else:                                                                                                           # userAccount[6] is -1
            print("Either your username or password is invalid, please try again!")
            count = count + 1
    print("-"*50)
    print("You have failed to login 3 times!. Please contact system administrator")
    exit()

def registerMenu():
    print("Welcome to Register Menu")
    while True:
        newUser = input("Please choose username: ")
        for eachLine in accInfo:
            eachItem = eachLine.strip().split(",")
            if newUser == eachItem[0]:                                                                                  # Check if username has been taken
                print("This username has been taken")
                break
            else:
                if newUser[0].islower() and newUser.isalnum() and len(newUser) > 5 and len(newUser) < 13:               # Check if username followed policies
                    newPass = input("Please choose your password or type 'a' to auto-generate password: ")
                    if newPass.lower() == "a" and len(newPass) == 1:                                                    # Check if auto-gen pswd
                        print("You have chosen", newPass, "system to auto-generate the password")
                        newPass = ranPwd()
                    elif len(newPass) < 8:                                                                              # Check password length
                        print("Your password is too short")
                        break
                    else:
                        if validatePass(newPass) < 3:                                                                   # Check if password followed policies
                            print("Your password combination doesn't follow company's policies")
                            break

                    emailAddress = input("Please enter valid email address: ")
                    if "@" in emailAddress:                                                                             # Check if email has @
                        print("Congratulations! You have registered to the system")
                        print("Your username: ",newUser)
                        print("Your password: ", newPass)
                        print("Your email address: ", emailAddress)
                        print("Please login again if you want to access the system")
                        encPwd = rsa.encrypt(newPass.encode(), pbKey).hex()                                             # Encrypted string

                        writeAccount(newUser, newPass, encPwd, emailAddress, currentDate, currentDate)                  # Write to accounts.txt
                        return
                    else:
                        print("Your email address is not valid")

                        break
                else:
                    print("You haven't followed the correct username policy")
                    break


def resetPwdMenu():
    global userAccount

    print("Welcome to Reset Password Menu")
    userAccount[1], userAccount[2] = resetPwd()                                                                         # Call reset function
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
            # print("Please choose option menu again")
            # return
        else:
            if validatePass(newPass) < 3:                                                                               # Check if password followed policies
                print("Your password combination doesn't follow company's policies")
                print("Please try again!")
            else:
                print("Your new password is", newPass)
                break
    encPwd = rsa.encrypt(newPass.encode(), pbKey).hex()                                                                 # Encrypted string from keys
    return newPass, encPwd

def viewAccountMenu():
    print("Welcome to View Account Menu")
    print("Only System Administrator can access this menu")
    print("Please login with SA credentials")
    saUser = input("Please type SA account: ")
    saPswd = input("Please type SA password: ")
    if saUser == adminUser and saPswd == adminPass:                                                                     # Check SA Credentials
        print("*"*50)
        print("Username\t","Password\t","Encrypted\t","Email\t","Last_Login\t","Last_Password_Changed")                 # Setup header
        for eachLine in accInfo:
            cleanLine = eachLine.strip()
            for eachItem in cleanLine.split(","):
                print(eachItem, end = "\t\t")
            print("")
    else:
        print("You haven't provided valid SA credentials")
def ranPwd():
    pwdLength = 8

    randomPwd = ""
    total = 0
    while True:
        randomPwd = "".join([secrets.choice(allPossibleChar) for i in range(8)])                                        # Random password from possible characters in length of 8 characters

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

    return sum(pwdChk)

def validateUser(existingUser, existingPwd):
    for eachLine in accInfo:
        eachItem = []
        eachItem = eachLine.strip().split(",")
        if existingUser == eachItem[0] and existingPwd == eachItem[1]:                                                  # Check if username/password are matched
            lastReset = datetime.strptime(eachItem[4], "%d/%m/%y")
            lastLogin = datetime.strptime(eachItem[5], "%d/%m/%y")
            print(lastReset, lastLogin)
            eachItem[4] = datetime.strftime(lastReset, "%d/%m/%y")
            eachItem[5] = datetime.strftime(lastLogin, "%d/%m/%y")
            eachItem.append((currentDateTime - lastReset).days)
            eachItem.append((currentDateTime - lastLogin).days)
            return eachItem
    eachItem = [existingUser,existingPwd,"","","","",-1,-1]                                                             # Set days to minus to indicate bad username/password
    return eachItem

def writeAccount(user, pwd, enc, email, login, change):                                                                 # Frunction to write info to file
    global accInfo
    foundUser = False
    for i, eachLine in enumerate(accInfo):                                                                              # Check if existing user
        eachItem = eachLine.strip().split(",")
        if user == eachItem[0]:
            foundUser = True
            lineIndex = i                                                                                               # Get line index where username is existed
            oldLine = [user, pwd, enc, email, str(login), str(change)]
            accInfo[i] = ",".join(oldLine) + "\n"                                                                       # Replace new information to line index
            with open(fileName,"w") as writeFile:
                writeFile.writelines(accInfo)
            with open(fileName, "r") as readFile:
                accInfo = readFile.readlines()                                                                          # Re-read to get latest info from file after wrote

    if foundUser == False:                                                                                              # If username is new register user
        newLine = [user, pwd, enc, email, str(login), str(change)]
        with open(fileName, "r+") as writeFile:
            info = writeFile.readlines()
            # print(info)
            writeFile.write("\n")
            writeFile.write(",".join(newLine))
        with open(fileName, "r") as readFile:
            accInfo = readFile.readlines()                                                                              # Re-read to get latest info from file after wrote
    return
# -------------------------variables-----------------------------------------------

fileName = "accounts.txt"
currentDateTime = datetime.now()
currentDate = currentDateTime.strftime("%d/%m/%y")
choice = ""
userName = ""
userAccount = ["","","","","","",0,0]
adminUser = "admin"
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
    with open(fileName, 'r') as accFile:
        accInfo = accFile.readlines()
except FileNotFoundError:
    with open(fileName, "w+") as accFile:
        print("No account data found!")
        print("Account data has been created\n")
        accInfo = accFile.readlines()

print("-"*50)
print("Welcome to Gelos Enterprises System")
print("Date: ", currentDateTime)

optionMenu()
while choice.lower() != "x":
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
    elif choice.lower() == "m":                                                                                         # To display option menu again
        optionMenu()
        print("-" * 50)
    elif choice.lower() == "x":
        print("You have chosen to exit the program")
        print("-" * 50)
        pass
    else:
        print("You haven't chosen the valid option")
        print("-" * 50)

logoutDateTime = datetime.now()
loginPeriod = logoutDateTime - currentDateTime

print("You are in the system for: ", loginPeriod)
print("You will be exited in 2 seconds")
while (datetime.now() - logoutDateTime).seconds < secondToDelay:                                                        # Delay seconds
    pass                                                                                                                # Do nothing, just wait until while loop is false
print("-"*50)
print("bye!!")