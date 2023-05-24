# -------------------------------- SOA ----------------
#                                Anupong
#                                20230524
#					        SOA Assignment
#					            Simple Login



# ----------------------Libraries----------------------
from datetime import datetime
import string
import rsa
import secrets


# ----------------------my function----------------
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
    count = 0
    while count < 3:

        existingUser = input("Please enter your user name: ")
        existingPwd = input("Please enter your password: ")
        userName, passWord, enCryptedPwd, eMail, lastReset, lastLogin, dayAfterResetPwd, dayAfterLastLogin = validateUser(existingUser, existingPwd)
        if dayAfterResetPwd >= dayToReset:
            print("Welcome back", existingUser)
            print("Your last login was", dayAfterLastLogin, "days ago")
            print("You haven't reset your password for", dayAfterResetPwd, "days")
            print("You must reset your password now")
            newResetPwd, newEncPwd = resetPwdMenu()
            return
        elif dayAfterResetPwd >= dayToReset -dayToNotify:
            print("Welcome back", existingUser)
            print("Your last login was", dayAfterLastLogin, "days ago")
            print("You haven't reset your password for", dayAfterResetPwd, "days")
            print("You should reset your password within next", dayToReset - dayAfterResetPwd, "days")
            return
        elif dayAfterResetPwd >= 0:
            print("Welcome back", existingUser)
            print("Your last login was", dayAfterLastLogin, "days ago")
            print("You haven't reset your password for", dayAfterResetPwd, "days")
            return
        else:
            print("Type: ",type(dayAfterResetPwd), dayAfterResetPwd)
            print("Either your username or password is invalid, please try again!")
            count = count + 1
    print("-"*50)
    print("You have failed to login 3 times!. Please contact system administrator")
    exit()

def registerMenu():
    while True:
        newUser = input("Please choose username: ")
        for eachLine in accInfo:
            userName, passWord, enCryptedPwd, eMail, last_reset, last_login = eachLine.split(",")
            if newUser == userName:
                print("This username has been taken")
                print("Please choose option menu again")
                return                                                                                                  # User force to choose option Menu again
            else:
                if newUser[0].islower() and newUser.isalnum() and len(newUser) > 5:
                    newPass = input("Please choose your password or type 'a' to auto-generate password: ")
                    if newPass.lower() == "a" and len(newPass) == 1:
                        print("You have chosen", newPass, "system to auto-generate the password")
                        newPass = ranPwd()
                    elif len(newPass) <8:
                        print("Your password is too short")
                        print("Please choose option menu again")
                        return                                                                                          # User force to choose option Menu again
                    else:
                        if validatePass(newPass) < 3:
                            print("Your password combination doesn't follow company's policies")
                            print("Please choose option menu again")
                            return                                                                                      # User force to choose option Menu again


                    emailAddress = input("Please enter valid email address: ")
                    if "@" in emailAddress:
                        print("Congratulations! You have registered to the system")
                        print("Your username: ",newUser)
                        print("Your password: ", newPass)
                        print("Your email address: ", emailAddress)
                        encPwd = rsa.encrypt(newPass.encode(), pbKey).hex()

                        writeAccount(newUser, newPass, encPwd, emailAddress, currentDate, currentDate)
                        return
                    else:
                        print("Your email address is not valid")
                        print("Please choose option menu again")
                        return
                else:
                    print("You haven't choose the correct username policy")
                    break


def resetPwdMenu():
    while True:
        newPass = input("Please choose your password or type 'a' to auto-generate password: ")
        if newPass.lower() == "a" and len(newPass) == 1:
            newPass = ranPwd()
        elif len(newPass) < 8:
            print("Your password is too short")
            print("Please choose option menu again")
            return
        else:
            if validatePass(newPass) < 3:
                print("Your password combination doesn't follow company's policies")
                print("Please try again!")
    encPwd = rsa.encrypt(newPass.encode(), pbKey).hex()
    return newPass, encPwd
def viewAccountMenu():
    for eachLine in accInfo:
        for eachItem in eachLine.split(","):
            print(eachItem)
def ranPwd():
    pwdLength = 8

    randomPwd = ""
    total = 0
    while True:
        randomPwd = "".join([secrets.choice(allPossibleChar) for i in range(8)])                                        # Random password from possible characters in length of 8 characters

        if validatePass(randomPwd) >= 3:                                                                                # Check if at least 3 conditions fulfiled
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
        userName, passWord, enCryptedPwd, eMail, lastReset, lastLogin = eachLine.strip().split(",")
        if existingUser == userName and existingPwd == passWord:

            lastReset = datetime.strptime(lastReset, "%d/%m/%y")
            lastLogin = datetime.strptime(lastLogin, "%d/%m/%y")
            dayPwd = (currentDateTime - lastReset).days
            dayLogin = (currentDateTime - lastLogin).days
            return userName, passWord, enCryptedPwd, eMail, lastReset, lastLogin, dayPwd, dayLogin
        else:
            dayPwd = -1
            dayLogin = -1
    return userName, passWord, enCryptedPwd, eMail, lastReset, lastLogin, dayPwd, dayLogin
def writeAccount(user, pwd, enc, email, login, change):
    newLine = [user, pwd, enc, email, str(login), str(change)]
    accFile.write("\n")
    accFile.write(",".join(newLine))

    return
# -------------------------variables--------------

fileName = "account.txt"
currentDateTime = datetime.now()
currentDate = currentDateTime.strftime("%d/%m/%y")
choice = ""
userName = ""
adminUser = "admin"
adminPass = "adminpass"
dayAfterResetPwd = 0
dayAfterLastLogin = 0
dayToReset = 120
dayToNotify = 10

nonAlphaString = string.punctuation
smallAlphaChar = string.ascii_lowercase
capAlphaChar = string.ascii_uppercase
numChar = string.digits
allPossibleChar = nonAlphaString + smallAlphaChar + capAlphaChar + numChar                                              # Concatenate with all possible characters for randomising password

pvKey, pbKey = rsa.newkeys(256)
# ----------------------the main code----------------
try:
    accFile = open(fileName, "r+")
except FileNotFoundError:
    accFile = open(fileName, "w+")

accInfo = accFile.readlines()
for line in accInfo:
    info = line.split(",")
    print(info[0])

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
        pass
    elif choice.lower() == "d":
        pass
    elif choice.lower() == "m":                                                                                         # To display option menu again
        optionMenu()
    elif choice.lower() == "x":
        pass
    else:
        print("You haven't chosen the valid option")

accFile.close()
logoutDateTime = datetime.now()
loginPeriod = logoutDateTime - currentDateTime

print("You are in the system for: ", loginPeriod)
print("You will be exited in 2 seconds")
while (datetime.now() - logoutDateTime).seconds < 2:
    pass
print("bye!!")