from asymmetricEncryption import *
import datetime

adminInfo = []
#1  Create admin account
adminusername = "chiman"
adminPW = "123456"
newAdmin = (adminusername,adminPW)
adminInfo.append(newAdmin)


#2  Create an election
#2.1  Generate Admin Keys(Privacy Key & Public Key)

keys = generateKey()
#print(keys[0])

#storing_privkey(keys[0])

#2.2  Input election start time and end time
def startDatetime():
    startYear = input('Please input election start Year: ')
    startMonth = input('Please input election start Month: ')
    startDay = input('Please input election start Day: ')
    startHour = input('Please input election start Hour: ')
    startMinute = input('Please input election start Minute: ')
    startSecond = input('Please input election start Second: ')
    startDatetime = datetime.datetime(int(startYear),int(startMonth),int(startDay),int(startHour),int(startMinute),int(startSecond))
    return startDatetime

def endDatetime():
    endYear = input('Please input election end Year: ')
    endMonth = input('Please input election end Month: ')
    endDay = input('Please input election end Day: ')
    endHour = input('Please input election end Hour: ')
    endMinute = input('Please input election end Minute: ')
    endSecond = input('Please input election end Second: ')
    endDatetime = datetime.datetime(int(endYear),int(endMonth),int(endDay),int(endHour),int(endMinute),int(endSecond))
    return endDatetime

#2.3  Input detail of candidate

def inputElectionInfo():
    nameOfElection = input("What is the name of this election? ")
    questionInfo = []
    numberOfQuestion = input("How many Question do you have of the this election? ")
    for y in range(int(numberOfQuestion)):
        questionOfElection = input("What is your question "+ str(y+1) +" of this election? ")
        numberOfOption = input("How many Option of the this question? ")
        option=[]
        for x in range(int(numberOfOption)):
            optionName = input("Option "+ chr(65+x)+ " is: ")
            option.append(optionName)
        questionInfo.append((questionOfElection,option))
    return nameOfElection,questionInfo

#print(inputElectionInfo())
#2.4  Release the election
