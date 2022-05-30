import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")

#mydb = myclient["mydatabase"]
#mycol = mydb["bookingTable"]

mydb = myclient["mydatabase1"]  # you can also use dot notation client.mydatabase
mydb.mycoll.insert_one({"test": 'test'})

#print(client.list_database_names())

print(myclient.list_database_names())

#Connect MongoDB..................................................................................................................................................................................
#print("a")
#   app.config['MONGO_URI'] =  "mongodb+srv://admin:admin@cluster0.sl4dv.mongodb.net/mydb?retryWrites=true&w=majority"
#   mongo = PyMongo(app)
#client = pymongo.MongoClient("mongodb://localhost:27017")
#mydb = client["eVoting"]
#print("b")
#   mycol = mydb["bookingTable"]
#userDB = mydb["userTable"]
#print("c")
#bookingDB =  mydb["bookingTable"]
#billDB = mydb["billTable"]
#activityDB = mydb["activityTable"]
#activityAppliedDB = mydb["activityAppliedTable"]

#import pymongo

#client = pymongo.MongoClient()

#mydb = client["NMS"]

#mycol = mydb["bookingTable"]

#Guess Data
#guest = {'Name' : 'Chan Tai Man', 'Password' : 123456, 'Tel' : 98765432}
#Elderly Data
#elderly = {'Name' : 'Chan Father', 'roomNum' : '10-1'}

def inputdata(inputElderlyRoomNo, inputElderlyName, inputDate):
    newBooking = {'guestName' : guest['Name'], 'guestTel' : guest['Tel'], 'elderlyRoomNo' : inputElderlyRoomNo, 'elderlyName' : inputElderlyName, 'bookingDate' : inputDate, 'bookingTime' : inputTime, 'bookingStatus' : 'Waiting for approving'}
    mycol.insert_one(newBooking)
    return True