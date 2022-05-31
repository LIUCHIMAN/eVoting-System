from flask import Flask, flash, render_template, abort, request, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, ValidationError, SubmitField
from wtforms.validators import InputRequired
from flask_bcrypt import Bcrypt
import uuid
from ballot_encryption import *
from asymmetricEncryption import *
from blockchain import *
import urllib.parse

app = Flask(__name__)
app.config["SECRET_KEY"] = "thisisasecret"
bcrypt = Bcrypt(app)

#Database set up and connection.................................................................................................................................................................................................................................
import pymongo
myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["eVoting"]

#Session set up and Logout function.................................................................................................................................................................................................................................
def logout():
    session.pop("username" , None)
    session.pop("_id" , None)
    session["logged in"] = False


#Login to Admin Account.................................................................................................................................................................................................................................
class LoginForm(FlaskForm):
    username = StringField("Username", [InputRequired(), validators.Regexp("^(?!.*[!@#$%^&*])[A-Za-z\d]{7,15}$", message = "Please input a valid Username and at least 8 characters")])
    password = PasswordField("Password", [InputRequired(), validators.Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{11,15}$", message = "Must at least a number, a letter and a special characters and at least 12 characters")])
    loginBtn = SubmitField("LOGIN")

@app.route("/", methods = ["GET", "POST"])
def home():
    form = LoginForm()
    username = form.username.data
    password = form.password.data
    loginUser = mydb.userDB.find_one({"username" : username})
            
    try:
        if request.method == "POST" and form.validate_on_submit():
            if loginUser and bcrypt.check_password_hash(loginUser["password"], password):
                session["username"] = loginUser["username"]
                session["logged in"] = True
                votingactivityList = mydb.votingDB.find({"owner" : loginUser["username"]})
                return render_template("admin_home.html", user = loginUser, list = votingactivityList)
            else:
                return render_template("wrongUnPw.html")
        logout()
        return render_template("home.html", form = form)
    except:
       abort(500)


#Sign Up Admin Account.................................................................................................................................................................................................................................
class SignUpForm(FlaskForm):
    email = StringField("Email", [InputRequired(), validators.Regexp("^[a-zA-Z0-9]+@[a-zA-Z]+\.(com|net|edu|org){1,39}$", message = "Please input a valid email")])
    username = StringField("Username", [InputRequired(), validators.Regexp("^(?!.*[!@#$%^&*])[A-Za-z\d]{7,15}$", message = "Please input a valid Username and at least 8 characters")])
    password = PasswordField("Password", [InputRequired(), validators.Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{11,15}$", message = "Must at least a number, a letter and a special characters and at least 12 characters")])
    secpassword = PasswordField("Confirm Password", [InputRequired(), validators.EqualTo("password", message = "Password not match")])
    registerBtn = SubmitField("Register")

    def validate_username(FlaskForm, username):
        if mydb.userDB.find_one({"username" : username.data}) or mydb.userDB.find_one({"_id" : uuid.uuid4().hex}):
            raise ValidationError("Username Exist")

    def validate_email(FlaskForm, email):
        if mydb.userDB.find_one({"email" : email.data}) or mydb.userDB.find_one({"_id" : uuid.uuid4().hex}):
            raise ValidationError("Email has been used")

@app.route("/signup", methods = ["GET", "POST"])
def signup():
    form = SignUpForm()
    email = form.email.data
    username = form.username.data
    password = form.password.data
    try:
        if request.method == "POST" and form.validate_on_submit():
            hashPassword = bcrypt.generate_password_hash(password).decode("utf-8")
            
            user = User(email, username, hashPassword)
            mydb.userDB.insert_one(user.exportRegisterUserInfo())
            return render_template("seccussfulRegister.html")
        return render_template("signup.html", form = form)
    except:
       abort(500)
    
class User:
    #Constructor
    def __init__(self, email, username, password):
        self.email = email
        self.username = username
        self.password = password

    def exportRegisterUserInfo(self):
        userInfo = {
            "_id" : uuid.uuid4().hex,
            "email" : self.email,
            "username" : self.username,
            "password" : self.password,
            }
        return userInfo


#New Voting.................................................................................................................................................................................................................................
class NewVotingForm(FlaskForm):
    votingname = StringField("Name of Voting Activity", [InputRequired()])
    question = StringField("Voting Question", [InputRequired()])
    optionA = StringField("Option A: ", [InputRequired()])
    optionB = StringField("Option B: ", [InputRequired()])
    optionC = StringField("Option C: ")
    optionD = StringField("Option D: ")
    optionE = StringField("Option E: ")
    optionF = StringField("Option F: ")
    optionG = StringField("Option G: ")
    optionH = StringField("Option H: ")
    submitBtn = SubmitField("CREATE")

@app.route("/newvoting", methods = ["GET", "POST"])
def newvoting():
    form = NewVotingForm()
    votingname = form.votingname.data
    question = form.question.data
    optionA = form.optionA.data
    optionB = form.optionB.data
    optionC = form.optionC.data
    optionD = form.optionD.data
    optionE = form.optionE.data
    optionF = form.optionF.data
    optionG = form.optionG.data
    optionH = form.optionH.data
    keys = generateKey()
    priv_key = show_privkey(keys[0])
    pub_key = show_pubkey(keys[1])

        
    try:
        if request.method == "POST" and form.validate_on_submit():
            if optionC == "":
                option = [optionA, optionB]
            elif optionD == "":
                option = [optionA, optionB, optionC]
            elif optionE == "":
                option = [optionA, optionB, optionC, optionD]
            elif optionF == "":
                option = [optionA, optionB, optionC, optionD, optionE]
            elif optionG == "":
                option = [optionA, optionB, optionC, optionD, optionE, optionF]
            elif optionH == "":
                option = [optionA, optionB, optionC, optionD, optionE, optionF, optionG]
            else:            
                option = [optionA, optionB, optionC, optionD, optionE, optionF, optionG, optionH]

            owner = session.get("username")
            newvoting = NewVoting(votingname, owner, question, option, pub_key)
            mydb.votingDB.insert_one(newvoting.exportNewVotingInfo())
            loginUser = owner
            votingactivityList = mydb.votingDB.find({"owner" : loginUser})

            voteInfo = mydb.votingDB.find_one({"votingname" : votingname},{"owner" : owner})
            voteID = voteInfo['_id']
            ballot_database = []
            block_database = []
            newBallotDB = NewBallotDB(voteID, owner, ballot_database, block_database)
            mydb.ballotDB.insert_one(newBallotDB.exportNewBallotDBInfo())
            Storing_privkey(keys[0], votingname)
            return render_template("admin_home.html", user = loginUser, list = votingactivityList)
        return render_template("admin_newVoting.html", form = form, priv_key = priv_key)
    except:
       abort(500)

class NewVoting:
    #Constructor
    def __init__(self, votingname, owner, question, option, pubKey):
        self.votingname = votingname
        self.owner = owner
        self.question = question
        self.option = option
        self.pubKey = pubKey

    def exportNewVotingInfo(self):
        votingInfo = {
            "_id" : uuid.uuid4().hex,
            "votingname" : self.votingname,
            "owner" : self.owner,
            "question" : self.question,
            "option" : self.option,
            "pubKey" : self.pubKey,
            "status" : "Waiting to start"
            }
        return votingInfo

class NewBallotDB:
    #Constructor
    def __init__(self, voteID, owner, ballot_database, block_database):
        self.voteID = voteID
        self.owner = owner
        self.ballot_database = ballot_database
        self.block_database = block_database

    def exportNewBallotDBInfo(self):
        votingInfo = {
            "_id" : uuid.uuid4().hex,
            "voteID" : self.voteID,
            "owner" : self.owner,
            "ballot_database" : self.ballot_database,
            "block_database" : self.block_database,
            "current_hash" : "Initial Block"
            }
        return votingInfo


#Voting.................................................................................................................................................................................................................................
@app.route("/voting/<id>", methods = ["GET", "POST"])
def confirmvoting(id):
    try:
        if session["logged in"] == True:
            btn = id[0:3]
            newID = id[3:]
            session['_id'] = newID
            if btn == "tra":
                votingInfo = mydb.votingDB.find_one({"_id" : newID})
                votingtracker = ""
                return render_template("votingPageTracker.html", votingInfo = votingInfo, votingtracker = votingtracker)
            if btn == "sta":
                votingInfo = mydb.votingDB.find_one({"_id" : newID})
                mydb.votingDB.update_one({"_id" : newID}, { "$set": { "status": "In Progress" } })
                return render_template("votingPage.html", votingInfo = votingInfo)
            if btn == "con":
                votingInfo = mydb.votingDB.find_one({"_id" : newID})
                return render_template("votingPage.html", votingInfo = votingInfo)
            if btn == "ree":
                votingInfo = mydb.votingDB.find_one({"_id" : newID})
                mydb.votingDB.update_one({"_id" : newID}, { "$set": { "status": "In Progress" } })
                return render_template("votingPage.html", votingInfo = votingInfo)
            if btn == "end":
                mydb.votingDB.update_one({"_id" : newID}, { "$set": { "status": "End" } })
                votingInfo = mydb.votingDB.find_one({"_id" : newID})
                result = []
                return render_template("votingPageResult.html", votingInfo = votingInfo, result = result)
            if btn == "res":
                votingInfo = mydb.votingDB.find_one({"_id" : newID})
                result = []
                return render_template("votingPageResult.html", votingInfo = votingInfo, result = result)
            if btn == "del":
                loginUser = session.get("username")
                votingactivityList = mydb.votingDB.find({"owner" : loginUser})
                mydb.votingDB.delete_one({"_id" : newID})
                mydb.ballottrackerDB.delete_many({"votingID" : newID})
                mydb.ballotDB.delete_one({"voteID" : newID})
                return render_template("admin_home.html", user = loginUser, list = votingactivityList)
        return render_template("askforhelp.html")
    except:
        abort(500)

@app.route("/votingtracker", methods = ["GET", "POST"])
def votingtracker():
    id = session.get('_id')
    votingInfo = mydb.votingDB.find_one({"_id" : id})
    try:
        if request.method == "POST":
            votingtracker = ballot_tracker_generation().decode()
            newBallotTracker = NewBallotTracker(id,votingtracker)
            mydb.ballottrackerDB.insert_one(newBallotTracker.exportBallotTracker())
            return render_template("votingPageTracker.html", votingInfo = votingInfo, votingtracker = votingtracker)
        votingtracker = ""
        return render_template("votingPageTracker.html", votingInfo = votingInfo, votingtracker = votingtracker)
    except:
       abort(500)

class NewBallotTracker:
    #Constructor
    def __init__(self, id, votingtracker):
        self.id = id
        self.votingtracker = votingtracker

    def exportBallotTracker(self):
        ballotInfo = {
            "_id" : uuid.uuid4().hex,
            "votingID" : self.id,
            "votingtracker" : self.votingtracker,
            "status" : "Just Registered"
            }
        return ballotInfo

@app.route("/voting", methods = ["GET", "POST"])
def voting():
    id = session.get('_id')
    votingInfo = mydb.votingDB.find_one({"_id" : id})
    try:
        if request.method == "POST":
            x = request.get_data()
            y = urllib.parse.unquote(x.decode())
            point = y.find("&ballottracker=")
            choice = y[0:point][7:]
            ballottracker = y[point:][15:]
            voteID = ""
            #Encoding the ballot
            #first_encrypted_ballot = ballot_encoding(choice,ballottracker).decode()
            
            checkTracker = mydb.ballottrackerDB.find({"votingID" : id})
            existingTracker = False
            for x in checkTracker:
                if x['votingtracker'] == ballottracker:
                    if x['status'] == "Just Registered":
                        voteID = x["_id"]
                        existingTracker = True

            if existingTracker == True:
                #Saving
                #Encoding the ballot
                first_encrypted_ballot = ballot_encoding(choice,ballottracker).decode()
                #Encrypt the ballot
                final_encrypted_ballot = encrypt_message(first_encrypted_ballot,reading_pubkey(votingInfo["pubKey"]))
                ballotDB = mydb.ballotDB.find_one({"voteID" : votingInfo["_id"]})
                #Storing the ballot by Blockchain
                block_database = ballotDB["block_database"]
                ballot_database = ballotDB["ballot_database"]
                current_hash = ballotDB["current_hash"]

                len_of_block = len(block_database)
                #first Block
                if len_of_block == 0:
                    ballot_database.append(final_encrypted_ballot)
                    new_block = Block(current_hash, ballot_database)
                    block_database.append((new_block.block_hash,new_block.block_data))
                    current_hash = new_block.block_hash
                    mydb.ballotDB.update_one({"voteID" : ballotDB["voteID"]}, { "$set": { "ballot_database": ballot_database }})
                    mydb.ballotDB.update_one({"voteID" : ballotDB["voteID"]}, { "$set": { "block_database": block_database }})
                    mydb.ballotDB.update_one({"voteID" : ballotDB["voteID"]}, { "$set": { "current_hash": current_hash }})
                
                elif len_of_block == 1:
                    #Using current database + previous hash--> hash and compare with current hash --> if same --> ballot_database will + new data -->create new block and append to block_database 
                    check_block = Block("Initial Block",ballot_database)
                    if current_hash == check_block.block_hash:
                        ballot_database.append(final_encrypted_ballot)
                        new_block = Block(current_hash, ballot_database)
                        block_database.append((new_block.block_hash,new_block.block_data))
                        current_hash = new_block.block_hash
                        mydb.ballotDB.update_one({"voteID" : ballotDB["voteID"]}, { "$set": { "ballot_database": ballot_database }})
                        mydb.ballotDB.update_one({"voteID" : ballotDB["voteID"]}, { "$set": { "block_database": block_database }})
                        mydb.ballotDB.update_one({"voteID" : ballotDB["voteID"]}, { "$set": { "current_hash": current_hash }})    
                    else:
                        logout()
                        return render_template("askforhelp2.html")

                else:
                    check_block = Block(block_database[len_of_block-2][0],ballot_database)
                    if current_hash == check_block.block_hash:
                        ballot_database.append(final_encrypted_ballot)
                        new_block = Block(current_hash, ballot_database)
                        block_database.append((new_block.block_hash,new_block.block_data))
                        current_hash = new_block.block_hash
                        mydb.ballotDB.update_one({"voteID" : ballotDB["voteID"]}, { "$set": { "ballot_database": ballot_database }})
                        mydb.ballotDB.update_one({"voteID" : ballotDB["voteID"]}, { "$set": { "block_database": block_database }})
                        mydb.ballotDB.update_one({"voteID" : ballotDB["voteID"]}, { "$set": { "current_hash": current_hash }}) 
                    else:
                        logout()
                        return render_template("askforhelp2.html")
                
                mydb.ballottrackerDB.update_one({"_id" : voteID}, { "$set": { "status": "Voted" } })
                flash("Your vote is successful. Next voter can vote.")

                return render_template("votingPage.html", votingInfo = votingInfo)
            else:
                flash("Your Ballot Tracker is wrong!!!Or You have voted!!! Please ask for help.")
                return render_template("votingPage.html", votingInfo = votingInfo)
            #return render_template("votingPage.html", votingInfo = votingInfo)
        return render_template("votingPage.html", votingInfo = votingInfo)
    except:
       abort(500)
 
@app.route("/result", methods = ["GET", "POST"])
def result():
    id = session.get('_id')
    votingInfo = mydb.votingDB.find_one({"_id" : id})
    ballotInfo = mydb.ballotDB.find_one({"voteID" : id})
    ballotTrackerInfo = mydb.ballottrackerDB.find({"votingID" : id})
    try:
        priKey = reading_privkey(votingInfo["votingname"])
    except:
       return render_template("errorPrivKey.html")

    resultList = []

    ballotTracker = []
    for votingtracker in ballotTrackerInfo:
        ballotTracker.append(votingtracker['votingtracker'])   
    
    for y in votingInfo["option"]:
        count = 0
        for x in ballotInfo["ballot_database"]:
            original_message = decrypt_message(x,priKey)
            for z in range(len(ballotTracker)):
                try:
                    message = ballot_decoding(original_message,ballotTracker[z])
                    if message == y:
                        count = count + 1
                except:
                    i=0
                
        result = (y,count)
        resultList.append(result)
    
    try:
        if request.method == "POST":
            return render_template("votingPageResult.html", votingInfo = votingInfo, result = resultList)
        votingtracker = []
        return render_template("votingPageResult.html", votingInfo = votingInfo, result = resultList)
    except:
       abort(500)


#Ask to Help.................................................................................................................................................................................................................................
@app.route("/help", methods = ["GET", "POST"])
def needHelp():
    return render_template("askforhelp.html")


#Start the Page.................................................................................................................................................................................................................................
if __name__ == "__main__":
    app.run(debug=True)