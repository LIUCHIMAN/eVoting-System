from secrets import choice
from flask import Flask, redirect, render_template, flash, abort, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, ValidationError, SubmitField, HiddenField, SelectField, IntegerField, RadioField
from wtforms.validators import DataRequired, InputRequired
from flask_bcrypt import Bcrypt
import uuid

app = Flask(__name__)
app.config["SECRET_KEY"] = "thisisasecret"
bcrypt = Bcrypt(app)


import pymongo
myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["eVoting"]


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
                return render_template("admin_home.html", user = loginUser)
            else:
                return render_template("wrongUnPw.html")
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

            
            newvoting = NewVoting(votingname, question, option)
            mydb.votingDB.insert_one(newvoting.exportNewVotingInfo())
          
            return redirect("/")
        return render_template("admin_newVoting.html", form = form)
    except:
       abort(500)


class NewVoting:
    #Constructor
    def __init__(self, votingname, question, option):
        self.votingname = votingname
        self.question = question
        self.option = option

    def exportNewVotingInfo(self):
        votingInfo = {
            "_id" : uuid.uuid4().hex,
            "votingname" : self.votingname,
            "question" : self.question,
            "option" : self.option,
            "status" : "Waiting to start"
            }
        return votingInfo



#Voting.................................................................................................................................................................................................................................
@app.route("/voting", methods = ["GET", "POST"])
def voting():
    votingInfo = mydb.votingDB.find_one({"votingname" : "try1"})
    try:
        if request.method == "POST":
            x=request.get_data(choice)
            y=x.decode()
            print(y[7:])
            print(type(y))
            return render_template("votingPage.html", votingInfo = votingInfo)
        return render_template("votingPage.html", votingInfo = votingInfo)
    except:
       abort(500)









#TRYTRYTRY.................................................................................................................................................................................................................................

@app.route("/try", methods = ["GET", "POST"])
def try1():
    loginUser = mydb.userDB.find_one({"username" : "chimanliu221"})
    votingInfo = mydb.votingDB.find({"votingname" : "try1"})

    return render_template("admin_home.html", user = loginUser, votinginfo = votingInfo)
        


    


#Ask to Help.................................................................................................................................................................................................................................
@app.route("/help", methods = ["GET", "POST"])
def needHelp():
    return render_template("askforhelp.html")

#Start the Page.................................................................................................................................................................................................................................
if __name__ == "__main__":
    app.run(debug=True)