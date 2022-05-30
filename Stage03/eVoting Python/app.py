from flask import Flask, render_template, flash, abort, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, ValidationError, SubmitField, HiddenField, SelectField
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
                return render_template("admin_home.html")
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


@app.route("/try", methods = ["GET", "POST"])
def try1():
    return render_template("admin_home.html")





#Ask to Help.................................................................................................................................................................................................................................
@app.route("/help", methods = ["GET", "POST"])
def needHelp():
    return render_template("askforhelp.html")

#Start the Page.................................................................................................................................................................................................................................
if __name__ == "__main__":
    app.run(debug=True)