from flask import Flask, render_template, abort, redirect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, ValidationError, SubmitField, HiddenField, SelectField
from wtforms.validators import DataRequired, InputRequired



app = Flask(__name__)
app.config["SECRET_KEY"] = "thisisasecret"


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
    try:
        if form.validate_on_submit():
            return render_template("home.html", form = form)
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

@app.route("/signup", methods = ["GET", "POST"])
def signup():
    form = SignUpForm()
    email = form.email.data
    username = form.username.data
    password = form.password.data
    try:
        if form.validate_on_submit():
            #Check Login
            #
            #
            return redirect(url_for("home"))
        return render_template("signup.html", form = form)
    except:
       abort(500)
    


#In Admin Account.................................................................................................................................................................................................................................
@app.route("/admin", methods = ["GET", "POST"])
def admin():
    return render_template("admin_home.html")



#Ask to Help.................................................................................................................................................................................................................................
@app.route("/help", methods = ["GET", "POST"])
def needHelp():
    return render_template("askforhelp.html")




#Start the Page.................................................................................................................................................................................................................................
if __name__ == "__main__":
    app.run(debug=True)