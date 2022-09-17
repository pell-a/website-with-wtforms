from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import InputRequired, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import re


class RegisterForm(FlaskForm):
    name = StringField(validators=[InputRequired(message="Can't be left empty")])
    password = PasswordField(validators=[InputRequired(message="Can't be left empty"),
                                         Length(min=8, message="Password must be more than 8 characters")])
    email = EmailField(validators=[InputRequired(message="Can't be left empty"),
                                   Email(message="Not a valid email")])
    submit = SubmitField("Enter")


class LoginForm(FlaskForm):
    email = EmailField(validators=[InputRequired(message="Can't be left empty"),
                                   Email(message="Not a valid email")])
    password = PasswordField(validators=[InputRequired(message="Can't be left empty")])
    submit = SubmitField("Enter")


login_manager = LoginManager()
app = Flask(__name__)
login_manager.init_app(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "uy4g7utg5u5hb6g"
db = SQLAlchemy(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300))
    email = db.Column(db.String(300), unique=True)
    password = db.Column(db.Integer)


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Users.query.filter_by(email=email).first()
        if not user:
            flash("User does not exist, kindly sign up")
            return redirect(url_for('register_page'))
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash("Incorrect Password")
            return redirect(url_for('login_page'))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        password_pattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
        if not re.match(password_pattern, form.password.data):
            flash("Password must include at least an uppercase character, lowercase character, digit and special "
                  "character")
            return redirect(url_for('register_page'))
        if Users.query.filter_by(email=form.email.data).first():
            flash("You already have an account with this email, log in instead")
            return redirect(url_for('login_page'))
        new_user = Users(
            name=form.name.data,
            email=form.email.data,
            password=generate_password_hash(password=form.password.data, method="pbkdf2:sha256", salt_length=16)
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/logout")
@login_required
def logout_page():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)