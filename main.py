from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from flask_bootstrap import Bootstrap5


app = Flask(__name__)
app.config['SECRET_KEY'] = "dafadgadgadf"

# Intiialize Bootstrap
bootstrap = Bootstrap5(app)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

base_dir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(base_dir, "instance")
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_path, "users.db")}'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Setup LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Where to redirect unauthorized users

# CREATE TABLE IN DB
class User(UserMixin,db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Register')


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html", status=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        # Check if user already exists
        existing_user = db.session.execute(
            db.select(User).where(User.email == email).scalar()
        )
        if existing_user:
            flash("You have already signed up with that email. Please log in instead.")
            return redirect(url_for('login'))

        # Hash the password and create a new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(email=email, password=hashed_password, name=name)
        db.session.add(new_user)
        try:
            db.session.commit()
        except:
            db.session.rollback()
            flash("An error occurred while creating your account. Please try again.")
            return redirect(url_for("register"), form=form)
        else:
            flash("Registration successful! You are now logged in.")
            login_user(new_user)
            return redirect(url_for('secrets'))
    return render_template(
        "register.html", logged_in=current_user.is_authenticated, form=form)

# Flask-Login requires a user_loader function to load a user from the database
@login_manager.user_loader
def load_user(user_id):
    # This function is called to load a user from the database based on the user_id
    return User.query.get(int(user_id))

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)  # Log them in
            flash("Login successful!")
            return redirect(url_for('secrets'))
        flash("Login failed. incorrect email or password.")
    return render_template("login.html", logged_in=current_user.is_authenticated)

@app.route('/secrets')
@login_required  # This protects the route
def secrets():
    return render_template("secrets.html", name=current_user.name, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    # Destroy the session and log out the user
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('home'))


@app.route('/download')
def download():
    return send_from_directory(directory='static', path='files/cheat_sheet.pdf', as_attachment=True)

@app.route('/clear-users')
def clear_users():
    # WARNING: This will delete all users from the database
    User.query.delete()
    db.session.commit()
    flash("All users have been cleared from the database.")
    return redirect(url_for('home'))

if __name__ == "__main__":
    # Development server - NOT for production!
    # For production, use a WSGI server (like Gunicorn, uWSGI)
    # WSGI servers bridge Python Flask apps with web servers
    app.run(debug=True)
