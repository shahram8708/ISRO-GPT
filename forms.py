from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

from models import User

class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=25)],
        render_kw={"placeholder": "Enter username", "class": "form-control"},
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email()],
        render_kw={"placeholder": "Enter email", "class": "form-control"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=6)],
        render_kw={"placeholder": "Enter password", "class": "form-control"},
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match")],
        render_kw={"placeholder": "Confirm password", "class": "form-control"},
    )
    submit = SubmitField("Register", render_kw={"class": "btn btn-primary w-100"})

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Username is already taken.")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError("An account with this email already exists.")


class LoginForm(FlaskForm):
    email = StringField(
        "Email or Username",
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter email or username", "class": "form-control"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter password", "class": "form-control"},
    )
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login", render_kw={"class": "btn btn-primary w-100"})

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    query_type = SelectField('Query Type', choices=[
        ('general', 'General Inquiry'),
        ('feedback', 'Feedback'),
        ('support', 'Support Request'),
        ('bug', 'Bug Report'),
        ('feature', 'Feature Request'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=20, message='Message must be at least 20 characters long')])
    subscribe = BooleanField('Subscribe to updates and newsletters')
