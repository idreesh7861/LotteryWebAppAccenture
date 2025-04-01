from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import Email, Length, DataRequired, EqualTo, ValidationError
import re
from datetime import datetime


def validate_phone(self, phone):
    # Regex for Phone Number Validation
    p = re.compile("^\d{4}-\d{3}-\d{4}$")
    if not p.match(phone.data):
        raise ValidationError("Phone number must be in the form: 1234-567-8910")


def validate_password(self, password):
    # Regex for Password Validation
    p = re.compile("^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z\d]).*$")
    if not p.match(password.data):
        raise ValidationError(
            "Password must contain at least 1 digit, at least 1 lowercase and at least 1 uppercase character."
            "Password must contain at least 1 special character")


def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][*{$#@<>"
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(f"Character {char} is not allowed.")

def validate_dob(form, dob):
    # Ensure D.O.B. is a valid Date
    try:
        # Attempt to parse the date string
        date_object = datetime.strptime(dob.data, "%d/%m/%Y")
        return True

    except ValueError:
        raise ValidationError("Date of Birth must be a valid Date of the form: DD/MM/YYYY")


def validate_postcode(self, postcode):
    # Regex for Postcode Validation
    p = re.compile("^(?:[A-Z]\d\s\d[A-Z]{2}|[A-Z]{2}\d\s\d[A-Z]{2}|[A-Z]\d[A-Z]\s\d[A-Z]{2})$")
    if not p.match(postcode.data):
        raise ValidationError(
            """Postcode must be of the following forms:
            XY YXX
            XYY YXX
            XXY YXX""")


class RegisterForm(FlaskForm):
    email = StringField(validators=[Email()])
    firstname = StringField(validators=[character_check])
    lastname = StringField(validators=[character_check])
    phone = StringField(validators=[validate_phone])
    dob = StringField(validators=[DataRequired(), validate_dob])
    postcode = StringField(validators=[DataRequired(), validate_postcode])
    password = PasswordField(validators=[DataRequired(), Length(min=6, max=12), validate_password])
    confirm_password = PasswordField(validators=[EqualTo('password',
                                                         message='Both password fields must be equal')])
    submit = SubmitField()


class LoginForm(FlaskForm):
    email = StringField(validators=[Email(), DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    pin = StringField(validators=[DataRequired()])
    postcode = StringField(validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField()


class PasswordForm(FlaskForm):
    current_password = PasswordField(id='password',
                                     validators=[DataRequired(), Length(min=6, max=12), validate_password])
    show_password = BooleanField('Show password', id='check')
    new_password = PasswordField(validators=[DataRequired(), Length(min=6, max=12), validate_password])
    confirm_new_password = PasswordField(
        validators=[DataRequired(), EqualTo('new_password', message='Both new password fields must be equal')])
    submit = SubmitField('Change Password')
