# app/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, DecimalField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    full_name = StringField('Full name', validators=[Length(max=255)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ReviewForm(FlaskForm):
    rating = IntegerField('Rating', validators=[DataRequired(), NumberRange(min=1, max=5)])
    title = StringField('Title', validators=[Length(max=255)])
    body = TextAreaField('Body', validators=[Length(max=2000)])
    submit = SubmitField('Submit')