from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, InputRequired


class LoginForm(FlaskForm):
    login = StringField("Login: ", validators=[Length(min=4, max=100, message="Login must be between 4 and 100 characters")])
    password = PasswordField("Password: ", validators=[InputRequired(), Length(min=4, max=100)])
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    login = StringField("Login: ", validators=[Length(min=4, max=100, message="Login must be between 4 and 100 characters")])
    password = PasswordField("Password: ", validators=[InputRequired(),
                                                       Length(min=4, max=100, message="Password must be between 4 and 100 characters")])
    password2 = PasswordField("Confirm Password: ", validators=[InputRequired(), EqualTo('psw', message="Password mismatch")])
    submit = SubmitField("Register")


class CreateForm(FlaskForm):
    task_name = StringField("task_name: ", validators=[Length(min=4, max=100, message="Task name must be between 4 and 100 characters")])
    descriptions = StringField("descriptions: ",
                              validators=[Length(min=4, max=255, message="Description should be between 4 and 255 characters")])
    owner = StringField("owner: ",
                        validators=[Length(min=4, max=100, message="Owner name must be between 4 and 100 characters")])
    submit = SubmitField("Create")

