from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField


class DrawForm(FlaskForm):
    number1 = IntegerField(id='no1')
    number2 = IntegerField(id='no2')
    number3 = IntegerField(id='no3')
    number4 = IntegerField(id='no4')
    number5 = IntegerField(id='no5')
    number6 = IntegerField(id='no6')
    submit = SubmitField("Submit Draw")
