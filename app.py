# Import necessary modules and libraries
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, login_user, UserMixin, logout_user, current_user
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

# Create a new Flask web server instance
app = Flask(__name__)


# Configure database settings for the Flask application
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Remember to replace this with a real secret key!

# Create a new SQLAlchemy database instance
db = SQLAlchemy(app)

# Setup and initialize Flask-Login's login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#--------------------------------------------models-----------------------------------------------------------

# User model definition
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Define relationship to the Income model
    incomes = db.relationship('Income', back_populates='user', lazy=True)
    # Define relationship to the Expense model
    expenses = db.relationship('Expense', back_populates='user', lazy=True)

    def set_password(self, password):
        # Hash and set the password for the user
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Check the password against its hash
        return check_password_hash(self.password_hash, password)

# Income model definition
class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    source = db.Column(db.String(80), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Define relationship to the User model
    user = db.relationship('User', back_populates='incomes')

# Expense model definition
class Expense(db.Model):
    class Expense(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
        category = db.Column(db.String(80), nullable=False)
        amount = db.Column(db.Integer, nullable=False)
        date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
        description = db.Column(db.String(200))
        # Define relationship to the User model
        user = db.relationship('User', back_populates='expenses')

 #---------------------------------------------forms------------------------------------------------------------

# Form definition for user registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    # Validate username uniqueness
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    # Validate email uniqueness
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already in use. Please choose a different one or log in.')


# Form definition for recording income
class IncomeForm(FlaskForm):
    source = StringField('Source', validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[Length(max=300)])  # Optional, so no DataRequired()
    amount = FloatField('Amount', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Form definition for recording expenses
class ExpenseForm(FlaskForm):
    source = StringField('Source/Category', validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[Length(max=300)])  # Optional, so no DataRequired()
    amount = FloatField('Amount', validators=[DataRequired()])
    submit = SubmitField('Submit')

#----------------------------------------------login-----------------------------------------------------------
# Define how Flask-Login retrieves a specific user object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#---------------------------------------------routes------------------------------------------------------------

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Thanks for registering!')
        return redirect(url_for('index'))  # Redirect to the main page or dashboard after registration
    return render_template('auth/register.html', form=form)

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))  # Redirect to the main page or dashboard after login
        flash('Invalid username or password')
    return render_template('auth/login.html')

# Route for user logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# Route for adding income

@app.route('/add_income', methods=['GET', 'POST'])
@login_required
def add_income():
    form = IncomeForm()
    if form.validate_on_submit():

        # Ensure the amount is positive
        if form.amount.data <= 0:
            flash('Please enter a positive amount for income.')
            return render_template('add_income.html', form=form)

        # Check for duplicate income source for the user
        existing_income = Income.query.filter_by(user_id=current_user.id, source=form.source.data).first()
        if existing_income:
            flash('You have already added this income source. Consider editing the existing entry.')
            return render_template('add_income.html', form=form)

        # Add the income
        income = Income(source=form.source.data, amount=form.amount.data, user_id=current_user.id)
        db.session.add(income)
        db.session.commit()

        flash('Income added successfully!')
        return redirect(url_for('view_incomes'))  # Redirect to the income list after adding income
    return render_template('add_income.html', form=form)

#route for editing / updating income

@app.route('/edit_income/<int:income_id>', methods=['GET', 'POST'])
@login_required
def edit_income(income_id):
    income = Income.query.get_or_404(income_id)

    # Ensure the logged-in user is the owner of the income entry
    if income.user_id != current_user.id:
        flash('You do not have permission to edit this entry.')
        return redirect(url_for('view_incomes'))

    form = IncomeForm(obj=income)  # Pre-fill the form with the current income details
    if form.validate_on_submit():

        # Ensure the amount is positive
        if form.amount.data <= 0:
            flash('Please enter a positive amount for income.')
            return render_template('edit_income.html', form=form)

        # Update the income details
        income.source = form.source.data
        income.amount = form.amount.data
        db.session.commit()

        flash('Income updated successfully!')
        return redirect(url_for('view_incomes'))
    return render_template('edit_income.html', form=form)


# Route for deleting income
@app.route('/delete_income/<int:income_id>', methods=['POST'])
@login_required
def delete_income(income_id):
    income = Income.query.get_or_404(income_id)

    # Ensure the logged-in user is the owner of the income entry
    if income.user_id != current_user.id:
        flash('You do not have permission to delete this entry.')
        return redirect(url_for('view_incomes'))

    db.session.delete(income)
    db.session.commit()
    flash('Income entry deleted successfully!')
    return redirect(url_for('view_incomes'))

# Route for viewing income list

@app.route('/view_incomes')
@login_required
def view_incomes():
    incomes = Income.query.filter_by(user_id=current_user.id).all()
    return render_template('view_incomes.html', incomes=incomes)




# Main dashboard route
@app.route('/index')
@login_required
def index():
    return "Hello, this is your dashboard!"

# Check if the script is executed as the main program and run the Flask app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
