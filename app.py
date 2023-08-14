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


# --------------------------------------------MODELS-----------------------------------------------------------

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
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(80), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.String(200))
    # Define relationship to the User model
    user = db.relationship('User', back_populates='expenses')


# ---------------------------------------------FORMS------------------------------------------------------------

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
    category = StringField('Category', validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[Length(max=300)])  # Optional, so no DataRequired()
    amount = FloatField('Amount', validators=[DataRequired()])
    submit = SubmitField('Submit')


# ----------------------------------------------Login-----------------------------------------------------------
# Define how Flask-Login retrieves a specific user object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------------------------USER-ROUTES-------------------------------------------------------

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

        try:
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('Thanks for registering!')
            return redirect(url_for('index'))
        except:
            db.session.rollback()
            flash('Error! Unable to register at the moment.')
    return render_template('auth/register.html', form=form)


# Route for user login with error handling
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('index'))
            flash('Invalid username or password')
    except Exception as e:
        flash('Error during login. Please try again.')
    return render_template('auth/login.html')


# Route for user logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


# ------------------------------------------INCOME-ROUTES----------------------------------------------------------

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

        # Add the income
        income = Income(source=form.source.data, amount=form.amount.data, user_id=current_user.id)

        try:
            db.session.add(income)
            db.session.commit()
            flash('Income added successfully!')
        except Exception as e:
            db.session.rollback()
            flash('Error adding income. Please try again later.', 'error')

        return redirect(url_for('view_incomes'))  # Redirect to the income list after adding income
    return render_template('add_income.html', form=form)


# route for editing / updating income

@app.route('/edit_income/<int:income_id>', methods=['GET', 'POST'])
@login_required
def edit_income(income_id):
    income = Income.query.get_or_404(income_id)
    if income.user_id != current_user.id:
        flash('You do not have permission to edit this entry.')
        return redirect(url_for('view_incomes'))

    form = IncomeForm(obj=income)
    if form.validate_on_submit():
        if form.amount.data <= 0:
            flash('Please enter a positive amount for income.')
            return render_template('edit_income.html', form=form)
        income.source = form.source.data
        income.amount = form.amount.data
        try:
            db.session.commit()
            flash('Income updated successfully!')
        except Exception as e:
            db.session.rollback()
            flash('Error updating income. Please try again later.')
        return redirect(url_for('view_incomes'))
    return render_template('edit_income.html', form=form)


# Route for deleting income
@app.route('/delete_income/<int:income_id>', methods=['POST'])
@login_required
def delete_income(income_id):
    income = Income.query.get_or_404(income_id)
    if income.user_id != current_user.id:
        flash('You do not have permission to delete this entry.')
        return redirect(url_for('view_incomes'))
    try:
        db.session.delete(income)
        db.session.commit()
        flash('Income entry deleted successfully!')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting income. Please try again later.')
    return redirect(url_for('view_incomes'))


# route for viewing incomes

@app.route('/view_incomes')
@login_required
def view_incomes():
    incomes = Income.query.filter_by(user_id=current_user.id).all()
    return render_template('view_incomes.html', incomes=incomes)


# ------------------------------------------EXPENSE-ROUTES----------------------------------------------------------

# route for adding expense

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    form = ExpenseForm()
    if form.validate_on_submit():
        if form.amount.data <= 0:
            flash('Please enter a positive amount for the expense.')
            return render_template('add_expense.html', form=form)

        expense = Expense(category=form.category.data, amount=form.amount.data, description=form.description.data,
                          user_id=current_user.id)
        try:
            db.session.add(expense)
            db.session.commit()
            flash('Expense added successfully!')
        except:
            db.session.rollback()
            flash('Error adding expense. Please try again later.')
        return redirect(url_for('view_expenses'))

    return render_template('add_expense.html', form=form)


# Route for editing / updating expense

@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash('You do not have permission to edit this entry.')
        return redirect(url_for('view_expenses'))

    form = ExpenseForm(obj=expense)
    if form.validate_on_submit():
        if form.amount.data <= 0:
            flash('Please enter a positive amount for the expense.')
            return render_template('edit_expense.html', form=form)

        expense.category = form.category.data
        expense.amount = form.amount.data
        expense.description = form.description.data
        try:
            db.session.commit()
            flash('Expense updated successfully!')
        except:
            db.session.rollback()
            flash('Error updating expense. Please try again later.')
        return redirect(url_for('view_expenses'))

    return render_template('edit_expense.html', form=form)


# Route for deleting expense

@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash('You do not have permission to delete this entry.')
        return redirect(url_for('view_expenses'))

    try:
        db.session.delete(expense)
        db.session.commit()
        flash('Expense entry deleted successfully!')
    except:
        db.session.rollback()
        flash('Error deleting expense. Please try again later.')
    return redirect(url_for('view_expenses'))


# Route for viewing expense list

@app.route('/view_expenses')
@login_required
def view_expenses():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('view_expenses.html', expenses=expenses)


# ------------------------------------------DASH----------------------------------------------------------

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
