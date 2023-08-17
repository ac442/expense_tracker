# ----- IMPORTS SECTION -----
# Required packages and libraries to run the Flask application, handle database operations, manage authentication, and deal with forms.
from datetime import datetime, timedelta
import logging
from faker import Faker
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np  # for linear regression
import os
import pandas as pd
import traceback
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import FloatField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from io import BytesIO
import unittest
from math import sqrt

# Create a new Flask web server instance
app = Flask(__name__)

# Configure database settings for the Flask application
# Determine the path to the current file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Construct the database path using the BASE_DIR
DATABASE_PATH = os.path.join(BASE_DIR, 'your_database_name.db')


app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random value for production
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
db = SQLAlchemy(app)

# Initialize CSRF protection
# csrf = CSRFProtect(app)

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your mail server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'a.c.hudson442@gmail.com'
app.config['MAIL_PASSWORD'] = 'chqcgtynbabeppqm'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)
mail.init_app(app)

# Create a new SQLAlchemy database instance

migrate = Migrate(app, db)



PREDEFINED_CATEGORIES = {
    'expense': ["Housing & Utilities", "Food & Dining", "Transportation",
                "Personal Care & Lifestyle", "Savings", "Investments",
                "Personal Debt", "Taxes", "Family & Relationships",
                "Education & Professional Services", "Miscellaneous"]


}

# Setup and initialize Flask-Login's login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.unauthorized_handler
def unauthorized():
    flash('You need to login first.')
    return redirect(url_for('login'))


# -----------------------------------DATA MODELS SECTION----------------------------------------------------------------

# User model definition
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    # Define relationship to the Expense model
    expenses = db.relationship('Expense', back_populates='user', lazy=True)

    # Define a one-to-one relationship to the Budget model
    budget = db.relationship('Budget', back_populates='user', uselist=False, lazy=True)

    # In the User model, this line establishes a one-to-many relationship with the Notification model.
    # This means one user can have multiple notifications.
    notifications = db.relationship('Notification', back_populates='user', lazy=True)

    def set_password(self, password):
        # Hash and set the password for the user
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Check the password against its hash
        return check_password_hash(self.password_hash, password)


# Expense model definition
class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    source = db.Column(db.String(80), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.String(200))

    # Define relationship to the User model
    user = db.relationship('User', back_populates='expenses')


class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    category = db.Column(db.String(80), nullable=False)  # New field for category
    amount = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', back_populates='budget')


# Notification model definition
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(200))
    date_created = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    user = db.relationship('User', back_populates='notifications', lazy=True)


@app.cli.command("initdb")
def initdb_command():
    """Initialize the database."""
    db.create_all()
    print("Database initialized.")

#---------------------------------------------FORMS SECTION------------------------------------------------------------
# User registration form definition
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


# User login form definition
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Form to record expenses
class ExpenseForm(FlaskForm):
    source = SelectField('Category', choices=PREDEFINED_CATEGORIES['expense'],
                         validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[Length(max=300)])  # Optional, so no DataRequired()
    amount = FloatField('Amount', validators=[DataRequired()])
    submit = SubmitField('Submit')


# Form to set budget

class BudgetForm(FlaskForm):
    category = SelectField('Category', choices=PREDEFINED_CATEGORIES['expense'], validators=[DataRequired()])
    amount = FloatField('Budget Amount', validators=[DataRequired()])
    submit = SubmitField('Set Budget')


# ============================================BASIC UTILITY FUNCTIONS===================================================
####
def get_monthly_expenses(user_id):
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year

    monthly_expenses = Expense.query.filter_by(user_id=user_id).filter(
        db.extract('month', Expense.date) == current_month,
        db.extract('year', Expense.date) == current_year
    ).all()

    return sum(expense.amount for expense in monthly_expenses)


def collect_expense_data(expenses):
    """
    This function collects and returns the sum of expenses by category.

    Parameters:
    - expenses: A list of expense objects.
                Each expense object is expected to have 'source' and 'amount' attributes.
    """

    # Create an empty dictionary to store the sum of expenses by category.
    category_data = {}

    # Loop through each expense in the provided list.
    for expense in expenses:

        # If the source (or category) of the expense is already in the dictionary,
        # add the amount of the current expense to its existing value.
        if expense.source in category_data:
            category_data[expense.source] += expense.amount

        # If the source (or category) of the expense is not in the dictionary,
        # create a new entry with the source as the key and the expense amount as the value.
        else:
            category_data[expense.source] = expense.amount

    # Return the dictionary with summed expenses by category.
    return category_data

#==================================================DATA PROCESSING AND ANALYALYSIS FUNCTIONS===============================================

def get_spending_trends(user_id):
    """Get spending trends for the current month compared to the previous month."""
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year

    # Calculate the previous month and year
    if current_month == 1:
        previous_month = 12
        previous_year = current_year - 1
    else:
        previous_month = current_month - 1
        previous_year = current_year

    # Fetch expenses for the current and previous month
    current_month_expenses = Expense.query.filter_by(user_id=user_id).filter(
        db.extract('month', Expense.date) == current_month,
        db.extract('year', Expense.date) == current_year
    ).all()

    previous_month_expenses = Expense.query.filter_by(user_id=user_id).filter(
        db.extract('month', Expense.date) == previous_month,
        db.extract('year', Expense.date) == previous_year
    ).all()

    trends = {}
    for category in PREDEFINED_CATEGORIES['expense']:
        current_spending = sum(exp.amount for exp in current_month_expenses if exp.source == category)
        previous_spending = sum(exp.amount for exp in previous_month_expenses if exp.source == category)

        if previous_spending != 0:
            percent_change = ((current_spending - previous_spending) / previous_spending) * 100
            trends[category] = percent_change

    return trends


def get_spending_anomalies(user_id):
    """Get anomalies in the current month's spending compared to the average spending."""
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year

    # Fetch expenses for the current month
    current_month_expenses = Expense.query.filter_by(user_id=user_id).filter(
        db.extract('month', Expense.date) == current_month,
        db.extract('year', Expense.date) == current_year
    ).all()

    # Calculate average spending for each category in previous months
    previous_expenses = Expense.query.filter_by(user_id=user_id).filter(
        or_(db.extract('month', Expense.date) != current_month,
            db.extract('year', Expense.date) != current_year)
    ).all()

    average_expenses = {}
    for category in PREDEFINED_CATEGORIES['expense']:
        total_spending = sum(exp.amount for exp in previous_expenses if exp.source == category)
        count = len([exp for exp in previous_expenses if exp.source == category])
        average = total_spending / count if count != 0 else 0
        average_expenses[category] = average

    anomalies = {}
    for category in PREDEFINED_CATEGORIES['expense']:
        current_spending = sum(exp.amount for exp in current_month_expenses if exp.source == category)

        if average_expenses[category] != 0 and current_spending > 1.2 * average_expenses[
            category]:  # 20% more than average
            anomalies[category] = current_spending

    return anomalies

#==============================================VISUALIZATION AND EXPORT FUNCTIONS=========================================================

# Function to generate a pie chart visualizing spending by category.
def generate_spending_chart(data):
    # Set the figure size for the chart.
    plt.figure(figsize=(10, 6))

    # Generate a pie chart using the provided data.
    # data.keys() provides the categories and data.values() provides the spending amounts for each category.
    # autopct='%1.1f%%' displays the percentage representation of each category on the chart.
    plt.pie(data.values(), labels=data.keys(), autopct='%1.1f%%')

    # Set the title for the chart.
    plt.title("Spending by Category")

    # Create a buffer to store the image data.
    buf = BytesIO()

    # Save the pie chart as a PNG image in the buffer.
    plt.savefig(buf, format="png")

    # Reset the buffer's position to the beginning.
    buf.seek(0)

    # Return the buffer containing the PNG image data.
    return buf


# Function to generate a line graph visualizing spending over time.
def generate_spending_over_time(data):
    # Assuming data is a sorted dict or an OrderedDict with date as key and spending as value
    # Set the figure size for the graph.
    plt.figure(figsize=(12, 7))

    # If data.keys() are already datetime objects, no need to parse
    dates = list(data.keys())

    # Generate a line graph using the provided data.
    plt.plot(dates, list(data.values()))

    # Set the title for the graph.
    plt.title("Spending over Time")

    # Create a buffer to store the image data.
    buf = BytesIO()

    # Save the line graph as a PNG image in the buffer.
    plt.savefig(buf, format="png")

    # Reset the buffer's position to the beginning.
    buf.seek(0)

    # Return the buffer containing the PNG image data.
    return buf


def export_to_excel(data):
    """Convert the data dictionary into an Excel file and return it."""
    df = pd.DataFrame(data)

    # Save DataFrame to an in-memory Excel file.
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name="Expenses", index=False)

    output.seek(0)
    return output




# ----------------------------------------HELPER FUNCTIONS FOR NOTIFICATIONS AND ALERTS------------------------------------------------------------

def check_budget():
    users = User.query.all()
    for user in users:
        for category in PREDEFINED_CATEGORIES['expense']:
            total_expense_for_category = sum(exp.amount for exp in user.expenses if exp.source == category)
            budget_for_category = Budget.query.filter_by(user_id=user.id, category=category).first()
            if budget_for_category and total_expense_for_category >= budget_for_category.amount:
                notify_user(user, f"Your spending in {category} has reached or exceeded your set budget.")


def check_large_expense():
    LARGE_EXPENSE_THRESHOLD = 1000  # or any other threshold
    users = User.query.all()
    for user in users:
        for expense in user.expenses:
            if expense.amount >= LARGE_EXPENSE_THRESHOLD:
                notify_user(user, f"You have a large expense of {expense.amount} for {expense.source}.")


def check_recurring_expenses():
    # Get the current month and year to check for recurring expenses within this month.
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year

    # Fetch all users from the database.
    users = User.query.all()

    for user in users:
        # Fetch expenses for the user in the current month.
        monthly_expenses = Expense.query.filter_by(user_id=user.id).filter(
            db.extract('month', Expense.date) == current_month,
            db.extract('year', Expense.date) == current_year
        ).all()

        # Check if the same source (or category) of expense appears more than once in the month.
        source_counts = {}
        for expense in monthly_expenses:
            if expense.source in source_counts:
                source_counts[expense.source] += 1
            else:
                source_counts[expense.source] = 1

        # Notify the user for sources of expenses that appear more than once.
        for source, count in source_counts.items():
            if count > 1:
                notify_user(user, f"Reminder: You have multiple expenses for '{source}' this month.")


def check_alerts():
    check_budget()
    check_large_expense()
    check_recurring_expenses()
    flash('Checked for alerts and notifications.')
    return redirect(url_for('view_notifications'))


def notify_user(user, message, via_email=False):
    notification = Notification(message=message, user_id=user.id)
    db.session.add(notification)
    db.session.commit()

    # If notifications should be sent via email
    if via_email:
        send_email_notification(user.email, "Finance App Alert", message)


def send_email_notification(to, subject, body):
    msg = Message(subject, recipients=[to])
    msg.body = body
    mail.send(msg)


# -------------------------------------------USER AUTHENTICATION ROUTES-----------------------------------------------
# Define the routes for user authentication (registration, login, logout).

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# This route is for user registration. It handles both GET (for displaying the registration form)
# and POST (for processing the form data) requests.
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Create an instance of the RegistrationForm.
    form = RegistrationForm()

    # Check if the form is submitted and validates without errors.
    if form.validate_on_submit():
        # Retrieve data from the form.
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Create a new User instance with the retrieved data.
        user = User(username=username, email=email)
        # Set the hashed password for the user.
        user.set_password(password)

        # Try to save the new user to the database.
        try:
            db.session.add(user)
            db.session.commit()
            # Log the user in immediately after successful registration.
            login_user(user)
            # Display a success message to the user.
            flash('Thanks for registering!')
            # Redirect the user to the main index page after successful registration.
            return redirect(url_for('dashboard'))
        except:
            # If there's an error during the registration process, rollback any database changes.
            db.session.rollback()
            # Display an error message to the user.
            flash('Error! Unable to register at the moment.')

    # If it's a GET request or the form data is invalid, display the registration form.
    return render_template('auth/register.html', form=form)


# LOGIN ROUTE

# This route is for user login. It handles both GET (for displaying the login form)
# and POST (for processing the form data) requests.
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Create an instance of the LoginForm.
    form = LoginForm()

    # Use a try-except block to handle potential errors during the login process.
    try:
        # Check if the form is submitted and validates without errors.
        if form.validate_on_submit():
            # Retrieve the username and password from the form.
            username = form.username.data
            password = form.password.data
            # Query the database for a user with the provided username.
            user = User.query.filter_by(username=username).first()

            # Check if the user exists and if the provided password is correct.
            if user and user.check_password(password):
                # Log the user in.
                login_user(user)
                # Redirect the user to the main index page after successful login.
                return redirect(url_for('dashboard'))

            # Display an error message if the login credentials are incorrect.
            flash('Invalid username or password')
    except Exception as e:
        # Display a general error message in case of any unexpected issues during login.
        flash('Error during login. Please try again.')

    # If it's a GET request or the form data is invalid, display the login form.
    return render_template('auth/login.html', form=form)


# This route is for logging out the currently logged-in user.

@app.route('/logout')
# Ensure that only logged-in users can access this route.
@login_required
def logout():
    # Log out the user.
    logout_user()
    # Display a message to the user confirming they have been logged out.
    flash('You have been logged out.')
    # Redirect the user to the login page after logging out.
    return redirect(url_for('login'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


# ------------------------------------------EXPENSE-ROUTES----------------------------------------------------------

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    # Create an instance of the ExpenseForm.
    form = ExpenseForm()

    # Check if the form is submitted and validates without errors.
    if form.validate_on_submit():
        # Ensure the expense amount entered is positive.
        if form.amount.data <= 0:
            flash('Please enter a positive amount for the expense.')
            return render_template('add_expense.html', form=form)

        # Create a new expense object with the form data.
        expense = Expense(source=form.source.data, amount=form.amount.data, description=form.description.data,
                          user_id=current_user.id)

        # Try to save the new expense entry to the database.
        try:
            db.session.add(expense)
            db.session.commit()
            flash('Expense added successfully!')

            # Call check_budget after successfully adding the expense
            check_budget()

            return redirect(url_for('view_expenses'))

        except:
            # If there's an error during the process, rollback any database changes.
            db.session.rollback()
            flash('Error adding expense. Please try again later.')

    # If it's a GET request or the form data is invalid, display the expense form.
    return render_template('add_expense.html', form=form)


# ROUTE FOR EDITING EXPENSE

# This route allows users to edit an existing expense entry based on its unique ID.
@app.route('/edit_expenses/<int:expense_id>', methods=['GET', 'POST'])
# Ensure that only logged-in users can access this route.
@login_required
def edit_expense(expense_id):
    # Fetch the specific expense entry from the database based on its ID.
    # If not found, return a 404 error.
    expense = Expense.query.get_or_404(expense_id)

    # Check if the current user is the owner of the expense entry.
    if expense.user_id != current_user.id:
        flash('You do not have permission to edit this entry.')
        return redirect(url_for('view_expenses'))

    # Create an instance of the ExpenseForm and populate it with the data from the fetched expense entry.
    form = ExpenseForm(obj=expense)

    # Check if the form is submitted and validates without errors.
    if form.validate_on_submit():
        # Ensure the expense amount entered is positive.
        if form.amount.data <= 0:
            flash('Please enter a positive amount for the expense.')
            return render_template('edit_expenses.html', form=form)

        # Update the expense entry with the new data from the form.
        expense.source = form.source.data
        expense.amount = form.amount.data
        expense.description = form.description.data

        # Try to save the updated expense entry to the database.
        try:
            db.session.commit()
            flash('Expense updated successfully!')
        except:
            # If there's an error during the process, rollback any database changes.
            db.session.rollback()
            flash('Error updating expense. Please try again later.')

        # Redirect the user to the expense list page after successfully updating the expense.
        return redirect(url_for('view_expenses'))

    # If it's a GET request or the form data is invalid, display the expense editing form.
    return render_template('edit_expenses.html', form=form)


# This route allows users to delete an existing expense entry based on its unique ID.
# It only handles POST requests as it's a destructive action.
@app.route('/delete_expense/<int:expense_id>', methods=['POST', 'GET'])
# Ensure that only logged-in users can access this route.
@login_required
def delete_expense(expense_id):
    # Fetch the specific expense entry from the database based on its ID.
    # If not found, return a 404 error.
    expense = Expense.query.get_or_404(expense_id)

    # Check if the current user is the owner of the expense entry.
    if expense.user_id != current_user.id:
        flash('You do not have permission to delete this entry.')
        return redirect(url_for('view_expenses'))

    # Try to delete the expense entry from the database.
    try:
        db.session.delete(expense)
        db.session.commit()
        flash('Expense entry deleted successfully!')
    except:
        # If there's an error during the process, rollback any database changes.
        db.session.rollback()
        flash('Error deleting expense. Please try again later.')

    # Redirect the user to the expense list page after the deletion attempt.
    return redirect(url_for('view_expenses'))


# ROUTE FOR VIEWING EXPENSES

# This route allows users to view a list of all their expense entries.
@app.route('/view_expenses')
# Ensure that only logged-in users can access this route.
@login_required
def view_expenses():
    # Fetch all expense entries for the currently logged-in user from the database.
    expenses = Expense.query.filter_by(user_id=current_user.id).all()

    # Render a template to display the list of expense entries.
    return render_template('view_expenses.html', expenses=expenses)


# ------------------------------------------BUDGET-ROUTES----------------------------------------------------------
# ROUTE FOR SETTING BUDGET

@app.route('/set_budget', methods=['GET', 'POST'])
@login_required
def set_budget():
    form = BudgetForm()
    if form.validate_on_submit():
        # Check if a budget for this category already exists
        existing_budget = Budget.query.filter_by(user_id=current_user.id, category=form.category.data).first()
        if existing_budget:
            existing_budget.amount = form.amount.data
        else:
            budget = Budget(category=form.category.data, amount=form.amount.data, user_id=current_user.id)
            db.session.add(budget)
        db.session.commit()
        flash('Your budget has been set!')
        return redirect(url_for('view_budget'))
    return render_template('set_budget.html', title='Set Budget', form=form)


# ROUTE TO VIEW CURRENT BUDGET

# This route is designed to allow users to view their current budget.

# Ensure that only logged-in users can access this route.
@app.route('/view_budget')
@login_required
def view_budget():
    budgets = Budget.query.filter_by(user_id=current_user.id).all()
    return render_template('view_budget.html', budgets=budgets)



# ------------------------------------------REPORT-ROUTES----------------------------------------------------------

# ROUTE FOR GENERATING REPORTS



@app.route('/reports/spending')
# @login_required
def spending_report():
    try:
        # 1. Data Collection
        expenses = Expense.query.filter_by(user_id=current_user.id).all()
        category_data = collect_expense_data(expenses)

        # If no expenses found, render a message to the user
        if not category_data:
            return render_template('no_expenses.html')  # This assumes you have a template to display a message

        # 2. Generate the Chart
        chart_path = generate_spending_chart(category_data)

        if not chart_path:
            logging.error("Chart generation failed.")
            return "Chart generation failed.", 500

        # 3. Send the generated chart as an image to the client.
        return send_file(chart_path, mimetype="image/png")

    except Exception as e:
        logging.error(f"Error in spending_report route: {e}")
        return str(e), 500


@app.route('/reports/spending_over_time')
@login_required
def spending_over_time_report():
    """Display a line graph of spending over time."""

    # Query the database for expenses over time for the logged-in user.
    expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.asc()).all()

    # Process the expenses into a dictionary where keys are dates and values are cumulative expenses.
    data = {}
    total = 0
    for expense in expenses:
        total += expense.amount
        data[expense.date] = total

    chart = generate_spending_over_time(data)  # Generate the chart using the helper function.

    # Send the generated chart as an image to the client.
    return send_file(chart, mimetype="image/png")



@app.route('/spending-trends')
@login_required
def view_spending_trends():
    trends = get_spending_trends(current_user.id)

    trend_messages = []
    for category, percent_change in trends.items():
        if percent_change > 0:
            trend_messages.append(f"Your spending on {category} has increased by {percent_change:.2f}% this month.")
        else:
            trend_messages.append(f"Your spending on {category} has decreased by {-percent_change:.2f}% this month.")

    return render_template('spending_trends.html', trend_messages=trend_messages)

@app.route('/view_spending_anomalies')
@login_required
def view_spending_anomalies():
    anomalies = get_spending_anomalies(current_user.id)
    return render_template('spending_anomalies.html', anomalies=anomalies)


@app.route('/reports/export')
@login_required
def export_report():
    """Export user's financial data to an Excel file."""

    # Fetch user's expenses from the database.
    expenses = Expense.query.filter_by(user_id=current_user.id).all()

    # Populate the data dictionary with actual data from the database.
    data = {
        "Description": [expense.description for expense in expenses],  # List comprehension
        "Amount": [expense.amount for expense in expenses],
        "Date": [expense.date for expense in expenses],
        "Expense Category": [expense.source for expense in expenses],
    }

    # Generate the Excel file in-memory.
    excel_file = export_to_excel(data)

    # Send the Excel file to the client as a download.
    return send_file(excel_file, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     as_attachment=True, download_name="report.xlsx")

# ------------------------------------------NOTIFICATIONS ROUTES----------------------------------------------------------

@app.route('/notifications/mark_all_as_read', methods=['POST'])
@login_required
def mark_all_as_read():
    # Fetch all unread notifications for the currently logged-in user and mark them as read.
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    for notification in notifications:
        notification.is_read = True
    db.session.commit()
    flash('All notifications marked as read.')
    return redirect(url_for('view_notifications'))


@app.route('/send_email')
def send_email():
    msg = Message("Test Subject", sender="a.c.hudson442@gmail.com", recipients=["monika.szymanczak@live.co.uk"])
    msg.body = "This is a test email sent from Flask app using Flask-Mail and Gmail."
    mail.send(msg)
    return "Email sent!"


# ------------------------------------------MAIN INDEX ROUTE----------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    current_month_expenses = get_monthly_expenses(current_user.id)
    budget = Budget.query.filter_by(user_id=current_user.id).first()

    if budget:
        budget_amount = budget.amount
        budget_progress = (current_month_expenses / budget_amount) * 100
    else:
        budget_amount = 0
        budget_progress = 0

    # Call the helper functions
    trends = get_spending_trends(current_user.id)
    anomalies = get_spending_anomalies(current_user.id)

    # Process the trends to create user-friendly messages
    trend_messages = []
    for category, percent_change in trends.items():
        if percent_change > 0:
            trend_messages.append(f"Your spending on {category} has increased by {percent_change:.2f}% this month.")
        else:
            trend_messages.append(f"Your spending on {category} has decreased by {-percent_change:.2f}% this month.")

    # Process anomalies to create user-friendly messages
    anomaly_messages = []
    for category, amount in anomalies.items():
        anomaly_messages.append(f"You spent {amount} on {category} this month, which is higher than your average.")

    return render_template('dashboard.html',
                           current_month_expenses=current_month_expenses,
                           budget_amount=budget_amount,
                           budget_progress=budget_progress,
                           trend_messages=trend_messages,
                           anomaly_messages=anomaly_messages)



# -------------------------------------------MAIN METHOD---------------------------------------------------------------
if __name__ == '__main__':
    # If the environment is set to 'development', run the app with debugging enabled.
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True)
    # If the environment is not 'development', run the app normally.
    else:
        app.run()
