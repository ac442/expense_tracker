# ----- IMPORTS SECTION -----
# Required packages and libraries to run the Flask application, handle database operations, manage authentication, and deal with forms.
from datetime import datetime
from flask import Flask, flash, redirect, render_template, send_file, url_for, jsonify
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from io import BytesIO
import matplotlib.pyplot as plt
import numpy as np
from prophet import Prophet
import os
import pandas as pd
from sklearn.linear_model import LinearRegression
import unittest
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import FloatField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import matplotlib.dates as mdates
import logging

# Create a new Flask web server instance
app = Flask(__name__)

# Configure database settings for the Flask application
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'your_database.db')
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random value for production

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
db = SQLAlchemy(app)
migrate = Migrate(app, db)

PREDEFINED_CATEGORIES = {
    'expense': ["Housing", "Transportation", "Food", "Personal Care & Health", "Entertainment & Leisure",
                "Financial & Insurance", "Education", "Clothing & Accessories", "Kids & Family", "Pets",
                "Gifts/Donations", "Memberships/Subscriptions", "Professional Services", "Travel/Vacations",
                "Utilities & Bills", "Groceries", "Dining Out", "Personal Debt", "Investments", "Savings", "Taxes",
                "Miscellaneous Expenses"]
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


# Budget model definition
class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)  # unique=True ensures one-to-one
    amount = db.Column(db.Integer, nullable=False)  # consider using db.Numeric if decimal values are needed

    # Define relationship back to the User model
    user = db.relationship('User', back_populates='budget')


# Notification model definition
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(200))
    date_created = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    user = db.relationship('User', back_populates='notifications', lazy=True)


# -----------------------------------------HELPER FUNCTIONS -------------------------------------------------------------


# ----------------------------------------HELPER FUNCTIONS FOR REPORTS AND ANALYTICS----------------------------------


def collect_expense_data(expenses):
    """Collect and return the sum of expenses by category."""
    category_data = {}  # This will store sum of expenses by category.
    for expense in expenses:
        if expense.source in category_data:
            category_data[expense.source] += expense.amount
        else:
            category_data[expense.source] = expense.amount
    return category_data


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


def predict_future_expenses(days=30):
    # Fetch the expenses data
    expenses = Expense.query.filter_by(user_id=current_user.id).all()

    # Prepare the data for Prophet
    df = pd.DataFrame({
        'ds': [expense.date for expense in expenses],
        'y': [expense.amount for expense in expenses]
    })

    # Instantiate and fit the Prophet model
    model = Prophet()
    model.fit(df)

    # Create a dataframe for future dates
    future = model.make_future_dataframe(periods=days)

    # Make predictions
    forecast = model.predict(future)

    return forecast


# ----------------------------------------HELPER FUNCTIONS FOR NOTIFICATIONS AND ALERTS---------------------------------------------

def check_budget():
    users = User.query.all()
    for user in users:
        if user.budget and sum(exp.amount for exp in user.expenses) >= user.budget.amount:
            notify_user(user, "Your spending has reached your set budget.")


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


# ---------------------------------------------FORMS SECTION------------------------------------------------------------

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
    amount = FloatField('Budget Amount', validators=[DataRequired()])
    submit = SubmitField('Set Budget')


# ----------------------------------------- USER AUTHENTICATION METHODS ------------------------------------------------
# Define how Flask-Login retrieves a specific user object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------------------------ROUTES SECTION----------------------------------------------------------
# Define the application routes which determine the functionality available at each URL.


# -------------------------------------------USER AUTHENTICATION ROUTES-----------------------------------------------
# Define the routes for user authentication (registration, login, logout).

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
            return redirect(url_for('index'))
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
                return redirect(url_for('index'))

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


# -------------------------------------------ACCOUNT MANAGEMENT ROUTES---------------------------------------------------

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
    print("Debug: Inside the /set_budget route")  # Debug line
    form = BudgetForm()

    if form.validate_on_submit():
        budget = Budget.query.filter_by(user_id=current_user.id).first()

        if budget:
            budget.amount = form.amount.data
        else:
            budget = Budget(amount=form.amount.data, user_id=current_user.id)
            db.session.add(budget)

        db.session.commit()
        check_budget = Budget.query.filter_by(user_id=current_user.id).first()  # Debug line
        print(f"Debug: Check budget for user {current_user.id} after commit is: {check_budget}")  # Debug line
        print(f"Debug: Set budget for user {current_user.id} to: {budget.amount}")  # Debug line
        flash('Your budget has been set!', 'success')
        return redirect(url_for('view_budget'))

    else:
        print(f"Debug: Form did not validate. Errors: {form.errors}")  # Debug line

    return render_template('set_budget.html', title='Set Budget', form=form)


# ROUTE TO VIEW CURRENT BUDGET

# This route is designed to allow users to view their current budget.

# Ensure that only logged-in users can access this route.
@app.route('/view_budget')
@login_required
def view_budget():
    budget = Budget.query.filter_by(user_id=current_user.id).first()
    print(f"Debug: Fetched budget for user {current_user.id} is: {budget}")  # Debug line
    return render_template('view_budget.html', budget=budget)


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


@app.route('/reports/export')
@login_required
def export_report():
    """Export user's financial data to an Excel file."""

    # Fetch user's expenses from the database.
    expenses = Expense.query.filter_by(user_id=current_user.id).all()

    # Populate the data dictionary with actual data from the database.
    data = {
        "Date": [expense.date for expense in expenses],
        "Expense Category": [expense.source for expense in expenses],
        "Amount": [expense.amount for expense in expenses]
    }

    # Generate the Excel file in-memory.
    excel_file = export_to_excel(data)

    # Send the Excel file to the client as a download.
    return send_file(excel_file, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     as_attachment=True, download_name="report.xlsx")


@app.route('/predict_expenses', methods=['GET', 'POST'])
@login_required
def predict_expenses():
    # 1. Data Collection
    expenses = Expense.query.filter_by(user_id=current_user.id).all()

    # 2. Data Preparation
    dates = [expense.date for expense in expenses]
    amounts = [expense.amount for expense in expenses]

    # 3. Model Selection & 4. Model Training
    X = np.array([d.toordinal() for d in dates]).reshape(-1, 1)
    y = np.array(amounts)
    model = LinearRegression().fit(X, y)

    # 5. Prediction
    future_date = datetime.date.today() + datetime.timedelta(days=30)  # Predict for 30 days from today
    predicted_expense = model.predict(np.array([[future_date.toordinal()]]))[0]

    # Optionally: Visualization (You might use libraries like Matplotlib or Plotly for this)

    # Display the prediction to the user
    return render_template('prediction.html', prediction=predicted_expense)


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


# Main dashboard route
@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html')


# -------------------------------------------MAIN METHOD---------------------------------------------------------------
if __name__ == '__main__':
    # If the environment is set to 'development', run the app with debugging enabled.
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True)
    # If the environment is not 'development', run the app normally.
    else:
        app.run()
