# ----- IMPORTS SECTION -----
# Required packages and libraries to run the Flask application, handle database operations, manage authentication, and deal with forms.
import os
from flask_migrate import Migrate
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, login_user, UserMixin, logout_user, current_user
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, SubmitField, PasswordField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
import matplotlib.pyplot as plt  # for plotting graphs
import pandas as pd  # for data manipulation
from io import BytesIO  # for saving plots as bytes
from flask import send_file  # for sending bytes to the browser

# Create a new Flask web server instance
app = Flask(__name__)

# Configure database settings for the Flask application
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'your_database.db')
app.config['SECRET_KEY'] = 'your_secret_key'  # Remember to replace this with a real secret key!

# Create a new SQLAlchemy database instance
db = SQLAlchemy(app)
migrate = Migrate(app, db)

PREDEFINED_CATEGORIES = {
    'income': ["Salary/Wages", "Bonuses", "Business Income", "Rental Income", "Investment Income", "Interest Income",
               "Royalties", "Pension", "Social Security", "Alimony/Child Support Received", "Freelance Income",
               "Gifts Received", "Tax Refund", "Sale of Assets", "Lottery/Gambling Winnings", "Miscellaneous Income"],
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


# -----------------------------------DATABASE MODELS SECTION------------------------------------------------------------

# User model definition
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    # Define a one-to-many relationship to the Income model
    incomes = db.relationship('Income', back_populates='user', lazy=True)

    # Define relationship to the Expense model
    expenses = db.relationship('Expense', back_populates='user', lazy=True)

    # Define a one-to-one relationship to the Budget model
    budget = db.relationship('Budget', back_populates='user', uselist=False, lazy=True)

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
    description = db.Column(db.String(200))

    # Define relationship to the User model
    user = db.relationship('User', back_populates='incomes')


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


# ---------------------------------------------HELPER FUNCTIONS---------------------------------------------------------

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
    # Generate a line graph using the provided data.
    # data.keys() provides the dates and data.values() provides the spending amounts for each date.
    plt.plot(data.keys(), data.values())
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

# Function to export provided data to an Excel file.
def export_to_excel(data):
    # Convert the provided data to a DataFrame using the pandas library.
    df = pd.DataFrame(data)

    # Create a buffer to store the Excel file data.
    buf = BytesIO()

    # Write the DataFrame to the buffer as an Excel file.
    # index=False means the DataFrame's index will not be written to the Excel file.
    df.to_excel(buf, index=False)

    # Reset the buffer's position to the beginning.
    buf.seek(0)

    # Return the buffer containing the Excel file data.
    return buf


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


# Form to record income
class IncomeForm(FlaskForm):
    source = SelectField('Source', choices=PREDEFINED_CATEGORIES['income'],
                         validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[Length(max=300)])  # Optional, so no DataRequired()
    amount = FloatField('Amount', validators=[DataRequired()])
    submit = SubmitField('Submit')


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


# ------------------------------------------INCOME-ROUTES----------------------------------------------------------
# ROUTE FOR ADDING INCOME

# Define a route to handle the addition of income. This route responds to both GET and POST requests.
@app.route('/add_income', methods=['GET', 'POST'])
# Ensure that only logged-in users can access this route.
@login_required
def add_income():
    # Create an instance of the IncomeForm.
    form = IncomeForm()

    # Check if the form is submitted and validates without errors.
    if form.validate_on_submit():

        # Check if the submitted income amount is non-positive.
        if form.amount.data <= 0:
            # Display an error message to the user.
            flash('Please enter a positive amount for income.')
            # Render the form again to allow user correction.
            return render_template('add_income.html', form=form)

        # Create an Income object using the data from the form.
        income = Income(source=form.source.data, amount=form.amount.data, user_id=current_user.id)

        try:
            # Try to add the income record to the database.
            db.session.add(income)
            db.session.commit()
            # Display a success message to the user.
            flash('Income added successfully!')
        except Exception as e:
            # If there's an error during database operation, rollback any changes.
            db.session.rollback()
            # Display an error message to the user.
            flash('Error adding income. Please try again later.', 'error')

        # Redirect the user to the list of incomes after successfully adding a new income.
        return redirect(url_for('view_incomes'))

    # If it's a GET request or the form data is invalid, render the income addition form.
    return render_template('add_income.html', form=form)


# ROUTE FOR EDITING INCOME

# Define a route to handle the editing of an existing income. The route requires an income ID as a parameter.
@app.route('/edit_income/<int:income_id>', methods=['GET', 'POST'])
# Ensure that only logged-in users can access this route.
@login_required
def edit_income(income_id):
    # Fetch the income record from the database using its ID. If it doesn't exist, return a 404 error.
    income = Income.query.get_or_404(income_id)

    # Check if the current user is not the owner of the income record.
    if income.user_id != current_user.id:
        # Display an error message to the user.
        flash('You do not have permission to edit this entry.')
        # Redirect the user to the list of incomes.
        return redirect(url_for('view_incomes'))

    # Create an instance of the IncomeForm and populate it with the data from the fetched income record.
    form = IncomeForm(obj=income)

    # Check if the form is submitted and validates without errors.
    if form.validate_on_submit():
        # Check if the submitted income amount is non-positive.
        if form.amount.data <= 0:
            # Display an error message to the user.
            flash('Please enter a positive amount for income.')
            # Render the form again to allow user correction.
            return render_template('edit_income.html', form=form)

        # Update the income record with the new data from the form.
        income.source = form.source.data
        income.amount = form.amount.data

        try:
            # Try to save the updated income record to the database.
            db.session.commit()
            # Display a success message to the user.
            flash('Income updated successfully!')
        except Exception as e:
            # If there's an error during database operation, rollback any changes.
            db.session.rollback()
            # Display an error message to the user.
            flash('Error updating income. Please try again later.')

        # Redirect the user to the list of incomes after successfully updating the income.
        return redirect(url_for('view_incomes'))

    # If it's a GET request or the form data is invalid, render the income editing form.
    return render_template('edit_income.html', form=form)


# ROUTE FOR DELETING INCOME

# Define a route to handle the deletion of an income. This route responds to POST requests and requires an income ID.
@app.route('/delete_income/<int:income_id>', methods=['POST'])
# Ensure that only logged-in users can access this route.
@login_required
def delete_income(income_id):
    # Fetch the income record from the database using its ID. If it doesn't exist, return a 404 error.
    income = Income.query.get_or_404(income_id)

    # Check if the current user is not the owner of the income record.
    if income.user_id != current_user.id:
        # Display an error message to the user.
        flash('You do not have permission to delete this entry.')
        # Redirect the user to the list of incomes.
        return redirect(url_for('view_incomes'))

    try:
        # Try to delete the income record from the database.
        db.session.delete(income)
        db.session.commit()
        # Display a success message to the user.
        flash('Income entry deleted successfully!')
    except Exception as e:
        # If there's an error during database operation, rollback any changes.
        db.session.rollback()
        # Display an error message to the user.
        flash('Error deleting income. Please try again later.')

    # Redirect the user to the list of incomes after attempting to delete an income.
    return redirect(url_for('view_incomes'))


# Define a route to display a list of incomes for the logged-in user.
@app.route('/view_incomes')
# Ensure that only logged-in users can access this route.
@login_required
def view_incomes():
    # Fetch all income records for the logged-in user from the database.
    incomes = Income.query.filter_by(user_id=current_user.id).all()
    # Render a template that displays the list of incomes.
    return render_template('view_incomes.html', incomes=incomes)


# ------------------------------------------EXPENSE-ROUTES----------------------------------------------------------

# ROUTE FOR ADDING EXPENSE

# This route allows users to add a new expense entry.
# It handles both GET (for displaying the expense form) and POST (for processing the form data) requests.
@app.route('/add_expense', methods=['GET', 'POST'])
# Ensure that only logged-in users can access this route.
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
        except:
            # If there's an error during the process, rollback any database changes.
            db.session.rollback()
            flash('Error adding expense. Please try again later.')

        # Redirect the user to the expense list page after successfully adding the expense.
        return redirect(url_for('view_expenses'))

    # If it's a GET request or the form data is invalid, display the expense form.
    return render_template('add_expense.html', form=form)


# ROUTE FOR EDITING EXPENSE

# This route allows users to edit an existing expense entry based on its unique ID.
@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
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
            return render_template('edit_expense.html', form=form)

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
    return render_template('edit_expense.html', form=form)


# ROUTE FOR DELETING EXPENSE

# This route allows users to delete an existing expense entry based on its unique ID.
# It only handles POST requests as it's a destructive action.
@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
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

# This route is designed to allow users to set or update their budget. It handles both GET (for displaying the budget form)
# and POST (for processing the form data) requests.
@app.route('/set_budget', methods=['GET', 'POST'])
# Ensure that only logged-in users can access this route.
@login_required
def set_budget():
    # Create an instance of the BudgetForm.
    form = BudgetForm()

    # Query the database to check if the currently logged-in user already has a set budget.
    existing_budget = Budget.query.filter_by(user_id=current_user.id).first()

    # Check if the form is submitted and validates without errors.
    if form.validate_on_submit():
        # Ensure the budget amount entered is positive.
        if form.amount.data <= 0:
            flash('Please enter a positive value for the budget.')
            return render_template('set_budget.html', form=form)

        # If an existing budget is found for the user, update its amount.
        if existing_budget:
            existing_budget.amount = form.amount.data
        # If no existing budget is found, create a new budget entry for the user.
        else:
            new_budget = Budget(amount=form.amount.data, user_id=current_user.id)
            db.session.add(new_budget)

        # Try to save the changes (either updating the existing budget or adding a new one) to the database.
        try:
            db.session.commit()
            flash('Budget set successfully!')
        except:
            # If there's an error during the process, rollback any database changes.
            db.session.rollback()
            flash('Error setting budget. Please try again later.')

        # Redirect the user to the main index page after successfully setting the budget.
        return redirect(url_for('index'))

    # If it's a GET request or the form data is invalid, display the budget form.
    return render_template('set_budget.html', form=form)


# ROUTE TO VIEW CURRENT BUDGET

# This route is designed to allow users to view their current budget.
@app.route('/view_budget')
# Ensure that only logged-in users can access this route.
@login_required
def view_budget():
    # Query the database to retrieve the currently logged-in user's budget.
    budget = Budget.query.filter_by(user_id=current_user.id).first()

    # Render the template to display the user's budget.
    return render_template('view_budget.html', budget=budget)


# ------------------------------------------REPORT-ROUTES----------------------------------------------------------

# ROUTE FOR GENERATING REPORTS
@app.route('/reports/spending')
@login_required
def spending_report():
    """Display a pie chart of spending by category."""
    # Query the database to get spending data by category for the logged-in user.
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    category_data = {}  # This will store sum of expenses by category.
    for expense in expenses:
        if expense.source in category_data:
            category_data[expense.source] += expense.amount
        else:
            category_data[expense.source] = expense.amount

    chart = generate_spending_chart(category_data)  # Generate the chart using the helper function.
    # Send the generated chart as an image to the client.
    return send_file(chart, mimetype="image/png")


@app.route('/reports/spending_over_time')
@login_required
def spending_over_time_report():
    """Display a line graph of spending over time."""
    # DEMO fetch and process data into a dictionary.
    # TODO query  you'd need to query and process data from your database.
    data = {}
    chart = generate_spending_over_time(data)  # Generate the chart using the helper function.
    # Send the generated chart as an image to the client.
    return send_file(chart, mimetype="image/png")


@app.route('/reports/export')
@login_required
def export_report():
    """Export user's financial data to an Excel file."""
    # Fetch and process data for the logged-in user.
    data = {"Date": [], "Expense Category": [], "Amount": []}
    # Populate the data dictionary with actual data.
    # For demonstration, it's left empty. You'd need to query and fill this from your database.
    excel_file = export_to_excel(data)  # Export the data to Excel using the helper function.
    # Send the Excel file to the client as a download.
    return send_file(excel_file, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     as_attachment=True, attachment_filename="report.xlsx")


# ------------------------------------------MAIN INDEX ROUTE----------------------------------------------------------


# Main dashboard route
@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html')


# -------------------------------------------MAIN METHOD---------------------------------------------------------------

# Check if the script is executed as the main program and run the Flask app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True)
    else:
        app.run()
