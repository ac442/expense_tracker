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
import matplotlib.pyplot as plt # for plotting graphs
import pandas as pd # for data manipulation
from io import BytesIO # for saving plots as bytes
from flask import send_file # for sending bytes to the browser

# Create a new Flask web server instance
app = Flask(__name__)

# Configure database settings for the Flask application
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
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

#---------------------------------------------HELPER FUNCTIONS---------------------------------------------------------

def generate_spending_chart(data):
    plt.figure(figsize=(10, 6))
    plt.pie(data.values(), labels=data.keys(), autopct='%1.1f%%')
    plt.title("Spending by Category")
    buf = BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    return buf

def generate_spending_over_time(data):
    # Assuming data is a sorted dict or an OrderedDict with date as key and spending as value
    plt.figure(figsize=(12, 7))
    plt.plot(data.keys(), data.values())
    plt.title("Spending over Time")
    buf = BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    return buf

def export_to_excel(data):
    # Convert data to DataFrame
    df = pd.DataFrame(data)
    buf = BytesIO()
    df.to_excel(buf, index=False)
    buf.seek(0)
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

# REGISTRATION ROUTE
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


# LOGIN ROUTE
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    try:
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('index'))
            flash('Invalid username or password')
    except Exception as e:
        flash('Error during login. Please try again.')
    return render_template('auth/login.html', form=form)


# LOGOUT ROUTE
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


# ------------------------------------------INCOME-ROUTES----------------------------------------------------------

# ROUTE FOR ADDING INCOME

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


# ROUTE FOR EDITING INCOME

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


# ROUTE FOR DELETING INCOME
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


# ROUTE FOR VIEWING INCOME

@app.route('/view_incomes')
@login_required
def view_incomes():
    incomes = Income.query.filter_by(user_id=current_user.id).all()
    return render_template('view_incomes.html', incomes=incomes)


# ------------------------------------------EXPENSE-ROUTES----------------------------------------------------------

# ROUTE FOR ADDING EXPENSE

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    form = ExpenseForm()
    if form.validate_on_submit():
        if form.amount.data <= 0:
            flash('Please enter a positive amount for the expense.')
            return render_template('add_expense.html', form=form)

        expense = Expense(source=form.source.data, amount=form.amount.data, description=form.description.data,
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


# ROUTE FOR EDITING EXPENSE

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

        expense.source = form.source.data
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


# ROUTE FOR DELETING EXPENSE

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


# ROUTE FOR VIEWING EXPENSES

@app.route('/view_expenses')
@login_required
def view_expenses():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('view_expenses.html', expenses=expenses)


# ------------------------------------------BUDGET-ROUTES----------------------------------------------------------
# ROUTE FOR SETTING BUDGET

@app.route('/set_budget', methods=['GET', 'POST'])
@login_required
def set_budget():
    form = BudgetForm()
    existing_budget = Budget.query.filter_by(user_id=current_user.id).first()
    if form.validate_on_submit():
        if form.amount.data <= 0:
            flash('Please enter a positive value for the budget.')
            return render_template('set_budget.html', form=form)

        if existing_budget:
            existing_budget.amount = form.amount.data
        else:
            new_budget = Budget(amount=form.amount.data, user_id=current_user.id)
            db.session.add(new_budget)
        try:
            db.session.commit()
            flash('Budget set successfully!')
        except:
            db.session.rollback()
            flash('Error setting budget. Please try again later.')
        return redirect(url_for('index'))

    return render_template('set_budget.html', form=form)


# ROUTE TO VIEW CURRENT BUDGET

@app.route('/view_budget')
@login_required
def view_budget():
    budget = Budget.query.filter_by(user_id=current_user.id).first()
    return render_template('view_budget.html', budget=budget)



# ------------------------------------------REPORTS-ROUTES----------------------------------------------------------

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
    # For demonstration, assuming you'd fetch and process data into a dictionary.
    # In practice, you'd need to query and process data from your database.
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
    return send_file(excel_file, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", as_attachment=True, attachment_filename="report.xlsx")



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
