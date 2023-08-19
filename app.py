import logging
import os
import re
from datetime import datetime
from io import BytesIO
import matplotlib.pyplot as plt
import pandas as pd
from flask import Flask, flash, redirect, render_template, send_file, url_for, request
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import FloatField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE_PATH = os.path.join(BASE_DIR, 'your_database_name.db')

app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random value for production
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['WTF_CSRF_ENABLED'] = False

db = SQLAlchemy(app)
flask_migrate = Migrate(app, db)

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

PREDEFINED_CATEGORIES = {
    'expense': ["Housing & Utilities", "Food & Dining", "Transport",
                "Personal Care & Lifestyle", "Savings", "Investments",
                "Personal Debt", "Taxes", "Family & Relationships",
                "Education & Professional Services", "Miscellaneous"]
}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ============================================BASIC UTILITY FUNCTIONS===================================================

@app.cli.command("initdb")
def initdb_command():
    db.create_all()
    print("Database reset and initialized.")


@login_manager.unauthorized_handler
def unauthorized():
    flash('You need to login first.')
    return redirect(url_for('login'))


@app.context_processor
def inject_notifications_count():
    if current_user.is_authenticated:
        unread_notifications_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return {'unread_notifications_count': unread_notifications_count}
    return {}


@app.template_filter('to_snake_case')
def to_snake_case(string):
    return string.lower().replace(' & ', '_and_').replace(' ', '_')


def get_previous_and_current_month_names():
    current_month_num = datetime.utcnow().month
    current_year = datetime.utcnow().year

    if current_month_num == 1:
        previous_month_num = 12
        previous_year = current_year - 1
    else:
        previous_month_num = current_month_num - 1
        previous_year = current_year

    month_names = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
                   "November", "December"]
    current_month_name = month_names[current_month_num - 1]
    previous_month_name = month_names[previous_month_num - 1]

    return previous_month_name, previous_year, current_month_name, current_year


# -----------------------------------DATA MODELS SECTION----------------------------------------------------------------


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    firstname = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    expenses = db.relationship('Expense', back_populates='user', lazy=True)
    budgets = db.relationship('Budget', back_populates='user', lazy=True)
    notifications = db.relationship('Notification', back_populates='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_budget_for_category(self, category):
        return Budget.query.filter_by(user_id=self.id, category=category).first()


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(80), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.String(200))
    user = db.relationship('User', back_populates='expenses')

    @classmethod
    def compute_spending_trends(cls, user_id):
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
        current_month_expenses = cls.query.filter_by(user_id=user_id).filter(
            db.extract('month', cls.date) == current_month,
            db.extract('year', cls.date) == current_year
        ).all()

        previous_month_expenses = cls.query.filter_by(user_id=user_id).filter(
            db.extract('month', cls.date) == previous_month,
            db.extract('year', cls.date) == previous_year
        ).all()

        trends = {}
        for category in PREDEFINED_CATEGORIES['expense']:
            current_spending = sum(exp.amount for exp in current_month_expenses if exp.category == category)
            previous_spending = sum(exp.amount for exp in previous_month_expenses if exp.category == category)

            if previous_spending != 0:
                percent_change = ((current_spending - previous_spending) / previous_spending) * 100
                trends[category] = percent_change

        return trends


class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(80), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', back_populates='budgets')  # Assuming you have a 'User' model

    # This constraint ensures that the combination of user_id and category is unique
    __table_args__ = (db.UniqueConstraint('user_id', 'category', name='unique_category_per_user'),)

    @classmethod
    def get_budget_for_category(cls, user_id, category):
        return cls.query.filter_by(user_id=user_id, category=category).first()


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(200))
    date_created = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    user = db.relationship('User', back_populates='notifications', lazy=True)


def check_budget():
    users = User.query.all()
    for user in users:
        for category in PREDEFINED_CATEGORIES['expense']:
            total_expense_for_category = sum(exp.amount for exp in user.expenses if exp.category == category)
            budget_for_category = Budget.query.filter_by(user_id=user.id, category=category).first()
            if budget_for_category and total_expense_for_category >= budget_for_category.amount:
                notify_user(user, f"Your spending in {category} has reached or exceeded your set budget.")


def check_large_expense():
    LARGE_EXPENSE_THRESHOLD = 1000  # or any other threshold
    users = User.query.all()
    for user in users:
        for expense in user.expenses:
            if expense.amount >= LARGE_EXPENSE_THRESHOLD:
                notify_user(user, f"You have a large expense of {expense.amount} for {expense.category}.")


def check_recurring_expenses():
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year
    users = User.query.all()

    for user in users:
        monthly_expenses = Expense.query.filter_by(user_id=user.id).filter(
            db.extract('month', Expense.date) == current_month,
            db.extract('year', Expense.date) == current_year
        ).all()
        source_counts = {}
        for expense in monthly_expenses:
            if expense.category in source_counts:
                source_counts[expense.category] += 1
            else:
                source_counts[expense.category] = 1
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
    if via_email:
        send_email_notification(user.email, "Finance App Alert", message)


def send_email_notification(to, subject, body):
    msg = Message(subject, recipients=[to])
    msg.body = body
    mail.send(msg)


# ---------------------------------------------FORMS SECTION------------------------------------------------------------


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already in use. Please choose a different one or log in.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

    class Meta:
        csrf = False  # This is the default behavior, so you can omit it if you want CSRF protection.
        # Add other Meta attributes as needed.


class EditProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[Length(max=50)])
    last_name = StringField('Last Name', validators=[Length(max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Profile')

    class Meta:
        csrf = False

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is already in use. Please choose a different one or log in.')


class ExpenseForm(FlaskForm):
    source = SelectField('Category', choices=PREDEFINED_CATEGORIES['expense'],
                         validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[Length(max=300)])  # Optional, so no DataRequired()
    amount = FloatField('Amount', validators=[DataRequired()])
    submit = SubmitField('Submit')


class MainBudgetForm(FlaskForm):
    main_budget = FloatField('Main Budget Amount', validators=[DataRequired()])
    submit = SubmitField('Set Main Budget')


def create_category_budget_form(categories):
    class DynamicCategoryBudgetForm(FlaskForm):
        submit = SubmitField('Set Category Budgets')

    for category in categories:
        field_name = to_snake_case(category)
        setattr(DynamicCategoryBudgetForm, field_name, FloatField(category))

    return DynamicCategoryBudgetForm()


# ==============================================VISUALIZATION AND EXPORT FUNCTIONS=========================================================

# Function to generate a pie chart visualizing spending by category.
def generate_spending_chart(data):
    # Set the figure size for the chart.
    plt.figure(figsize=(10, 6))
    plt.pie(data.values(), labels=data.keys(), autopct='%1.1f%%')
    plt.title("Spending by Category")
    buf = BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    return buf


def generate_spending_over_time(data):
    plt.figure(figsize=(12, 7))
    dates = list(data.keys())
    plt.plot(dates, list(data.values()))
    plt.title("Spending over Time")
    buf = BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    return buf


def export_to_excel(data):
    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name="Expenses", index=False)
    output.seek(0)
    return output


# -------------------------------------------USER AUTHENTICATION ROUTES-----------------------------------------------
# Define the routes for user authentication (registration, login, logout).


# Assuming the User model and other necessary configurations have been defined above...

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match!')
            return render_template('register.html')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!')
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password_hash=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!')
        return redirect(url_for('login'))  # Assuming you have a 'login' route

    return render_template('register.html')


if __name__ == '__main__':
    db.create_all()  # Create database tables
    app.run(debug=True)


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

                return redirect(url_for('dashboard'))

            flash('Invalid username or password')
    except Exception as e:

        flash('Error during login. Please try again.')

    # If it's a GET request or the form data is invalid, display the login form.
    return render_template('login.html', form=form), 401


@app.route('/logout')
# Ensure that only logged-in users can access this route.
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/edit_profile_details', methods=['GET', 'POST'])
@login_required
def edit_profile_details():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.email.data = current_user.email
    return render_template('edit_profile_details.html', form=form), 401


# ------------------------------------------EXPENSE-ROUTES----------------------------------------------------------

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    form = ExpenseForm()
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
        expense.category = form.source.data
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
    main_budget_form = MainBudgetForm()
    category_budget_form = create_category_budget_form(PREDEFINED_CATEGORIES['expense'])

    if main_budget_form.validate_on_submit() and 'main_budget' in request.form:
        # Handle the main budget logic here. Assuming category "Main" represents the main budget.
        existing_main_budget = Budget.get_budget_for_category(current_user.id, "Main")
        if existing_main_budget:
            existing_main_budget.amount = main_budget_form.main_budget.data
        else:
            main_budget = Budget(category="Main", amount=main_budget_form.main_budget.data, user_id=current_user.id)
            db.session.add(main_budget)
        db.session.commit()
        flash('Your main budget has been set!')
        return redirect(url_for('view_budget'))

    if category_budget_form.validate_on_submit():
        # Loop over each category in the form
        for category, field in category_budget_form._fields.items():
            if category != 'submit' and field.data:  # Only process categories that have data
                existing_budget = Budget.get_budget_for_category(current_user.id, category)
                if existing_budget:
                    existing_budget.amount = field.data
                else:
                    budget = Budget(category=category, amount=field.data, user_id=current_user.id)
                    db.session.add(budget)
        db.session.commit()
        flash('Your category budgets have been set!')
        return redirect(url_for('view_budget'))

    # Default return statement to render the set_budget template
    return render_template('set_budget.html', title='Set Budget', main_budget_form=main_budget_form,
                           category_budget_form=category_budget_form, PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES)


# ROUTE TO VIEW CURRENT BUDGET

# This route is designed to allow users to view their current budget.

# Ensure that only logged-in users can access this route.
@app.route('/view_budgets')
@login_required
def view_budgets():
    user_id = current_user.id

    # Fetch the main budget
    main_budget = Budget.get_budget_for_category(user_id, "Main")

    # Fetch category budgets
    category_budgets = Budget.query.filter_by(user_id=user_id).filter(Budget.category != "Main").all()

    return render_template('view_budgets.html', main_budget=main_budget, category_budgets=category_budgets)


# ------------------------------------------REPORT-ROUTES----------------------------------------------------------

# ROUTE FOR GENERATING REPORTS


@app.route('/reports/spending_report')
# @login_required
def spending_report():
    try:
        # 1. Data Collection
        expenses = Expense.query.filter_by(user_id=current_user.id).all()
        category_data = Expense.collect_expense_data(expenses)

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


@app.route('/reports/view_spending_trends')
def view_spending_trends():
    user_id = current_user.id

    previous_month_name, previous_year, current_month_name, current_year = get_previous_and_current_month_names()

    trends = Expense.compute_spending_trends(user_id)
    trend_messages = [
        f"For {category} from {previous_month_name} {previous_year} to {current_month_name} {current_year}, the change in spending is {trends[category]:.2f}%"
        for category, value in trends.items()
    ]

    return render_template('view_spending_trends.html', trend_messages=trend_messages,
                           PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES)


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
        "Expense Category": [expense.category for expense in expenses],
    }

    # Generate the Excel file in-memory.
    excel_file = export_to_excel(data)

    # Send the Excel file to the client as a download.
    return send_file(excel_file, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     as_attachment=True, download_name="report.xlsx")


# ------------------------------------------NOTIFICATIONS ROUTES----------------------------------------------------------

@app.route('/notifications')
@login_required
def view_notifications():
    user_id = current_user.id
    notifications = Notification.query.filter_by(user_id=user_id, is_read=False).all()
    return render_template('notifications.html', notifications=notifications)


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
    user_id = current_user.id

    previous_month_name, previous_year, current_month_name, current_year = get_previous_and_current_month_names()

    trends = Expense.compute_spending_trends(user_id)
    trend_messages = [
        f"For {category} from {previous_month_name} {previous_year} to {current_month_name} {current_year}, the change in spending is {trends[category]:.2f}%"
        for category, value in trends.items()
    ]

    return render_template('dashboard.html', trend_messages=trend_messages, PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES)


# =================================TESTING ROUTES=============================================


# -------------------------------------------MAIN METHOD---------------------------------------------------------------
if __name__ == '__main__':
    # If the environment is set to 'development', run the app with debugging enabled.
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True)
    # If the environment is not 'development', run the app normally.
    else:
        app.run()
