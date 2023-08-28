import logging
import os
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from datetime import datetime
from io import BytesIO
from collections import defaultdict
import pandas as pd
from flask import Flask, abort, send_file, jsonify
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import FloatField, PasswordField, SelectField, StringField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import matplotlib.pyplot as plt
import io
from wtforms.validators import Optional
from base64 import b64encode
import base64
from dateutil.relativedelta import relativedelta
from collections import Counter
from flask import flash, redirect, render_template, request, url_for
import numpy as np
from datetime import datetime, timedelta


app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s - %(message)s')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'your_database_name.db')
app.config['SECRET_KEY'] = 'randomString323'  # Change this to a random value for production
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['WTF_CSRF_ENABLED'] = False
app.config["jwt"] = JWTManager(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)
flask_migrate = Migrate(app, db)
PREDEFINED_CATEGORIES = {'expense': ["Housing & Utilities", "Food & Dining", "Transport",
                "Personal Care & Lifestyle", "Savings", "Investments",
                "Personal Debt", "Taxes", "Family & Relationships",
                "Education & Professional Services", "Miscellaneous"]}
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# ============================================HELPER FUNCTIONS===================================================
@app.cli.command("initdb")
def initdb_command():
    db.create_all()
    print("Database reset and initialized.")
@login_manager.unauthorized_handler
def unauthorized():
    flash('You need to login first.')
    return redirect(url_for('login'))
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
@app.context_processor
def inject_notifications_count():
    if current_user.is_authenticated:
        unread_notifications_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return {'unread_notifications_count': unread_notifications_count}
    return {}
@app.context_processor
def inject_predefined_categories():
    return dict(PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES)
@app.template_filter('to_snake_case')
def to_snake_case(string):
    return string.lower().replace(' & ', '_and_').replace(' ', '_')

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

def notify_user(user, message):
    notification = Notification(message=message, user_id=user.id)
    db.session.add(notification)
    db.session.commit()
def get_previous_and_current_month_names():
    current_date = datetime.utcnow()
    previous_date = current_date - relativedelta(months=1)
    month_names = ["January", "February", "March", "April", "May", "June",
                   "July", "August", "September", "October", "November", "December"]
    current_month_name = month_names[current_date.month - 1]
    previous_month_name = month_names[previous_date.month - 1]
    return previous_month_name, previous_date.year, current_month_name, current_date.year

def add_and_commit(db_object):
    try:
        db.session.add(db_object)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f"An error occurred while committing to the database: {e}")

def get_current_month_and_year():
    current_datetime = datetime.utcnow()
    return current_datetime.month, current_datetime.year

def get_monthly_expenses(year, month):
    return Expense.query.filter_by(user_id=current_user.id)\
            .filter(db.extract('year', Expense.date) == year, db.extract('month', Expense.date) == month)\
            .all()

def get_budget_for_month(user, category):
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year
    existing_budget = Budget.query.filter_by(
        user_id=user.id,
        category=category,
        month=current_month,
        year=current_year
    ).first()
    return existing_budget.budget_amount if existing_budget else 0
def get_budget_vs_actual(user_id, month, year):
    categories = PREDEFINED_CATEGORIES['expense']
    budget_vs_actual = {}
    for category in categories:
        budget_amount = get_budget_for_month(current_user, category)
        expenses = Expense.query.filter_by(user_id=user_id, category=category).filter(
            db.extract('month', Expense.date) == month,
            db.extract('year', Expense.date) == year).all()
        actual_expense = sum(expense.amount for expense in expenses)
        budget_vs_actual[category] = {"budget": budget_amount, "actual": actual_expense}
    return budget_vs_actual
def generate_budget_vs_actual_chart(data):
    categories = list(data.keys())
    budget_values = [entry["budget"] for entry in data.values()]
    actual_values = [entry["actual"] for entry in data.values()]
    width = 0.35  # the width of the bars
    fig, ax = plt.subplots(figsize=(12, 7))
    ind = np.arange(len(categories))  # the label locations
    p1 = ax.bar(ind - width / 2, budget_values, width, label='Budget', color='blue')
    p2 = ax.bar(ind + width / 2, actual_values, width, label='Actual', color='orange')
    ax.set_title('Budget vs Actual Expenses by Category')
    ax.set_xticks(ind)
    ax.set_xticklabels(categories, rotation=45)
    ax.legend()
    for bar in p1:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, yval + 5, round(yval, 2), ha='center', va='bottom', color='black',
                size=8)
    for bar in p2:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, yval + 5, round(yval, 2), ha='center', va='bottom', color='black',
                size=8)
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png')
    buf.seek(0)
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"
def set_category_budget_for_month(user, category, amount):
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year
    existing_budget = Budget.query.filter_by(
        user_id=user.id,
        category=category,
        month=current_month,
        year=current_year
    ).first()
    if existing_budget:
        existing_budget.budget_amount = amount
    else:
        budget_entry = Budget(
            user_id=user.id, category=category,
            budget_amount=amount
        )
        db.session.add(budget_entry)
def get_cumulative_spending_over_time(user_id):
    expenses = Expense.query.filter_by(user_id=user_id).order_by(Expense.date.asc()).all()
    data = {}
    total = 0
    for expense in expenses:
        total += expense.amount
        data[expense.date] = total
    return data
def generate_spending_chart(data):
    plt.figure(figsize=(10, 6))
    plt.pie(data.values(), labels=data.keys(), autopct='%1.1f%%')
    plt.title("Spending by Category")
    buf = BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    return buf
def calculate_amount_spent(user_id, category):
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year
    expenses = Expense.query.filter_by(user_id=user_id, category=category).filter(
        db.extract('month', Expense.date) == current_month,
        db.extract('year', Expense.date) == current_year).all()
    return sum(expense.amount for expense in expenses)

def generate_report_image(img_generator_func, data):
    try:
        img = img_generator_func(data)
        img_str = b64encode(img.getvalue()).decode('utf-8')
        return img_str, True
    except Exception as e:
        logging.error(f"Error generating report image: {e}")
        return None, False
def check_budget_limit(user_id, category, amount_spent):
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year

    budget = Budget.query.filter_by(
        user_id=user_id,
        category=category,
        month=current_month,
        year=current_year
    ).first()

    if budget:
        budget_amount = budget.budget_amount
        if amount_spent >= 0.75 * budget_amount:
            notification = Notification(
                message=f"You have reached 75% of your budget in the {category} category.",
                user_id=user_id
            )
            db.session.add(notification)
            db.session.commit()
def get_expense_frequency(user_id):
    expenses = Expense.query.filter_by(user_id=user_id).all()
    categories = [expense.category for expense in expenses]
    frequency = Counter(categories)
    return frequency
def get_most_frequent_categories(user_id):
    frequency = get_expense_frequency(user_id)
    sorted_categories = sorted(frequency.items(), key=lambda x: x[1], reverse=True)
    return sorted_categories
def identify_savings_opportunities(user_id):
    budget = {}
    actual_spending = {}
    three_months_ago = datetime.utcnow() - relativedelta(months=3)
    three_months_ago_month = three_months_ago.month
    three_months_ago_year = three_months_ago.year
    budgets = Budget.query.filter_by(user_id=user_id).filter((Budget.month >= three_months_ago_month) & (Budget.year >= three_months_ago_year)).all()
    for b in budgets:
        budget[b.category] = budget.get(b.category, 0) + b.budget_amount
    expenses = Expense.query.filter_by(user_id=user_id).filter(Expense.date >= three_months_ago).all()
    for e in expenses:
        actual_spending[e.category] = actual_spending.get(e.category, 0) + e.amount
    savings_opportunities = {}
    for category, budget_amount in budget.items():
        actual_amount = actual_spending.get(category, 0)
        if actual_amount < budget_amount:
            savings_opportunities[category] = budget_amount - actual_amount
    return savings_opportunities
def send_budget_reminders():
    next_month = datetime.utcnow().month + 1
    next_year = datetime.utcnow().year
    if next_month == 13:
        next_month = 1
        next_year += 1
    users = User.query.all()
    for user in users:
        budget_exists = Budget.query.filter_by(
            user_id=user.id,
            month=next_month,
            year=next_year).first()
        if not budget_exists:
            notification = Notification(message="Please set a budget for the upcoming month.", user_id=user.id)
            db.session.add(notification)
    db.session.commit()
def generate_line_graph(data, title='Spending Over Time'):
    dates = list(data.keys())
    amounts = list(data.values())
    plt.figure(figsize=(10, 6))
    plt.plot(dates, amounts, marker='o')
    plt.title(title)
    plt.xlabel('Date')
    plt.ylabel('Total Amount')
    plt.grid(True)
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    return buf
def generate_trend_graph(trends, title="Spending Trends"):
    categories = list(trends.keys())
    values = list(trends.values())
    colors = ['green' if val >= 0 else 'red' for val in values]
    plt.figure(figsize=(12, 7))
    bars = plt.bar(categories, values, color=colors)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval,
                 round(yval, 2),
                 ha='center',
                 va='bottom' if yval < 0 else 'top',
                 color='black')
    plt.title(title)
    plt.xlabel("Categories")
    plt.ylabel("Percentage Change")
    plt.xticks(rotation=45)
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png')
    buf.seek(0)
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"
def export_to_excel(data):
    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name="Expenses", index=False)
    output.seek(0)
    return output
# ===================================================FORMS SECTION======================================================
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user: raise ValidationError('That username is already taken. Please choose a different one.')
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
class EditProfileForm(FlaskForm):
    firstname = StringField('First Name', validators=[Length(max=50)])
    lastname = StringField('Last Name', validators=[Length(max=50)])
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
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password',                                                                                   message='Passwords must match.')])
    submit = SubmitField('Change Password')


PREDEFINED_CATEGORIES = {
    'expense': ["Housing & Utilities", "Food & Dining", "Transport",
                "Personal Care & Lifestyle", "Savings", "Investments",
                "Personal Debt", "Taxes", "Family & Relationships",
                "Education & Professional Services", "Miscellaneous"]
}

class ExpenseForm(FlaskForm):
    category = SelectField('Category', choices=[(cat, cat) for cat in PREDEFINED_CATEGORIES['expense']],
                           validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[Optional(), Length(max=300)])
    amount = FloatField('Amount', validators=[DataRequired()])
    is_recurring = BooleanField('Is this a recurring expense?')  # New field for recurring
    recurring_frequency = SelectField('Recurring Frequency', choices=[('', '--Select Frequency--'), ('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly')])  # New field for frequency
    submit = SubmitField('Submit')

class CategoryBudgetForm(FlaskForm):
    for category in PREDEFINED_CATEGORIES['expense']:
        locals()[to_snake_case(category)] = FloatField(category, validators=[Optional()])
    submit = SubmitField('Set Category Budgets')

# -----------------------------------DATA MODELS SECTION----------------------------------------------------------------
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(200))
    date_created = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    user = db.relationship('User', back_populates='notifications', lazy=True)
    @classmethod
    def has_unread_notifications(user_id):
        count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
        return count > 0

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(80), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.String(200))
    is_recurring = db.Column(db.Boolean, default=False)  # New field
    recurring_frequency = db.Column(db.String(50))  # New field (e.g., 'Weekly', 'Monthly')
    user = db.relationship('User', back_populates='expenses')

    # Your existing Classmethods and other functionalities
    # ...

    @classmethod
    def compute_monthly_spending_trends(cls, user_id):
        current_month = datetime.utcnow().month
        current_year = datetime.utcnow().year
        if current_month == 1:
            previous_month = 12
            previous_year = current_year - 1
        else:
            previous_month = current_month - 1
            previous_year = current_year
        current_month_expenses = cls.query.filter_by(user_id=user_id).filter(
            db.extract('month', cls.date) == current_month,
            db.extract('year', cls.date) == current_year).all()
        previous_month_expenses = cls.query.filter_by(user_id=user_id).filter(
            db.extract('month', cls.date) == previous_month,
            db.extract('year', cls.date) == previous_year).all()
        trends = {}
        for category in PREDEFINED_CATEGORIES['expense']:
            current_spending = sum(exp.amount for exp in current_month_expenses if exp.category == category)
            previous_spending = sum(exp.amount for exp in previous_month_expenses if exp.category == category)
            if previous_spending != 0:
                percent_change = ((current_spending - previous_spending) / previous_spending) * 100
                trends[category] = percent_change
        return trends
    @classmethod
    def compute_yearly_spending_trends(cls, user_id):
        current_year = datetime.utcnow().year
        previous_year = current_year - 1
        current_year_expenses = cls.query.filter_by(user_id=user_id).filter(
            db.extract('year', cls.date) == current_year).all()
        previous_year_expenses = cls.query.filter_by(user_id=user_id).filter(
            db.extract('year', cls.date) == previous_year).all()
        trends = {}
        for category in PREDEFINED_CATEGORIES['expense']:
            current_spending = sum(exp.amount for exp in current_year_expenses if exp.category == category)
            previous_spending = sum(exp.amount for exp in previous_year_expenses if exp.category == category)
            if previous_spending != 0:
                percent_change = ((current_spending - previous_spending) / previous_spending) * 100
                trends[category] = percent_change
        return trends
    @classmethod
    def collect_expense_data(cls, expenses):
        data = defaultdict(float)  # Default value of 0.0 for each category
        for expense in expenses:
            data[expense.category] += expense.amount
        return dict(data)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    firstname = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    main_budget = db.Column(db.Float)  # New field for the overall budget
    expenses = db.relationship('Expense', back_populates='user', lazy=True)
    budgets = db.relationship('Budget', back_populates='user', lazy=True)
    notifications = db.relationship('Notification', back_populates='user', lazy=True)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    @staticmethod
    def check_large_expense_for_user(user):
        LARGE_EXPENSE_THRESHOLD = 1000  # or any other threshold
        for expense in user.expenses:
            if expense.amount >= LARGE_EXPENSE_THRESHOLD:  # Replaced expense.budget_amount with expense.amount
                notify_user(user, f"You have a large expense of {expense.amount} for {expense.category}.")
    @staticmethod
    def check_recurring_expenses_for_user(user):
        current_month = datetime.utcnow().month
        current_year = datetime.utcnow().year
        monthly_expenses = Expense.query.filter_by(user_id=user.id).filter(
            db.extract('month', Expense.date) == current_month,
            db.extract('year', Expense.date) == current_year).all()
        category_counts = {}
        for expense in monthly_expenses:
            if expense.category in category_counts:
                category_counts[expense.category] += 1
            else:
                category_counts[expense.category] = 1
        for category, count in category_counts.items():
            if count > 1:
                notify_user(user, f"Reminder: You have multiple expenses for '{category}' this month.")
    @classmethod
    def check_all_alerts_for_user(cls, user):
        cls.check_budget_for_user(user)
        cls.check_large_expense_for_user(user)
        cls.check_recurring_expenses_for_user(user)
class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(80), nullable=False)  # Specific category like "Housing", "Food", etc.
    budget_amount = db.Column(db.Float, nullable=True)  # Budget amount for that category
    month = db.Column(db.Integer, nullable=False, default=datetime.utcnow().month)
    year = db.Column(db.Integer, nullable=False, default=datetime.utcnow().year)
    user = db.relationship('User', back_populates='budgets')
    __table_args__ = (db.UniqueConstraint('user_id', 'category', name='unique_category_per_user'),)
    @classmethod
    def get_budget_for_category(cls, user_id, category):
        budget = cls.query.filter_by(user_id=user_id, category=category).first()
        print(f"Budget for user_id {user_id} and category {category}: {budget}")
        return budget




# ===============================================ROUTES SECTION=========================================================
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/user/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match!')
            return render_template('register.html'), 400  # Bad Request

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!')
            return render_template('register.html'), 409  # Conflict

        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!')
        return redirect(url_for('login')), 201  # Created
    return render_template('register.html', form=form), 200  # OK


from flask import Flask, jsonify, redirect, url_for, flash, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity


# Initialize Flask app and Flask-JWT-Extended
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this!
jwt = JWTManager(app)


@app.route('/user/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    try:
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            # Assuming User is your user model and you have a method to query by username
            user = User.query.filter_by(username=username).first()

            # Assuming you have a method to check password in the User model
            if user and user.check_password(password):

                # Create the token
                access_token = create_access_token(identity=username)

                # You can store the token in the client side, either as a cookie or in local storage
                response = jsonify({'login': True, 'token': access_token})
                return response, 200  # OK
            else:
                flash('Invalid username or password')
                return render_template('login.html', form=form)
    except Exception as e:
        logging.error(f"Error during login: {e}")
        flash('Error during login. Please try again.')
    return render_template('login.html', form=form)


@app.route('/user/logout', methods=['GET'])
@login_required  # This decorator is optional depending on your use case
def logout():
    # With JWT, there's no server-side way to invalidate the token
    # Inform the client to remove the token on their side
    return jsonify({'logout': True, 'message': 'You have been logged out.'}), 200  # OK


@app.route('/user/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login')), 200  # OK
@app.route('/user/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user), 200  # OK

@app.route('/user/edit_profile_details', methods=['GET', 'POST'])
@login_required
def edit_profile_details():
    form = EditProfileForm()
    try:
        if form.validate_on_submit():
            current_user.firstname = form.firstname.data
            current_user.lastname = form.lastname.data
            current_user.email = form.email.data
            db.session.commit()
            flash('Your profile has been updated!', 'success')
            return redirect(url_for('dashboard')), 200  # OK
        elif request.method == 'GET':
            form.firstname.data = current_user.firstname
            form.lastname.data = current_user.lastname
            form.email.data = current_user.email
    except Exception as e:
        logging.error(f"Error during profile update: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return render_template('edit_profile_details.html', form=form), 500  # Internal Server Error
    return render_template('edit_profile_details.html', form=form), 200  # OK

@app.route('/user/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    try:
        if form.validate_on_submit():
            if not check_password_hash(current_user.password, form.current_password.data):  # Updated this line
                flash('Incorrect old password.', 'danger')
                return redirect(url_for('change_password')), 401  # Unauthorized
            current_user.password = generate_password_hash(form.new_password.data, method='sha256')
            db.session.commit()
            flash('Your password has been changed successfully!', 'success')
            return redirect(url_for('dashboard')), 200  # OK
    except Exception as e:
        logging.error(f"Error during password change: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return render_template('change_password.html', form=form), 500  # Internal Server Error
    return render_template('change_password.html', form=form), 200  # OK


# ------------------------------------------EXPENSE-ROUTES----------------------------------------------------------
@app.route('/expenses/add', methods=['GET', 'POST'])
@login_required  # Moved the decorator here to ensure the user is logged in before adding an expense
def add_expense():
    form = ExpenseForm()
    try:
        if form.validate_on_submit():
            expense = Expense(
                category=form.category.data,
                amount=form.amount.data,
                description=form.description.data or None,
                user_id=current_user.id,
                is_recurring=form.is_recurring.data,  # New field
                recurring_frequency=form.recurring_frequency.data if form.is_recurring.data else None  # New field
            )
            db.session.add(expense)
            db.session.commit()
            # Additional logic like amount_spent and check_budget_limit are assumed to be defined elsewhere
            flash('Expense added successfully!', 'success')
            return redirect(url_for('view_expenses')), 201  # Created
    except Exception as e:
        logging.error(f"Error adding expense: {e}")
        db.session.rollback()  # Roll back the session in case of an error
        flash('An error occurred while adding the expense. Please try again.', 'danger')
        return render_template('add_expense.html', form=form), 500  # Internal Server Error
    return render_template('add_expense.html', form=form), 200  # OK

from flask import request  # make sure to import request

@app.route('/expenses/view-all', methods=['GET'])
@login_required
def view_expenses():
    is_recurring_filter = request.args.get('is_recurring', None, type=bool)

    if is_recurring_filter is not None:
        expenses = Expense.query.filter_by(user_id=current_user.id, is_recurring=is_recurring_filter).all()
    else:
        expenses = Expense.query.filter_by(user_id=current_user.id).all()

    return render_template('view_expenses.html', expenses=expenses), 200  # OK

@app.route('/expenses/update-expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash('You do not have permission to edit this entry.', 'danger')
        return redirect(url_for('view_expenses')), 403  # Forbidden
    form = ExpenseForm(obj=expense)
    try:
        if form.validate_on_submit():
            expense.category = form.category.data
            expense.amount = form.amount.data  # Fixed from 'budget_amount' to 'amount'
            expense.description = form.description.data
            db.session.commit()
            flash('Expense updated successfully!', 'success')
            return redirect(url_for('view_expenses')), 200  # OK
    except Exception as e:
        logging.error(f"Error updating expense: {e}")
        db.session.rollback()
        flash('An error occurred while updating the expense. Please try again.', 'danger')
        return render_template('edit_expenses.html', form=form), 500  # Internal Server Error
    return render_template('edit_expenses.html', form=form), 200  # OK

@app.route('/expenses/delete-expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash('You do not have permission to delete this entry.', 'danger')
        return redirect(url_for('view_expenses')), 403  # Forbidden
    try:
        if request.method == 'POST':
            db.session.delete(expense)
            db.session.commit()
            flash('Expense entry deleted successfully!', 'success')
            return redirect(url_for('view_expenses')), 200  # OK
    except Exception as e:
        logging.error(f"Error deleting expense: {e}")
        db.session.rollback()
        flash('An error occurred while deleting the expense. Please try again.', 'danger')
        return render_template('delete_expense.html', expense=expense), 500  # Internal Server Error
    return render_template('delete_expense.html', expense=expense), 200  # OK

# ------------------------------------------BUDGET-ROUTES----------------------------------------------------------
@app.route('/category-budgets/add-or-update', methods=['GET', 'POST'])
@login_required
def add_or_update_category_budget():
    form = CategoryBudgetForm()
    try:
        if form.validate_on_submit():
            for category, field in form._fields.items():
                if category == "submit":
                    continue
                set_category_budget_for_month(current_user, category, field.data)
            db.session.commit()
            flash('Budgets added or updated successfully!', 'success')
            return redirect(url_for('view_category_budgets')), 201  # Created
    except Exception as e:
        logging.error(f"Error adding or updating category budget: {e}")
        db.session.rollback()
        flash('An error occurred while updating the budget. Please try again.', 'danger')
        return render_template('add_or_update_category_budget.html', form=form), 500  # Internal Server Error
    return render_template('add_or_update_category_budget.html', form=form), 200  # OK

@app.route('/category-budgets/view-all', methods=['GET'])
@login_required
def view_category_budgets():
    category_budgets = Budget.query.filter(Budget.user_id == current_user.id).all()
    return render_template('view_category_budgets.html', category_budgets=category_budgets), 200  # OK

@app.route('/category-budgets/delete/<int:budget_id>', methods=['POST'])
@login_required
def delete_category_budget(budget_id):
    budget = Budget.query.get_or_404(budget_id)
    current_month = datetime.now().month
    current_year = datetime.now().year
    try:
        if budget.user_id != current_user.id or budget.month != current_month or budget.year != current_year:
            abort(403)  # Forbidden access
        db.session.delete(budget)
        db.session.commit()
        flash(f'Your budget for {budget.category} has been deleted!', 'success')
        return redirect(url_for('view_category_budgets')), 200  # OK
    except Exception as e:
        logging.error(f"Error deleting category budget: {e}")
        db.session.rollback()
        flash('An error occurred while deleting the budget. Please try again.', 'danger')
        return redirect(url_for('view_category_budgets')), 500  # Internal Server Error

# ------------------------------------------REPORT-ROUTES----------------------------------------------------------
@app.route('/reports/spending-by-category/monthly')
@login_required
def monthly_spending_report():
    try:
        current_month = datetime.utcnow().month
        current_year = datetime.utcnow().year
        expenses = Expense.query.filter_by(user_id=current_user.id)\
            .filter(db.extract('month', Expense.date) == current_month, db.extract('year', Expense.date) == current_year)\
            .all()
        category_data = Expense.collect_expense_data(expenses)
        img_str, success = generate_report_image(generate_spending_chart, category_data)
        if success:
            return render_template('monthly-spending-report.html', image_data=img_str, title="Monthly Spending by Category"), 200  # OK
        else:
            flash('An error occurred while generating the report. Please try again.', 'danger')
            return render_template('monthly-spending-report.html', title="Monthly Spending by Category"), 500  # Internal Server Error
    except Exception as e:
        logging.error(f"Error generating monthly spending report: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return jsonify({'error': 'Internal Server Error'}), 500  # Internal Server Error
@app.route('/reports/spending-by-category/yearly')
@login_required
def yearly_spending_report():
    try:
        current_year = datetime.utcnow().year
        expenses = Expense.query.filter_by(user_id=current_user.id)\
            .filter(db.extract('year', Expense.date) == current_year)\
            .all()
        category_data = Expense.collect_expense_data(expenses)
        img_str, success = generate_report_image(generate_spending_chart, category_data)
        if success:
            return render_template('yearly-spending-report.html', image_data=img_str, title="Yearly Spending by Category"), 200
        else:
            flash('An error occurred while generating the report. Please try again.', 'danger')
            return render_template('yearly-spending-report.html', title="Yearly Spending by Category"), 500
    except Exception as e:
        logging.error(f"Error generating yearly spending report: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/reports/spending-over-time')
@login_required
def spending_over_time_report():
    try:
        data = get_cumulative_spending_over_time(current_user.id)
        img_str, success = generate_report_image(generate_line_graph, data)
        if success:
            return render_template('spending_over_time.html', image_data=img_str), 200
        else:
            flash('An error occurred while generating the report. Please try again.', 'danger')
            return render_template('spending_over_time.html'), 500
    except Exception as e:
        logging.error(f"Error generating spending over time report: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return jsonify({'error': 'Internal Server Error'}), 500
@app.route('/reports/spending-trends/monthly')
@login_required  # Adding login_required to protect the route
def monthly_spending_trends():
    try:
        user_id = current_user.id
        trends = Expense.compute_monthly_spending_trends(user_id)
        trend_messages = [
            f"For {category}, the change in spending this month compared to the previous month is {trends[category]:.2f}%"
            for category in trends.keys()]
        img_data, success = generate_report_image(generate_trend_graph, trends)
        if success:
            return render_template('view_monthly_spending_trends.html', trend_messages=trend_messages, PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES, img_data=img_data), 200
        else:
            flash('An error occurred while generating the trend report. Please try again.', 'danger')
            return render_template('view_monthly_spending_trends.html', PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES), 500
    except Exception as e:
        logging.error(f"Error generating monthly spending trends: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/reports/spending-trends/yearly')
@login_required  # Adding login_required to protect the route
def yearly_spending_trends():
    try:
        user_id = current_user.id
        previous_year = datetime.utcnow().year - 1
        current_year = datetime.utcnow().year
        trends = Expense.compute_yearly_spending_trends(user_id)
        trend_messages = [
            f"For {category} from {previous_year} to {current_year}, the change in spending is {trends[category]:.2f}%"
            for category in trends.keys()]
        return render_template('view_yearly_spending_trends.html', trend_messages=trend_messages, PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES), 200
    except Exception as e:
        logging.error(f"Error generating yearly spending trends: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/expense_frequency', methods=['GET'])
@login_required
def expense_frequency():
    most_frequent_categories = get_most_frequent_categories(current_user.id)
    return render_template('expense_frequency.html', most_frequent_categories=most_frequent_categories)
@app.route('/reports/budget-vs-actual', methods=['GET'])
@login_required
def budget_vs_actual_report():
    try:
        current_month = datetime.utcnow().month
        current_year = datetime.utcnow().year
        data = get_budget_vs_actual(current_user.id, current_month, current_year)
        img_data_url, success = generate_report_image(generate_budget_vs_actual_chart, data)
        if success:
            return render_template('budget_vs_actual.html', image_data=img_data_url), 200
        else:
            flash('An error occurred while generating the report. Please try again.', 'danger')
            return render_template('budget_vs_actual.html'), 500
    except Exception as e:
        logging.error(f"Error generating budget vs actual report: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return jsonify({'error': 'Internal Server Error'}), 500
@app.route('/savings_opportunities', methods=['GET'])
@login_required
def savings_opportunities():
    opportunities = identify_savings_opportunities(current_user.id)
    return render_template('savings_opportunities.html', opportunities=opportunities)
@app.route('/reports/export')
@login_required
def export_report():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    data = {"Description": [expense.description for expense in expenses],  # List comprehension
        "Amount": [expense.amount for expense in expenses],
        "Date": [expense.date for expense in expenses],
        "Expense Category": [expense.category for expense in expenses]}
    excel_file = export_to_excel(data)
    return send_file(excel_file, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",as_attachment=True, download_name="report.xlsx")
# ------------------------------------------NOTIFICATIONS ROUTES----------------------------------------------------------
@app.route('/notifications')
@login_required
def view_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).all()
    return render_template('view_notifications.html', notifications=notifications)
@app.route('/notifications/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_as_read(notification_id):
    notification = Notification.query.get(notification_id)
    if not notification or notification.user_id != current_user.id:
        flash('Notification not found.', 'error')
        return redirect(url_for('dashboard'))
    notification.is_read = True
    db.session.commit()
    flash('Notification marked as read.')
    return redirect(url_for('dashboard'))
@app.route('/notifications/mark_all_as_read', methods=['POST'])
@login_required
def mark_all_as_read():
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    for notification in notifications:
        notification.is_read = True
    db.session.commit()
    flash('All notifications marked as read.')
    return redirect(url_for('view_notifications'))
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = current_user.id
    unread_notification_count = Notification.query.filter_by(user_id=user_id, is_read=False).count()
    previous_month_name, previous_year, current_month_name, current_year = get_previous_and_current_month_names()
    trends = Expense.compute_monthly_spending_trends(user_id)
    trend_messages = [ f"For {category} from {previous_month_name} {previous_year} to {current_month_name} {current_year}, the change in spending is {trends[category]:.2f}%" for category, value in trends.items()]
    return render_template('dashboard.html', trend_messages=trend_messages, PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES, unread_notification_count=unread_notification_count)


if __name__ == '__main__':
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True)
    else:
        app.run()