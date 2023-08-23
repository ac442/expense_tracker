import logging
import os
from datetime import datetime
from io import BytesIO
from collections import defaultdict
import pandas as pd
from flask import Flask, flash, redirect, render_template, url_for, request, abort, send_file
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import FloatField, PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import matplotlib.pyplot as plt
import io
from wtforms.validators import Optional
from base64 import b64encode
import base64
from dateutil.relativedelta import relativedelta

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s - %(message)s')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'your_database_name.db')
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random value for production
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['WTF_CSRF_ENABLED'] = False
db = SQLAlchemy(app)
flask_migrate = Migrate(app, db)
PREDEFINED_CATEGORIES = {
    'expense': ["Housing & Utilities", "Food & Dining", "Transport",
                "Personal Care & Lifestyle", "Savings", "Investments",
                "Personal Debt", "Taxes", "Family & Relationships",
                "Education & Professional Services", "Miscellaneous"]
}
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
def generate_line_graph(data):
    dates = list(data.keys())
    amounts = list(data.values())
    plt.figure(figsize=(10, 6))
    plt.plot(dates, amounts, marker='o')
    plt.title('Spending Over Time')
    plt.xlabel('Date')
    plt.ylabel('Total Amount')
    plt.grid(True)
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
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

# -----------------------------------DATA MODELS SECTION----------------------------------------------------------------
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

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(80), nullable=False)  # Specific category like "Housing", "Food", etc.
    budget_amount = db.Column(db.Float, nullable=True)  # Budget amount for that category
    user = db.relationship('User', back_populates='budgets')
    __table_args__ = (db.UniqueConstraint('user_id', 'category', name='unique_category_per_user'),)
    @classmethod
    def get_budget_for_category(cls, user_id, category):
        budget = cls.query.filter_by(user_id=user_id, category=category).first()
        print(f"Budget for user_id {user_id} and category {category}: {budget}")
        return budget


class BudgetService:
    @staticmethod
    def check_budget_for_user(user):
        for category in PREDEFINED_CATEGORIES['expense']:
            total_expense_for_category = sum(
                exp.amount for exp in user.expenses if exp.category == category)  # Updated attributes
            budget_for_category = Budget.query.filter_by(user_id=user.id, category=category).first()
            if budget_for_category and total_expense_for_category >= budget_for_category.budget_amount:
                notify_user(user, f"Your spending in {category} has reached or exceeded your set budget.")

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
            db.extract('year', Expense.date) == current_year
        ).all()
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


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category = db.Column(db.String(80), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.String(200))
    user = db.relationship('User', back_populates='expenses')
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
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password',
                                                                                                 message='Passwords must match.')])
    submit = SubmitField('Change Password')
class ExpenseForm(FlaskForm):
    category = SelectField('Category', choices=PREDEFINED_CATEGORIES['expense'],
                           validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[Optional(), Length(max=300)])
    amount = FloatField('Amount', validators=[DataRequired()])
    submit = SubmitField('Submit')
class MainBudgetForm(FlaskForm):
    main_budget = FloatField('Main Budget Amount', validators=[DataRequired()])
    submit = SubmitField('Set Main Budget')

class CategoryBudgetForm(FlaskForm):
    for category in PREDEFINED_CATEGORIES['expense']:
        locals()[to_snake_case(category)] = FloatField(category, validators=[Optional()])
    submit = SubmitField('Set Category Budgets')


# ===============================================ROUTES SECTION=========================================================
@app.route('/user/register', methods=['GET', 'POST'])
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
@app.route('/user/login', methods=['GET', 'POST'])
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
    return render_template('login.html', form=form), 401
@app.route('/user/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))
@app.route('/user/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)
@app.route('/user/edit_profile_details', methods=['GET', 'POST'])
@login_required
def edit_profile_details():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.firstname = form.firstname.data
        current_user.lastname = form.lastname.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.firstname.data = current_user.firstname
        form.lastname.data = current_user.lastname
        form.email.data = current_user.email
    return render_template('edit_profile_details.html', form=form)

@app.route('/user/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not check_password_hash(current_user.password, form.old_password.data):
            flash('Incorrect old password.', 'danger')
            return redirect(url_for('change_password'))
        current_user.password = generate_password_hash(form.new_password.data, method='sha256')
        db.session.commit()
        flash('Your password has been changed successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html', form=form)
# ------------------------------------------EXPENSE-ROUTES----------------------------------------------------------
@app.route('/expenses/add-expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    form = ExpenseForm()
    if form.validate_on_submit():
        expense = Expense(category=form.category.data, amount=form.amount.data,
                          description=form.description.data or None, user_id=current_user.id)
        db.session.add(expense)
        db.session.commit()
        flash('Expense added successfully!')
        BudgetService.check_large_expense_for_user(current_user)
        return redirect(url_for('view_expenses'))
    return render_template('add_expense.html', form=form)

@app.route('/expenses/view-expense')
@login_required
def view_expenses():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('view_expenses.html', expenses=expenses)
@app.route('/expenses/update-expense/<int:expense_id>', methods=['GET', 'POST'])
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
            return render_template('edit_expenses.html', form=form)
        expense.budget_type = form.source.data
        expense.budget_amount = form.amount.data
        expense.description = form.description.data
        try:
            db.session.commit()
            flash('Expense updated successfully!')
        except:
            db.session.rollback()
            flash('Error updating expense. Please try again later.')
        return redirect(url_for('view_expenses'))
    return render_template('edit_expenses.html', form=form)
@app.route('/expenses/delete-expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    if expense.user_id != current_user.id:
        flash('You do not have permission to delete this entry.')
        return redirect(url_for('view_expenses'))
    if request.method == 'POST':
        db.session.delete(expense)
        db.session.commit()
        flash('Expense entry deleted successfully!')
        return redirect(url_for('view_expenses'))
    return render_template('delete_expense.html', expense=expense)
# ------------------------------------------BUDGET-ROUTES----------------------------------------------------------
@app.route('/category-budgets/add-category', methods=['GET', 'POST'])
@login_required
def add_category_budget():
    form = CategoryBudgetForm()
    if form.validate_on_submit():
        for category in PREDEFINED_CATEGORIES['expense']:
            field = getattr(form, to_snake_case(category))
            if field.data is not None:  # Only save if the field has data
                budget_entry = Budget(user_id=current_user.id, category=category, budget_amount=field.data)
                db.session.add(budget_entry)
        db.session.commit()
        flash('Budgets added successfully!')
        return redirect(url_for('view_category_budgets'))
    return render_template('add_category_budget.html', category_budget_form=form)

@app.route('/category-budgets/view-all', methods=['GET'])
@login_required
def view_category_budgets():
    category_budgets = Budget.query.filter(Budget.user_id == current_user.id).all()
    return render_template('view_category_budgets.html', category_budgets=category_budgets)
@app.route('/category-budgets/update', methods=['GET', 'POST'])
@login_required
def update_category_budget():
    form = CategoryBudgetForm()

    if form.validate_on_submit():
        for category, field in form._fields.items():
            if category == "submit":
                continue

            budget_for_category = Budget.get_budget_for_category(current_user.id, category)
            if budget_for_category:
                budget_for_category.budget_amount = field.data

        db.session.commit()
        flash('Budgets updated successfully!')
        return redirect(url_for('view_category_budgets'))

    elif request.method == 'GET':
        for category_budget in Budget.query.filter_by(user_id=current_user.id).all():
            field = getattr(form, to_snake_case(category_budget.category))
            field.data = category_budget.budget_amount

    return render_template('update_category_budget.html', category_budget_form=form)

@app.route('/category-budgets/delete/<int:budget_id>', methods=['POST'])
@login_required
def delete_category_budget(budget_id):
    budget = Budget.query.get_or_404(budget_id)
    if budget.user_id != current_user.id:
        abort(403)  # Forbidden access
    db.session.delete(budget)
    db.session.commit()
    flash(f'Your budget for {budget.category} has been deleted!', 'success')
    return redirect(url_for('view_category_budgets'))

# ------------------------------------------REPORT-ROUTES----------------------------------------------------------
@app.route('/reports/spending-by-category/monthly')
@login_required
def monthly_spending_report():
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year
    expenses = Expense.query.filter_by(user_id=current_user.id)\
        .filter(db.extract('month', Expense.date) == current_month, db.extract('year', Expense.date) == current_year)\
        .all()
    category_data = Expense.collect_expense_data(expenses)
    img = generate_spending_chart(category_data)
    img_str = b64encode(img.getvalue()).decode('utf-8')
    return render_template('monthly-spending-report.html', image_data=img_str, title="Monthly Spending by Category")


@app.route('/reports/spending-by-category/yearly')
@login_required
def yearly_spending_report():
    current_year = datetime.utcnow().year

    expenses = Expense.query.filter_by(user_id=current_user.id)\
        .filter(db.extract('year', Expense.date) == current_year)\
        .all()

    category_data = Expense.collect_expense_data(expenses)
    img = generate_spending_chart(category_data)
    img_str = b64encode(img.getvalue()).decode('utf-8')
    return render_template('yearly-spending-report.html', image_data=img_str, title="Yearly Spending by Category")

@app.route('/reports/spending-over-time')
@login_required
def spending_over_time_report():
    data = get_cumulative_spending_over_time(current_user.id)
    img = generate_line_graph(data)
    img_str = b64encode(img.getvalue()).decode('utf-8')
    return render_template('spending_over_time.html', image_data=img_str)

@app.route('/reports/spending-trends/monthly')
def monthly_spending_trends():
    user_id = current_user.id
    trends = Expense.compute_monthly_spending_trends(user_id)
    trend_messages = [
        f"For {category}, the change in spending this month compared to the previous month is {trends[category]:.2f}%"
        for category, value in trends.items()
    ]
    img_data = generate_trend_graph(trends, title="Monthly Spending Trends")
    return render_template('view_monthly_spending_trends.html', trend_messages=trend_messages,
                           PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES, img_data=img_data)

@app.route('/reports/spending-trends/yearly')
def yearly_spending_trends():
    user_id = current_user.id
    previous_year = datetime.utcnow().year - 1
    current_year = datetime.utcnow().year
    trends = Expense.compute_yearly_spending_trends(user_id)
    trend_messages = [
        f"For {category} from {previous_year} to {current_year}, the change in spending is {trends[category]:.2f}%"
        for category, value in trends.items()
    ]
    return render_template('view_yearly_spending_trends.html', trend_messages=trend_messages,
                           PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES)
@app.route('/reports/export')
@login_required
def export_report():
    expenses = Expense.query.filter_by(user_id=current_user.id).all()
    data = {
        "Description": [expense.description for expense in expenses],  # List comprehension
        "Amount": [expense.amount for expense in expenses],
        "Date": [expense.date for expense in expenses],
        "Expense Category": [expense.category for expense in expenses],
    }

    excel_file = export_to_excel(data)
    return send_file(excel_file, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     as_attachment=True, download_name="report.xlsx")


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
    trend_messages = [
        f"For {category} from {previous_month_name} {previous_year} to {current_month_name} {current_year}, the change in spending is {trends[category]:.2f}%"
        for category, value in trends.items()
    ]
    return render_template('dashboard.html', trend_messages=trend_messages, PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES, unread_notification_count=unread_notification_count)

# -------------------------------------------MAIN METHOD---------------------------------------------------------------
if __name__ == '__main__':
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True)
    else:
        app.run()
