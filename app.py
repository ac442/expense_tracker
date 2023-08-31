from imports import *
import pyotp # New import for 2FA
app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s - %(message)s')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'your_database_name.db')
app.config['SECRET_KEY'] = 'randomString323'  # Change this to a random value for production
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['WTF_CSRF_ENABLED'] = False
app.config["jwt"] = JWTManager(app)
db = SQLAlchemy(app)
# jwt = JWTManager(app)
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
def utility_processor():
    return dict(range=range)


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
    return Expense.query.filter_by(user_id=current_user.id) \
        .filter(db.extract('year', Expense.date) == year, db.extract('month', Expense.date) == month) \
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


def generate_budget_vs_actual_chart_to_file(data):
    # ... (same code as before to generate the plot)
    unique_filename = f"budget_vs_actual_{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
    file_path = os.path.join("static/images", unique_filename)
    plt.savefig(file_path)
    return file_path



def check_data_integrity(data):
    if not isinstance(data, dict):
        logging.error("Data is not a dictionary")
        return False
    for key, value in data.items():
        if not isinstance(value, dict):
            logging.error(f"Value for {key} is not a dictionary")
            return False
        if 'budget' not in value or 'actual' not in value:
            logging.error(f"Value for {key} does not have 'budget' and 'actual' keys")
            return False
    return True


def get_last_budget_setting(user_id, category):
    # Fetch the most recent budget setting for a user and category
    last_budget_setting = Budget.query.filter_by(user_id=user_id, category=category) \
        .order_by(Budget.year.desc(), Budget.month.desc(), Budget.day_set.desc()) \
        .first()
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
def add_object_to_db(db_object):
    db.session.add(db_object)

def generate_budget_vs_actual_chart(data):
    categories = list(data.keys())
    budget_values = [entry["budget"] for entry in data.values()]
    actual_values = [entry["actual"] for entry in data.values()]

    width = 0.35  # the width of the bars
    fig, ax = plt.subplots(figsize=(8, 5))  # Smaller dimensions
    ind = np.arange(len(categories))  # the x locations for the groups

    p1 = ax.bar(ind - width / 2, budget_values, width, label='Budget', color='blue')
    p2 = ax.bar(ind + width / 2, actual_values, width, label='Actual', color='orange')

    ax.set_title('Budget vs Actual Expenses by Category')
    ax.set_xticks(ind)
    ax.set_xticklabels(categories, rotation=45)
    ax.legend()

    for bar in p1:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, yval + 5, round(yval, 2), ha='center', va='bottom', color='black', size=8)

    for bar in p2:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, yval + 5, round(yval, 2), ha='center', va='bottom', color='black', size=8)

    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png')  # Lower quality is typically for 'jpeg' or 'jpg'
    buf.seek(0)

    return buf

def set_category_budget_for_month(user, category, amount, day_set, today):
    budget = Budget.query.filter_by(user_id=user.id, category=category).first()
    if not budget:
        budget = Budget(user_id=user.id, category=category)
        db.session.add(budget)
    budget.budget_amount = amount
    budget.day_set = day_set  # Store the day the budget was set
    budget.month = today.month
    budget.year = today.year
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
def flash_message(message, category):
    flash(message, category)
def redirect_with_status(url, status_code):
    return redirect(url_for(url)), status_code
def handle_db_operation(operation, action, entity, form=None):
    try:
        operation()
        db.session.commit()
        flash(f'{entity.capitalize()} {action} successfully!', 'success')
        return True
    except Exception as e:
        logging.error(f"Error {action} {entity}: {e}")
        db.session.rollback()
        flash(f'An error occurred while {action} the {entity}. Please try again.', 'danger')
        return False
def handle_form(form, template, **extra_context):
    if form.validate_on_submit():
        return True, None
    else:
        context = {'form': form}
        context.update(extra_context)
        return False, render_template(template, **context)
def calculate_amount_spent(user_id, category):
    current_month = datetime.utcnow().month
    current_year = datetime.utcnow().year
    expenses = Expense.query.filter_by(user_id=user_id, category=category).filter(
        db.extract('month', Expense.date) == current_month,
        db.extract('year', Expense.date) == current_year).all()
    return sum(expense.amount for expense in expenses)
def generate_spending_report(timeframe):
    current_year = datetime.utcnow().year
    current_month = datetime.utcnow().month if timeframe == 'monthly' else None
    filter_conditions = [Expense.user_id == current_user.id]
    if timeframe == 'monthly':
        filter_conditions.append(db.extract('month', Expense.date) == current_month)
    filter_conditions.append(db.extract('year', Expense.date) == current_year)
    expenses = Expense.query.filter(*filter_conditions).all()
    category_data = Expense.collect_expense_data(expenses)
    img_str, success = generate_report_image(generate_spending_chart, category_data)
    if success:
        return render_template(f'{timeframe}-spending-report.html', image_data=img_str,
                               title=f"{timeframe.capitalize()} Spending by Category"), 200
    else:
        flash('An error occurred while generating the report. Please try again.', 'danger')
        return render_template(f'{timeframe}-spending-report.html',
                               title=f"{timeframe.capitalize()} Spending by Category"), 500
def generate_spending_trends(timeframe):
    user_id = current_user.id
    trends = Expense.compute_spending_trends(user_id, timeframe)
    trend_messages = [
        f"For {category}, the change in spending for the selected timeframe is {trends[category]:.2f}%"
        for category in trends.keys()]
    return render_template(f'view_{timeframe}_spending_trends.html', trend_messages=trend_messages,
                           PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES), 200
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
    budgets = Budget.query.filter_by(user_id=user_id).filter(
        (Budget.month >= three_months_ago_month) & (Budget.year >= three_months_ago_year)).all()
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
        plt.text(bar.get_x() + bar.get_width() / 2, yval,
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
    def validate_confirm_password(self, field):
        if self.password.data != self.confirm_password.data:
            raise ValidationError("Passwords do not match.")

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
    category = SelectField('Category', choices=[(cat, cat) for cat in PREDEFINED_CATEGORIES['expense']],
                           validators=[DataRequired(), Length(min=2, max=100)])
    description = StringField('Description', validators=[Optional(), Length(max=300)])
    amount = FloatField('Amount', validators=[DataRequired()])
    is_recurring = BooleanField('Is this a recurring expense?')  # New field for recurring
    recurring_frequency = SelectField('Recurring Frequency',
                                      choices=[('', '--Select Frequency--'), ('daily', 'Daily'), ('weekly', 'Weekly'),
                                               ('monthly', 'Monthly')])  # New field for frequency
    submit = SubmitField('Submit')
class CategoryBudgetForm(FlaskForm):
    for category in PREDEFINED_CATEGORIES['expense']:
        locals()[to_snake_case(category)] = FloatField(category, validators=[Optional()])
    submit = SubmitField('Set Category Budgets')
class FinancialGoalForm(FlaskForm):
    goal_name = StringField('Goal Name', validators=[DataRequired()])
    goal_amount = FloatField('Goal Amount', validators=[DataRequired()])
    due_date = DateTimeField('Due Date (YYYY-MM-DD HH:MM:SS)', format='%Y-%m-%d %H:%M:%S', validators=[Optional()])
    submit = SubmitField('Save')
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
    is_recurring = db.Column(db.Boolean, default=False)
    recurring_frequency = db.Column(db.String(50))  # e.g., 'Weekly', 'Monthly'
    due_date = db.Column(db.DateTime)  # New field for due date reminders

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
class User(UserMixin, db.Model):
    # Existing fields
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    firstname = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    main_budget = db.Column(db.Float)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    secret_key = db.Column(db.String(16))
    expenses = db.relationship('Expense', back_populates='user', lazy=True)
    budgets = db.relationship('Budget', back_populates='user', lazy=True)
    notifications = db.relationship('Notification', back_populates='user', lazy=True)
    financial_goals = db.relationship('FinancialGoal', back_populates='user', lazy=True)

    def validate_two_factor_code(self, two_factor_code):
        totp = pyotp.TOTP(self.secret_key)
        return totp.verify(two_factor_code)

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
    day_set = db.Column(db.Integer, nullable=True)  # New field for day of the month
    last_budget_setting = db.Column(db.Date, nullable=True)  # New field for the last date when the budget was set
    month = db.Column(db.Integer, nullable=False, default=datetime.utcnow().month)
    year = db.Column(db.Integer, nullable=False, default=datetime.utcnow().year)
    user = db.relationship('User', back_populates='budgets')
    ___table_args__ = (db.UniqueConstraint('user_id', 'category', 'month', 'year', name='unique_category_per_user_per_month_per_year'),)

    @classmethod
    def get_budget_for_category(cls, user_id, category):
        budget = cls.query.filter_by(user_id=user_id, category=category).first()
        print(f"Budget for user_id {user_id} and category {category}: {budget}")
        return budget
class FinancialGoal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    goal_name = db.Column(db.String(100), nullable=False)
    goal_amount = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = db.relationship('User', back_populates='financial_goals')
    @classmethod
    def create_goal(cls, user_id, goal_name, goal_amount, due_date):
        new_goal = cls(
            user_id=user_id,
            goal_name=goal_name,
            goal_amount=goal_amount,
            due_date=due_date
        )
        db.session.add(new_goal)
        db.session.commit()
    def update_goal(self, goal_name, goal_amount, due_date):
        self.goal_name = goal_name
        self.goal_amount = goal_amount
        self.due_date = due_date
        db.session.commit()
# ===============================================ROUTES SECTION=========================================================
@app.route('/user/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data  # Already confirmed to match confirm_password by WTForms
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'danger')
            return render_template('register.html', form=form), 409  # Conflict
        # Hash the password and create a new user
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, email=email, password_hash=hashed_password)
        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login')), 201  # Created

    return render_template('register.html', form=form)
@app.route('/user/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.is_2fa_enabled:
                session['username'] = username
                return redirect(url_for('two_factor'))
            else:
                login_user(user)
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)
@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        user = User.query.filter_by(username=session['username']).first()
        user_otp = request.form.get('otp')
        totp = pyotp.TOTP(user.secret_key)
        if totp.verify(user_otp):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP', 'danger')
    return render_template('two_factor.html')
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
    def update_profile_details():
        # This function contains the code that updates the user profile.
        current_user.firstname = form.firstname.data
        current_user.lastname = form.lastname.data
        current_user.email = form.email.data
    if form.validate_on_submit():
        # Use handle_db_operation to execute update_profile_details,
        # handle database commit/rollback, and flash messages.
        if handle_db_operation(update_profile_details, 'updated', 'Profile'):
            return redirect(url_for('dashboard')), 200  # OK
    elif request.method == 'GET':
        form.firstname.data = current_user.firstname
        form.lastname.data = current_user.lastname
        form.email.data = current_user.email
    return render_template('edit_profile_details.html', form=form), 200  # OK
@app.route('/user/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    def update_password():
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('Incorrect old password.', 'danger')
            return False  # Return False to indicate the operation was not successful
        current_user.password = generate_password_hash(form.new_password.data, method='sha256')
        return True  # Return True to indicate the operation was successful
    if form.validate_on_submit():
        # Execute the update_password function and check its return value.
        # If it returns True, proceed with the redirect.
        if handle_db_operation(update_password, 'changed', 'Password'):
            return redirect(url_for('dashboard')), 200  # OK
    return render_template('change_password.html', form=form), 200  # OK
@app.route('/enable_2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if current_user.is_2fa_enabled:
        flash('Two-factor authentication is already enabled.', 'info')
        return redirect(url_for('profile'))  # Redirect to the user's profile page
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        totp = TOTP(current_user.secret_key)
        is_valid_otp = totp.verify(user_otp)
        if is_valid_otp:
            current_user.is_2fa_enabled = True
            db.session.commit()
            flash('Two-factor authentication has been enabled successfully.', 'success')
            return redirect(url_for('profile'))  # Redirect to the user's profile page
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    totp = TOTP(current_user.secret_key)
    qr_code_url = totp.provisioning_uri(current_user.email, issuer_name='YourApp')
    return render_template('enable_2fa.html.html', qr_code_url=qr_code_url)
# ------------------------------------------EXPENSE-ROUTES----------------------------------------------------------
@app.route('/expenses/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    form = ExpenseForm()

    def add_object_to_db():
        # Step 1: Log the expense
        expense = Expense(
            user_id=current_user.id,
            category=form.category.data,
            description=form.description.data,
            amount=form.amount.data,
            date=form.date.data
        )
        db.session.add(expense)

        # Step 2: Fetch the corresponding budget
        budget = Budget.get_budget_for_category(
            user_id=current_user.id,
            category=form.category.data,
            month=form.date.data.month,  # Assuming the form's date is a datetime object
            year=form.date.data.year
        )

        # Step 3: Update the budget
        if budget:
            budget.budget_amount -= form.amount.data

    if form.validate_on_submit():
        if handle_db_operation(add_object_to_db, 'added', 'Expense'):
            flash('Expense entry added and budget updated successfully!', 'success')
            return redirect(url_for('view_expenses')), 201  # Created
        else:
            flash('An error occurred while adding the expense entry. Please try again.', 'danger')
            return render_template('add_expense.html', form=form), 500  # Internal Server Error
    return render_template('add_expense.html', form=form), 200  # OK


@app.route('/expenses/view-all', methods=['GET'])
@login_required
def view_expenses():
    is_recurring_filter = request.args.get('is_recurring', None, type=bool)
    if is_recurring_filter is not None:
        expenses = Expense.query.filter_by(user_id=current_user.id, is_recurring=is_recurring_filter).all()
    else:
        expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('view_expenses.html', expenses=expenses), 200  # OK
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
from datetime import datetime

@app.route('/category-budgets/add', methods=['GET', 'POST'])
@login_required
def add_category_budget():
    form = CategoryBudgetForm()
    today = datetime.utcnow()
    current_day = today.day
    current_month = today.month
    current_year = today.year

    def operation():
        for category, field in form._fields.items():
            if category == "submit":
                continue

            existing_budget = Budget.get_budget_for_category(current_user.id, category)

            if existing_budget:
                # Update the existing budget
                existing_budget.budget_amount = field.data
                existing_budget.day_set = current_day
                existing_budget.last_budget_setting = today
                existing_budget.month = current_month
                existing_budget.year = current_year
            else:
                # Create a new budget
                new_budget = Budget(
                    user_id=current_user.id,
                    category=category,
                    budget_amount=field.data,
                    day_set=current_day,
                    last_budget_setting=today,
                    month=current_month,
                    year=current_year
                )
                db.session.add(new_budget)
        db.session.commit()
        return True

    if form.validate_on_submit():
        if operation():
            flash('Budgets set successfully.', 'success')
            return redirect(url_for('view_category_budgets')), 201
    return render_template('add_category_budget.html', form=form), 200



@app.route('/category-budgets/view-all', methods=['GET'])
@login_required
def view_category_budgets():
    category_budgets = Budget.query.filter(Budget.user_id == current_user.id).all()
    return render_template('view_category_budgets.html', category_budgets=category_budgets), 200  # OK
@app.route('/category-budgets/update', methods=['GET', 'POST'])
@login_required
def update_category_budget():
    form = CategoryBudgetForm()
    today = datetime.utcnow()
    current_day = today.day
    current_month = today.month
    current_year = today.year
    existing_budget = Budget.query.filter_by(user_id=current_user.id).first()
    if existing_budget:
        last_budget_setting = existing_budget.last_budget_setting
        if last_budget_setting and last_budget_setting.month == current_month and last_budget_setting.year == current_year:
            flash('You have already set your budget this month.', 'warning')
            return render_template('update_category_budget.html', form=form), 403  # Forbidden
    def update_budgets():
        for category, field in form._fields.items():
            if category == "submit":
                continue  # Skip the submit button
            set_category_budget_for_month(current_user, category, field.data, current_day, today)
    if handle_db_operation(update_budgets, 'updated', 'Budgets'):
        return redirect(url_for('view_category_budgets')), 200  # OK
    return render_template('update_category_budget.html', form=form), 500  # Internal Server Error
@app.route('/category-budgets/delete/<int:budget_id>', methods=['POST'])
@login_required
def delete_category_budget(budget_id):
    budget = Budget.query.get_or_404(budget_id)
    current_month = datetime.now().month
    current_year = datetime.now().year
    def delete_budget():
        if budget.user_id != current_user.id or budget.month != current_month or budget.year != current_year:
            abort(403)  # Forbidden access
        db.session.delete(budget)
    if handle_db_operation(delete_budget, 'deleted', 'Budget'):
        return redirect(url_for('view_category_budgets')), 200  # OK
    else:
        return redirect(url_for('view_category_budgets')), 500  # Internal Server Error
# ------------------------------------------GOAL-ROUTES----------------------------------------------------------
@app.route('/financial_goals/add_or_update', methods=['GET', 'POST'])
@app.route('/financial_goals/add_or_update/<int:goal_id>', methods=['GET', 'POST'])
@login_required
def add_or_update_financial_goal(goal_id=None):
    goal = None
    form = FinancialGoalForm()  # Initialize your form
    if goal_id:
        goal = FinancialGoal.query.get_or_404(goal_id)
        form = FinancialGoalForm(obj=goal)  # Initialize your form with existing data
    if form.validate_on_submit():
        goal_name = form.goal_name.data
        goal_amount = form.goal_amount.data
        due_date = form.due_date.data  # This will already be a datetime object
        if goal:
            goal.update_goal(goal_name, goal_amount, due_date)
            flash('Financial goal updated successfully!', 'success')
        else:
            FinancialGoal.create_goal(current_user.id, goal_name, goal_amount, due_date)
            flash('Financial goal created successfully!', 'success')
        return redirect(url_for('list_financial_goals'))
    return render_template('add_or_update_financial_goal.html', form=form, goal=goal)  # Create this template
@app.route('/financial_goals/list', methods=['GET'])
@login_required
def list_financial_goals():
    goals = FinancialGoal.query.filter_by(user_id=current_user.id).all()
    return render_template('list_financial_goals.html', goals=goals)
@app.route('/financial_goals/delete/<int:goal_id>', methods=['POST'])
@login_required
def delete_financial_goal(goal_id):
    goal = FinancialGoal.query.get_or_404(goal_id)
    if goal.user_id != current_user.id:
        abort(403)  # Forbidden
    db.session.delete(goal)
    db.session.commit()
    flash('Financial goal deleted successfully!', 'success')
    return redirect(url_for('list_financial_goals'))
# ------------------------------------------REPORT-ROUTES----------------------------------------------------------
@app.route('/reports/spending-by-category/monthly')
@login_required
def monthly_spending_report():
    try:
        return generate_spending_report('monthly')
    except Exception as e:
        logging.error(f"Error generating monthly spending report: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return jsonify({'error': 'Internal Server Error'}), 500  # Internal Server Error
@app.route('/reports/spending-by-category/yearly')
@login_required
def yearly_spending_report():
    try:
        return generate_spending_report('yearly')
    except Exception as e:
        logging.error(f"Error generating yearly spending report: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return jsonify({'error': 'Internal Server Error'}), 500  # Internal Server Error
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
    return generate_spending_trends('monthly')
@app.route('/reports/spending-trends/yearly')
@login_required  # Adding login_required to protect the route
def yearly_spending_trends():
    return generate_spending_trends('yearly')
@app.route('/reports/expense_frequency', methods=['GET'])
@login_required
def expense_frequency():
    most_frequent_categories = get_most_frequent_categories(current_user.id)
    return render_template('expense_frequency.html', most_frequent_categories=most_frequent_categories)

@app.route('/reports/budget_vs_actual_report', defaults={'month': None, 'year': None}, methods=['GET'])
@app.route('/reports/budget_vs_actual_report/<int:month>/<int:year>', methods=['GET'])
@login_required
def budget_vs_actual_report(month, year):
    current_year = datetime.now().year
    next_year = current_year + 1

    # Check for a "dummy" query parameter to use dummy data
    use_dummy_data = request.args.get('dummy', default=False, type=bool)

    if month is None and year is None:
        return render_template('budget_vs_actual_report_selector.html',
                               current_year=current_year,
                               next_year=next_year)

    try:
        if use_dummy_data:
            # Dummy data for testing
            data = {
                'Food': {'budget': 200, 'actual': 180},
                'Rent': {'budget': 1000, 'actual': 1000},
                'Utilities': {'budget': 100, 'actual': 110},
            }
        else:
            # Actual data retrieval logic
            data = get_budget_vs_actual(current_user.id, month, year)

        if not check_data_integrity(data):
            logging.error("Data integrity check failed")
            flash('An error occurred due to inconsistent data. Please try again.', 'danger')
            return render_template('budget_vs_actual_report.html',
                                   current_year=current_year,
                                   next_year=next_year), 400

        image_path = generate_budget_vs_actual_chart_to_file(data)

        return render_template('budget_vs_actual_report.html',
                               image_path=image_path,
                               current_year=current_year,
                               next_year=next_year), 200
    except Exception as e:
        logging.error(f"Error generating budget vs actual report: {e}", exc_info=True)
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
        for category, value in trends.items()]
    return render_template('dashboard.html', trend_messages=trend_messages, PREDEFINED_CATEGORIES=PREDEFINED_CATEGORIES,
                           unread_notification_count=unread_notification_count)
if __name__ == '__main__':
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True)
    else:
        app.run()
