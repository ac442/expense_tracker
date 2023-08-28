from datetime import datetime
from collections import Counter
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from io import BytesIO
import base64
from base64 import b64encode
import io
from flask import render_template
from dateutil.relativedelta import relativedelta
from flask_login import current_user
from flask import current_app, g
from extensions import db



#General utility functions


def get_current_month_and_year():
    current_time = datetime.utcnow()
    return current_time.month, current_time.year


def get_budget_for_month(user, category):
    from app import Budget  # Lazy import
    current_month, current_year = get_current_month_and_year()
    existing_budget = get_existing_budget(user.id, category, current_month, current_year)
    return existing_budget.budget_amount if existing_budget else 0

def get_previous_month_and_year():
    current_month, current_year = get_current_month_and_year()
    if current_month == 1:
        previous_month = 12
        previous_year = current_year - 1
    else:
        previous_month = current_month - 1
        previous_year = current_year
    return previous_month, previous_year

def notify_user(user, message):
    from app import Notification
    db = get_db()
    notification = Notification(message=message, user_id=user.id)
    db.session.add(notification)
    db.session.commit()
def calculate_spending_trends(current_expenses, previous_expenses):
    from app import PREDEFINED_CATEGORIES  # Lazy import
    trends = {}
    for category in PREDEFINED_CATEGORIES['expense']:
        current_spending = sum(exp.amount for exp in current_expenses if exp.category == category)
        previous_spending = sum(exp.amount for exp in previous_expenses if exp.category == category)
        if previous_spending != 0:
            percent_change = ((current_spending - previous_spending) / previous_spending) * 100
            trends[category] = percent_change
    return trends

#Database Query functions

def get_expenses_by_time_and_user(user_id, categories=None, start_date=None, end_date=None, month=None, year=None):
    from app import Expense  # Lazy import
    db = get_db()
    query = Expense.query.filter_by(user_id=user_id)
    if categories:
        query = query.filter(Expense.category.in_(categories))
    if start_date and end_date:
        query = query.filter(Expense.date >= start_date, Expense.date <= end_date)
    if month:
        query = query.filter(db.extract('month', Expense.date) == month)
    if year:
        query = query.filter(db.extract('year', Expense.date) == year)
    return query.all()


def get_existing_budget(user_id, category, month, year):
    from app import Budget  # Lazy import
    db = get_db()
    return Budget.query.filter_by(
        user_id=user_id,
        category=category,
        month=month,
        year=year
    ).first()

def get_cumulative_spending_over_time(user_id):
    from app import Expense  # Lazy import
    expenses = get_expenses_by_time_and_user(user_id)
    expenses.sort(key=lambda x: x.date)  # Make sure the expenses are sorted by date
    data = {}
    total = 0
    for expense in expenses:
        total += expense.amount
        data[expense.date] = total
    return data

#Budget Functions
def set_category_budget_for_month(user, category, amount):
    from app import Budget  # Lazy import
    db = get_db()
    current_month, current_year = get_current_month_and_year()
    existing_budget = get_existing_budget(user.id, category, current_month, current_year)
    if existing_budget:
        existing_budget.budget_amount = amount
    else:
        budget_entry = Budget(
            user_id=user.id,
            category=category,
            month=current_month,
            year=current_year,
            budget_amount=amount
        )
        db.session.add(budget_entry)
        db.session.commit()


def get_budget_vs_actual(user_id, month, year):
    from app import Expense, PREDEFINED_CATEGORIES# Lazy import
    categories = PREDEFINED_CATEGORIES['expense']
    budget_vs_actual = {}
    expenses = get_expenses_by_time_and_user(user_id, month=month, year=year)
    for category in categories:
        budget_amount = get_budget_for_month(current_user, category)
        actual_expense = sum(expense.amount for expense in expenses if expense.category == category)
        budget_vs_actual[category] = {"budget": budget_amount, "actual": actual_expense}
    return budget_vs_actual

#Report Generation Functions

def render_spending_report_with_chart(expenses, template, title, predefined_categories):
    from app import Expense  # Lazy import
    category_data = Expense.aggregate_expenses_by_category(expenses)
    img = generate_spending_chart(category_data)  # Assuming you have this function defined
    img_str = b64encode(img.getvalue()).decode('utf-8')
    return render_template(template, image_data=img_str, title=title, PREDEFINED_CATEGORIES=predefined_categories)

def render_trend_report(trends, template, title, time_period_description, predefined_categories):
    trend_messages = [
        f"For {category}, {time_period_description} the change in spending is {trends[category]:.2f}%"
        for category in trends.keys()
    ]
    return render_template(template, trend_messages=trend_messages, title=title, PREDEFINED_CATEGORIES=predefined_categories)

def calculate_amount_spent(user_id, category):
    from app import Expense  # Lazy import
    current_month, current_year = get_current_month_and_year()
    with current_app.app_context():
        expenses = get_expenses_by_time_and_user(user_id, month=current_month, year=current_year)
    return sum(expense.amount for expense in expenses if expense.category == category)

def check_budget_limit(user_id, category, amount_spent):
    from app import Notification
    current_month, current_year = get_current_month_and_year()
    with current_app.app_context():
        budget = get_existing_budget(user_id, category, current_month, current_year)

    if budget and amount_spent >= 0.75 * budget.budget_amount:
        notify_user(user_id, f"You have reached 75% of your budget in the {category} category.")

    if budget and amount_spent >= 0.75 * budget.budget_amount:
        notify_user(user_id, f"You have reached 75% of your budget in the {category} category.")
def get_expense_frequency(user_id):
    from app import Expense  # Lazy import
    db = get_db()
    expenses = Expense.query.filter_by(user_id=user_id).all()
    categories = [expense.category for expense in expenses]
    frequency = Counter(categories)
    return frequency

def get_most_frequent_categories(user_id):
    from app import Expense  # Lazy import
    frequency = get_expense_frequency(user_id)
    sorted_categories = sorted(frequency.items(), key=lambda x: x[1], reverse=True)
    return sorted_categories


def identify_savings_opportunities(user_id):
    from app import Budget, Expense  # Lazy import
    db = get_db()  # Fetch the database instance
    budget = {}
    actual_spending = {}
    three_months_ago = datetime.utcnow() - relativedelta(months=3)
    three_months_ago_month = three_months_ago.month
    three_months_ago_year = three_months_ago.year

    # Fetching budgets and expenses
    budgets = Budget.query.filter_by(user_id=user_id).filter(
        (Budget.month >= three_months_ago_month) &
        (Budget.year >= three_months_ago_year)
    ).all()
    expenses = Expense.query.filter_by(user_id=user_id).filter(
        Expense.date >= three_months_ago
    ).all()

    for b in budgets:
        budget[b.category] = budget.get(b.category, 0) + b.budget_amount
    for e in expenses:
        actual_spending[e.category] = actual_spending.get(e.category, 0) + e.amount

    # Identify savings opportunities
    savings_opportunities = {}
    for category, budget_amount in budget.items():
        actual_amount = actual_spending.get(category, 0)
        if actual_amount < budget_amount:
            savings_opportunities[category] = budget_amount - actual_amount

    return savings_opportunities

    return savings_opportunities

def send_budget_reminders():
    from app import Budget, Notification, User  # Lazy import
    db = get_db()
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
def generate_spending_chart(data):
    plt.figure(figsize=(10, 6))
    plt.pie(data.values(), labels=data.keys(), autopct='%1.1f%%')
    plt.title("Spending by Category")
    buf = BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    return buf
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
# ... your utility functions ...

def get_db():
    if 'db' not in g:
        g.db = current_app.db
    return g.db

