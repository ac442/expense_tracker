@app.route('/reports/view_spending_anomalies')
@login_required
def view_spending_anomalies():
    user_id = current_user.id

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
        total_spending = sum(exp.amount for exp in previous_expenses if exp.category == category)
        count = len([exp for exp in previous_expenses if exp.category == category])
        average = total_spending / count if count != 0 else 0
        average_expenses[category] = average

    messages = []
    for category in PREDEFINED_CATEGORIES['expense']:
        current_spending = sum(exp.amount for exp in current_month_expenses if exp.category == category)
        if average_expenses[category] != 0:
            percent_change = ((current_spending - average_expenses[category]) / average_expenses[category]) * 100
            if current_spending > 1.2 * average_expenses[category]:  # 20% more than average
                messages.append(
                    f"Spending on {category} increased by {percent_change:.2f}% compared to the average of previous months.")
            elif current_spending < 0.8 * average_expenses[category]:  # 20% less than average
                messages.append(
                    f"Spending on {category} decreased by {-percent_change:.2f}% compared to the average of previous months.")

    return render_template('view_spending_anomalies.html', messages=messages)


@app.route('/generate-fake-data', methods=['GET'])
def generate_fake_data():
    from datetime import datetime, timedelta
    import random

    # Sample sources and average amounts
    categories = {
        'Housing & Utilities': (500, 1500),
        'Food & Dining': (10, 150),
        'Transport': (5, 50),
        'Personal Care & Lifestyle': (20, 300),
        'Savings': (100, 500),
        'Entertainment': (10, 200),
        'Utilities': (50, 300)
        # Add more categories as needed
    }

    descriptions = [
        "Lunch at restaurant",
        "Monthly rent payment",
        "Bus fare",
        "Grocery shopping",
        "Concert tickets",
        "Utility bill payment",
        "Bought new clothes",
        "Weekend trip"
        # Add more descriptions as needed
    ]

    # Generate data for the past 60 days to add more variability
    for _ in range(60):
        date = datetime.now() - timedelta(days=random.randint(0, 59))
        selected_category = random.choice(list(categories.keys()))
        min_amount, max_amount = categories[selected_category]
        amount = random.randint(min_amount, max_amount)
        description = random.choice(descriptions)

        # Create a new expense entry
        expense = Expense(date=date, amount=amount, category=selected_category, description=description, user_id=current_user.id)
        db.session.add(expense)

    db.session.commit()
    return "Improved fake data generated successfully!"
