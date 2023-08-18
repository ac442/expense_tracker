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
        source = random.choice(list(categories.keys()))
        min_amount, max_amount = categories[source]
        amount = random.randint(min_amount, max_amount)
        description = random.choice(descriptions)

        # Create a new expense entry
        expense = Expense(date=date, amount=amount, source=source, description=description, user_id=current_user.id)
        db.session.add(expense)

    db.session.commit()
    return "Improved fake data generated successfully!"


@app.route('/clear-expense-data', methods=['GET'])
def clear_expense_data():
    Expense.query.delete()
    db.session.commit()
    return "Expense data cleared!"