# Define the database operation as a separate function
def add_new_expense():
    expense = Expense(
        category=form.category.data,
        amount=form.amount.data,
        description=form.description.data or None,
        user_id=current_user.id,
        is_recurring=form.is_recurring.data,
        recurring_frequency=form.recurring_frequency.data if form.is_recurring.data else None
    )
    db.session.add(expense)

# Use handle_db_operation to execute the operation and handle errors
if form.validate_on_submit():
    if handle_db_operation(add_new_expense, 'added', 'Expense'):
        return redirect(url_for('view_expenses')), 201  # Created