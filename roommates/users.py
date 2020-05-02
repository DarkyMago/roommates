from roommates import app
from roommates.helpers import login_required, query_db
from roommates.classes import User

from flask import redirect, url_for, g, request, flash, render_template, session
import bcrypt

@app.route("/users", methods=['GET'])
@login_required
def users():
	user_ids = query_db('SELECT id FROM users ORDER BY id ASC')
	users = []
	for user_id in user_ids:
		temp_user = User(user_id['id'])
		users.append(temp_user)
	return render_template('users.html', users=users, current_id=session.get('id'))


@app.route("/users/add", methods=['GET', 'POST'])
@login_required
def users_add():
	if request.method == 'POST':
		for key, value in request.form.items():
			if value == '':
				flash('Please fill out all the fields.', 'error')
				return render_template('users_add.html', values=request.form)
		g.db.execute('INSERT INTO users (name, login, birthday, password) VALUES (?, ?, ?, ?)', [
				request.form["name"],
				request.form["login"],
				request.form["birthday"],
				bcrypt.hashpw(request.form["password"].encode('utf-8'), bcrypt.gensalt())
			])
		g.db.commit()
		flash('The new user "{}" has been added.'.format(request.form['name']))
	return render_template('users_add.html', values=[])


@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def users_edit(id):
	if request.method == 'POST':
		if session.get('id') != id:
			flash('You cannot edit this user.')
			return redirect(url_for('users'))
		for key, value in request.form.items():
			if value == '' and key != "password" and key != "confirm":
				flash('Please fill out all the fields.', 'error')
				return render_template('users_edit.html', values=request.form)
		if request.form["password"] or request.form["confirm"]:
			if request.form["password"] == request.form["confirm"]:
				g.db.execute('UPDATE users SET password=? WHERE id=?', [
					bcrypt.hashpw(request.form["password"].encode('utf-8'), bcrypt.gensalt()),
					id
				])
			else:
				flash('Both passwords do not match', 'error')
				return render_template('users_edit.html', values=request.form)
		g.db.execute('UPDATE users SET name=?, login=?, birthday=? WHERE id=?', [
				request.form["name"],
				request.form["login"],
				request.form["birthday"],
				id
			])
		g.db.commit()
		flash('User "' + request.form['name'] + '" updated.')
		return redirect(url_for('users'))

	else:
		user = query_db('SELECT * FROM users WHERE id = ?', [id], one=True)
		if user:
			return render_template('users_edit.html', values=user)
		else:
			abort(404)


@app.route("/remove_user/<id>", methods=['GET'])
@login_required
def remove_user(id):
	user = query_db('SELECT id from users WHERE id = ?', [id], one = True)
	if user:
		g.db.execute('DELETE FROM users WHERE id = ?', [id])
		g.db.commit()
		flash('The user has been deleted.')
	else:
		flash('No user with this id.', 'error')
	return redirect(url_for('users'))
