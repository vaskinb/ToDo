from flask import Flask, render_template, request, render_template, redirect, url_for, request, flash, session
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from forms import LoginForm, RegisterForm, CreateForm


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:12345@localhost/tododb'
app.config['SECRET_KEY'] = 'any secret string'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = LoginManager(app)
db.create_all()


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=True)
    password = db.Column(db.String(255), nullable=True)

    # pr = db.relationship('Tasks', backref='users', uselist=False)

    def __repr__(self):
        return f"<users {self.id}>"


@manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(128), nullable=True)
    descriptions = db.Column(db.String(255), nullable=True)
    owner = db.Column(db.String(128), nullable=True)
    # user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f"<tasks {self.id}>"


@app.route("/")
@login_required
def index():
    info = []
    try:
        info = Tasks.query.all()
    except:
        print("DB read error")

    return render_template("index.html", title="Главная", list=info)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = Users.query.filter_by(login=login).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login or password is not correct')
    else:
        flash('Please fill login and password fields')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash('Please, fill all fields!')
        elif password != password2:
            flash('Passwords are not equal!')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = Users(login=request.form['login'], password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login_page'))

    return render_template('register.html', form=form)


@app.route("/create", methods=['GET', 'POST'])
@login_required
def create():
    form = CreateForm()
    task_name = request.form.get('task_name')
    descriptions = request.form.get('descriptions')
    owner = request.form.get('owner')

    if request.method == 'POST':
        if not (task_name or descriptions or owner):
            flash('Please, fill all fields!')
        else:
            new_task = Tasks(task_name=request.form['task_name'], descriptions=request.form['descriptions'],
                             owner=request.form['owner'])
            db.session.add(new_task)
            db.session.commit()

            return redirect(url_for('index'))

    return render_template('create.html', form=form)


@app.route("/delete/<int:task_id>")
def delete(task_id):
    task = Tasks.query.filter_by(id=task_id).first()
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for("index"))


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_page'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)

    return response


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
