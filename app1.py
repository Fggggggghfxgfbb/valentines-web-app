import base64
from datetime import datetime

from flask import Flask, render_template, url_for, redirect, request
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators, TextAreaField, HiddenField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import os


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secretkey'
app.config['file_extensions'] = ['.jpeg', '.jpg', '.png']
app.config['MAX_CONTENT_LENGTH'] = 4472*4472
pfp = "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"

dbs = SQLAlchemy(app)
bcrypt = Bcrypt(app)

loginmanager = LoginManager()
loginmanager.init_app(app)
loginmanager.login_view = "login"


@loginmanager.user_loader
def loaduser(user_id):
    return User.query.get(int(user_id))


class User(dbs.Model, UserMixin):
    id = dbs.Column(dbs.Integer, primary_key=True)
    username = dbs.Column(dbs.String(20), nullable=False, unique=True)
    password = dbs.Column(dbs.String(80), nullable=False)
    pfp = dbs.Column(dbs.Text, nullable=False)


class Comment(dbs.Model, UserMixin):
    id = dbs.Column(dbs.Integer, primary_key=True)
    comment = dbs.Column(dbs.String(50), nullable=False)
    postdate = dbs.Column(dbs.DateTime, nullable=False)
    pfp = dbs.Column(dbs.Text, nullable=False)
    pname = dbs.Column(dbs.String(20), nullable=False)
    post_id = dbs.Column(dbs.Integer, dbs.ForeignKey('post.id'))

class Post(dbs.Model):
    id = dbs.Column(dbs.Integer, primary_key=True)
    caption = dbs.Column(dbs.String(75), nullable=False)
    data = dbs.Column(dbs.Text, nullable=False)
    pdata = dbs.Column(dbs.Text, nullable=False)
    pname = dbs.Column(dbs.String(20), nullable=False)
    postdate = dbs.Column(dbs.DateTime, nullable=False)
    comments = dbs.relationship('Comment', lazy='dynamic')


with app.app_context():
    dbs.create_all()

class commentform(FlaskForm):
    comment = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Comment..."})
    postid = StringField()
    submit = SubmitField("comment")

class Registerform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validusername(self, username):
        existingusername = User.query.filter_by(username=username.data).first()

        if existingusername:
            raise ValidationError("username already exist you cant use this soz")


class Postform(FlaskForm):
    caption = TextAreaField(validators=[InputRequired(), Length(min=4, max=50)],
                            render_kw={"placeholder": "Enter a caption"})
    submit = SubmitField("Post")



class Loginform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


@app.route('/')
def home():
    return render_template("home.html")


@app.route("/post", methods=['GET', 'POST'])
@login_required
def postpage():
    if request.method == 'POST':
        uploadedfile = request.files['file']
        caption = request.form['caption']

        filename = uploadedfile.filename
        if filename != "":
            file_ext = os.path.splitext(filename)[1]
            if file_ext not in app.config['file_extensions']:
                return redirect(url_for('postpage'))
            else:
                data = base64.b64encode(uploadedfile.read()).decode()
                newpost = Post(caption=caption, data=data,  pdata=current_user.pfp,
                               pname=current_user.username, postdate=datetime.now().replace(microsecond=0))
                dbs.session.add(newpost)
                dbs.session.commit()
                return redirect(url_for('index'))

    return render_template("post.html")

@app.route("/index/<username>", methods=['GET', 'POST'])
@login_required
def index1(username):
    posts = Post.query.filter_by(pname=username)
    pfp1 = User.query.filter_by(username=username).first()
    form = commentform()
    username = username
    if request.method == 'POST':
        if form.validate_on_submit():
            post_id = form.postid.data
            #idiij = post_id
            comment = Comment(comment=form.comment.data,
                              postdate=datetime.now().replace(microsecond=0),
                              pfp=current_user.pfp, pname=current_user.username,
                              post_id=post_id)
            dbs.session.add(comment)
            dbs.session.commit()
            return redirect(url_for('index1'))

    comments = Comment.query.order_by(Comment.postdate.desc())

    return render_template('acc.html', posts=posts, form=form, comments=comments, username=username, pfp1=pfp1)


@app.route("/index", methods=['GET', 'POST'])
@login_required
def index():
    posts = Post.query.order_by(Post.postdate.desc())
    form = commentform()
    idiij = 0
    if request.method == 'POST':
        if form.validate_on_submit():
            post_id = form.postid.data
            #idiij = post_id
            comment = Comment(comment=form.comment.data,
                              postdate=datetime.now().replace(microsecond=0),
                              pfp=current_user.pfp, pname=current_user.username,
                              post_id=post_id)
            dbs.session.add(comment)
            dbs.session.commit()
            return redirect(url_for('index'))

    comments = Comment.query.order_by(Comment.postdate.desc())
    return render_template('index.html', posts=posts, form=form, comments=comments)


@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        uploadedfile = request.files['file']


        filename = uploadedfile.filename
        if filename != "":
            file_ext = os.path.splitext(filename)[1]
            if file_ext not in app.config['file_extensions']:
                return redirect(url_for('profile'))
            else:
                data = base64.b64encode(uploadedfile.read()).decode()
                current_user = data
                dbs.session.commit()

                return redirect(url_for('profile'))

    return render_template('profile.html', pfp1=pfp)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = Loginform()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)

                return redirect(url_for('index'))
    return render_template("login.html", form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = Registerform()
    if form.validate_on_submit():
        hashedpassword = bcrypt.generate_password_hash(form.password.data)

        newuser = User(username=form.username.data, password=hashedpassword, pfp= pfp)
        dbs.session.add(newuser)
        dbs.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html", form=form)


@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


app.run(debug=True, port=8000)
