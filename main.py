#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, make_response, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import DataRequired, Email, EqualTo
from datetime import datetime, timedelta
from flask_login import UserMixin, login_user, LoginManager, logout_user
from gevent.pywsgi import WSGIServer
import os


##################################################
# Setup
##################################################


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///storage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
db = SQLAlchemy(app)


##################################################
# Easy-to-use helper functions
##################################################

# returns the username of the logged-in user
def get_sk():
  return request.cookies.get('devSession')

#returns if the devSession and session cookies are set.  If both are, a user is logged in.
def test_logged_in():
  return request.cookies.get('devSession') and request.cookies.get('remember_token')

#returns the user that is logged in.  The user whose username is equal to the DevSession cookie.
def logged_in():
  return User.query.filter_by(username=request.cookies.get('devSession')).first()

def qlen(q):
    a = 0
    for i in q:
        a += 1
    return a

code2key = {
    "nopoverty":"Reduce the Poverty",
    "zerohunger":"Decrease Hunger",
    "goodhealth":"Empower Health",
    "genderequality":"Gender Equality",
    "cleanwater": "Clean Water & Sanitation",
    "affordableand": "Affordable & Clean Energy",
    "decentwork": "Decent Work & Economic Growth",
    "industryinnovation": "Industry, Innovation, and Infrastructure",
    "reducedinequalities": "Reduced Inequalities",
    "sustainablecities":"Sustainable Cities & Communities",
    "responsibleconsumation": "Responsible Consumption & Production",
    "climateaction": "Climate Action",
    "lifebelow": "Life Below Water",
    "lifeon": "Life on Land",
    "peacejustice": "Peace, Justice, & String Institutions",
    "partnershipsfor": "Partnerships for the Goals",
    "other": "Other"
}
key2code = {
    "Reduce the Poverty":"nopoverty",
    "Decrease Hunger":"zerohunger",
    "Empower Health":"goodhealth",
    "Gender Equality":"genderequality",
    "Clean Water & Sanitation":"cleanwater",
    "Affordable & Clean Energy":"affordableand",
    "Decent Work & Economic Growth":"decentwork",
    "Industry, Innovation, and Infrastructure":"industryinnovation",
    "Reduced Inequalities":"reducedinequalities",
    "Sustainable Cities & Communities":"sustainablecities",
    "Responsible Consumption & Production":"responsibleconsumation",
    "Climate Action":"climateaction",
    "Life Below Water":"lifebelow",
    "Life on Land":"lifeon",
    "Peace, Justice, & String Institutions":"peacejustice",
    "Partnerships for the Goals":"partnershipsfor",
    "Other": "other"
}


##################################################
# Database Models
##################################################

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), index=True, unique=True)
    nickname = db.Column(db.String(50), index=True, unique=True)
    email = db.Column(db.String(100), index=True, unique=True)
    password = db.Column(db.String(100), index=True, unique=True)
    verified = db.Column(db.String(5), index=True, default="false")
    bio = db.Column(db.String(200), index=True, default="I am a person")
    avatar = db.Column(db.Text, index=True, default="https://github.com/Conner1115/lensflare/blob/main/UserImg2.png?raw=true")
    date_joined = db.Column(db.DateTime(), index=True, default=datetime.utcnow)
    has_new = db.Column(db.Integer, index=True, default=0)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, index=True)
    cont = db.Column(db.Text, index=True)
    goals = db.Column(db.Text, index=True)
    need_list = db.Column(db.Text, index=True)
    budget = db.Column(db.Integer, index=True, default=0)
    topic = db.Column(db.Text, index=True)
    contact = db.Column(db.Text, index=True)
    made = db.Column(db.Text, index=True, default=str(datetime.today().date().strftime('%m/%d/%y')))
    authorid = db.Column(db.Integer, index=True)
    likes = db.Column(db.Integer, index=True, default=0)
    bookmarks = db.Column(db.Integer, index=True, default=0)
    author = db.Column(db.Text, index=True)
    comments = db.Column(db.Integer, index=True, default=0)
    status = db.Column(db.Text, index=True, default="just_started")
    author_avatar = db.Column(db.Text, index=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, index=True)
    author = db.Column(db.Text, index=True)
    post_for = db.Column(db.Integer, index=True)
    replies = db.Column(db.Integer, index=True, default=0)
    author_avatar = db.Column(db.Text, index=True)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, index=True)
    author = db.Column(db.Text, index=True)
    comment_for = db.Column(db.Integer, index=True)
    author_avatar = db.Column(db.Text, index=True)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.Text, index=True)
    post_for = db.Column(db.Integer, index=True)

class Bookmark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.Text, index=True)
    post_for = db.Column(db.Integer, index=True)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_from = db.Column(db.Text, index=True)
    user_for = db.Column(db.Text, index=True)
    href = db.Column(db.Integer, index=True)
    text = db.Column(db.Text, index=True)
    read = db.Column(db.Integer, index=True, default=0)

##################################################
# Flask Forms
##################################################

class SignupForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Confirm Password',validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Create Account')

class LoginForm(FlaskForm):
        ue = StringField('username', validators=[DataRequired()])
        password = PasswordField('Password', validators=[DataRequired()])
        submit = SubmitField('Log In')

##################################################
# User Loading and Error Handling
##################################################

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
@login_manager.unauthorized_handler
def unauthorized():
    logout_user()
    resp = make_response(render_template(
        'message.html',
        message="One more step",
        header="Log In First",title="Unauthorized Request"))
    resp.delete_cookie('devSession')
    resp.delete_cookie('session')
    return resp

@app.errorhandler(404)
def page_not_found(error):
    return render_template(
        'message.html',
        title="404 not found",
        header="404",
        message="Not Found", logged_in=logged_in()), 404

##################################################
# Visible Routes
##################################################

@app.route('/')
def index():
    usr = logged_in()
    if usr and test_logged_in():
      resp = make_response(redirect('/user/'+usr.username))
      return resp
    else:
      resp = make_response(render_template("index.html", logged_in=logged_in()))
      resp.delete_cookie('devSession')
      resp.delete_cookie("session")
      resp.delete_cookie("remember_token")
      return resp

@app.route('/thread/<int:id>')
def thread(id):
    cmt = Comment.query.filter_by(id=id).first()
    replies = Reply.query.filter_by(comment_for=id).all()
    author = User.query.filter_by(username=cmt.author).first()
    return render_template("thread.html",comment=cmt,replies=replies,logged_in=logged_in(),author=author)


@app.route('/about')
def about():
    return render_template("about.html", logged_in=logged_in())

@app.route('/new')
def idea_new():
    if test_logged_in():
        return render_template("new.html", logged_in=logged_in())
    else:
        return render_template(
        'message.html',
        message="One more step",
        header="Log In First",title="Unauthorized Request", logged_in=logged_in())

@app.route('/notifications')
def notifs():
    if test_logged_in():
        return render_template("notifpage.html", logged_in=logged_in(), notifs=Notification.query.filter_by(user_for=logged_in().username))
    else:
        return render_template(
        'message.html',
        message="One more step",
        header="Log In First",title="Unauthorized Request", logged_in=logged_in())

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    error = ""
    
    if form.validate_on_submit():
        test_user1 = User.query.filter_by(email=form.email.data).first()
        test_user2 = User.query.filter_by(username=form.username.data).first()
        if test_user1:
            error = "A user with that email address already exists!  Please try again with a different one."
        if test_user2:
            error = "A user with that username already exists.  Please try again with a different one."
        if not test_user1 and not test_user2:
            user = User(username=form.username.data,
                        nickname=form.username.data,
                        password=generate_password_hash(form.password.data),
                        email=form.email.data)
            db.session.add(user)
            db.session.commit()
            return redirect('/login')
    
    return render_template('signup.html', form=form, error=error, logged_in=logged_in())

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = ""
    if form.validate_on_submit():
        test_for_user1 = User.query.filter_by(username=form.ue.data).first()
        test_for_user2 = User.query.filter_by(email=form.ue.data).first()
        if test_for_user1 and not test_for_user2:
            if check_password_hash(test_for_user1.password,
                                   form.password.data):
                login_user(test_for_user1, remember=True, duration=timedelta(days=365))
                resp = make_response(
                    redirect('/user/' + test_for_user1.username))
                resp.set_cookie('devSession', test_for_user1.username, max_age=31536000)
                return resp
            else:
                error = "Incorrect username or password.  Please try again."
        if test_for_user2 and not test_for_user1:
            if check_password_hash(test_for_user2.password,
                                   form.password.data):
                login_user(test_for_user2, remember=True, duration=timedelta(days=365))
                resp = make_response(
                    redirect('/user/' + test_for_user2.username))
                resp.set_cookie('devSession', test_for_user2.username, max_age=31536000)
                return resp
            else:
                error = "Incorrect email or password.  Please try again."
        else:
            error = "That user doesn't seem to exist.  Try again or consider signing up."
    return render_template('login.html', form=form, error=error, logged_in=logged_in())

@app.route('/user/<username>', methods=['GET','POST'])
def profile(username):
    user = User.query.filter_by(username=username).first()
    if user:
        user_logged_in = test_logged_in()
        bms = []
        bmks = Bookmark.query.filter_by(author=user.username).all()
        posts = Post.query.filter_by(author=user.username).all()
        for i in bmks:
            bms.append( Post.query.filter_by(id=i.post_for).first() )
        if user and not user_logged_in:
            return render_template("user.html",user=user, logged_in=False, test_logged_in=test_logged_in(), posts=Post.query.filter_by(author=user.username).all(), bms=False)
        if user and user_logged_in:
            return render_template("user.html",user=user, logged_in=logged_in(), test_logged_in=test_logged_in(), posts=posts, bms=bms)
    if not user:
        return render_template("message.html",
                               message="That user doesn't exist.",
                               title="Uh Oh!", logged_in=logged_in())

@app.route('/post/<int:id>')
def post(id):
    pst = Post.query.filter_by(id=id).first()
    if pst:
        author = User.query.filter_by(id=pst.authorid).first()
        comments = Comment.query.filter_by(post_for=id).all()
        userlk = Like.query.filter_by(post_for=id,author=logged_in().username).first()
        userbm = Bookmark.query.filter_by(post_for=id,author=logged_in().username).first()
        has_liked_post = False
        has_bookmarked_post = False
        if userlk:
            has_liked_post = True
        if userbm:
            has_liked_post = True
        return render_template("post.html",post=pst,author=author, comments=comments, logged_in=logged_in(), has_liked_post=has_liked_post, has_bookmarked_post=has_bookmarked_post)
    else:
        return render_template(
        'message.html',
        title="404 not found",
        header="404",
        message="Post Not Found", logged_in=logged_in()), 404


##################################################
# Form / Action Routes
##################################################

@app.route('/reply/<int:id>', methods=['GET','POST'])
def reply(id):
    pst = Comment.query.filter_by(id=id).first()
    text = request.form['text']
    author = logged_in().username
    comm = Reply(text=text,author=author,comment_for=id, author_avatar=logged_in().avatar)
    db.session.add(comm)
    db.session.commit()
    notif = Notification(user_from=logged_in().username,href="/thread/"+str(id),user_for=pst.author, text=str(logged_in().username)+" Replied to your comment: "+comm.text)
    receiver = User.query.filter_by(username=pst.author).first()
    receiver.has_new = 1
    db.session.add(receiver)
    db.session.commit()
    db.session.add(notif)
    db.session.commit()
    pst.replies = qlen(Reply.query.filter_by(comment_for=id).all())
    db.session.add(pst)
    db.session.commit()
    return redirect('/thread/'+str(id))

@app.route('/postidea',methods=['GET','POST'])
def postidea():
        title = request.form['title']
        cont = request.form['idea']
        goals = request.form['goals']
        need_list = request.form['need-list']
        budget = request.form['budget']
        topic = code2key[request.form['topic']]
        contact = request.form['contact']
        author = logged_in().username
        authorid = logged_in().id
        post = Post(title=title,cont=cont,goals=goals,need_list=need_list,budget=budget,topic=topic,contact=contact, author=author,authorid=authorid, author_avatar=logged_in().avatar)
        db.session.add(post)
        db.session.commit()
        return redirect('/post/'+str(post.id))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie('session')
    resp.delete_cookie('devSession')
    resp.delete_cookie('remember_token')
    logout_user()
    return resp

@app.route('/comment/<int:id>', methods=['GET','POST'])
def comment(id):
    text = request.form['text']
    author = logged_in().username
    comm = Comment(text=text,author=author,post_for=id, author_avatar=logged_in().avatar)
    db.session.add(comm)
    db.session.commit()
    pst = Post.query.filter_by(id=id).first()
    notif = Notification(user_from=logged_in().username,href="/post/"+str(id),user_for=pst.author, text=str(logged_in().username)+" Commented on your post: "+comm.text)
    receiver = User.query.filter_by(username=pst.author).first()
    receiver.has_new = 1
    db.session.add(receiver)
    db.session.commit()
    db.session.add(notif)
    db.session.commit()
    pst.comments = qlen(Comment.query.filter_by(post_for=id).all())
    db.session.add(pst)
    db.session.commit()
    return redirect('/post/'+str(id))

@app.route('/change-status/<int:id>', methods=['GET','POST'])
def changeStatus(id):
    sel = request.form['options']
    pst = Post.query.filter_by(authorid=logged_in().id).first()
    pst.status = sel
    db.session.add(pst)
    db.session.commit()
    return redirect('/post/'+str(id))

@app.route('/like/<int:id>', methods=['GET','POST'])
def like(id):
    pst = Post.query.filter_by(id=id).first()
    lk = Like(author=logged_in().username,post_for=id)
    us = User.query.filter_by(username=pst.author).first()
    ntf = Notification(user_from=logged_in().username, user_for=pst.author, href="/post/"+str(id), text=str(logged_in().username) +" Liked your Post: "+str(pst.title))
    db.session.add(lk)
    db.session.add(ntf)
    db.session.commit()
    totalLikes = qlen(Like.query.filter_by(post_for=id).all())
    pst.likes += totalLikes
    us.has_new = 1
    db.session.add(us)
    db.session.add(pst)
    db.session.commit()
    return redirect('/post/'+str(id))

@app.route('/bm/<int:id>', methods=['GET','POST'])
def bm(id):
    pst = Post.query.filter_by(id=id).first()
    bm = Bookmark(author=logged_in().username,post_for=id)
    ntf = Notification(user_from=logged_in().username, user_for=pst.author, href="/post/"+str(id), text=str(logged_in().username) +" Liked your Post: "+str(pst.title))
    db.session.add(bm)
    db.session.add(ntf)
    db.session.commit()
    totalBookmarks = qlen(Bookmark.query.filter_by(post_for=id).all())
    pst.bookmarks += totalBookmarks
    db.session.add(pst)
    db.session.commit()
    return redirect('/post/'+str(id))

@app.route('/read/<int:id>', methods=['GET','POST'])
def readNotif(id):
    ntf = Notification.query.filter_by(id=id).first()
    usr = User.query.filter_by(username=ntf.user_for).first()
    usr.has_new = 0
    ntf.read = 1
    db.session.add(usr)
    db.session.add(ntf)
    db.session.commit()
    return redirect('/notifications')

@app.route('/browse', methods=['GET','POST'])
def browse():
    psts = False
    ft = False
    filt = request.args.get('filter')
    tp = request.args.get('topic')
    vl = request.args.get('search')
    val = "%"
    if not vl:
        val = "%"
    else:
        val = "%"+str(request.args.get('search'))+"%"
    

    if not filt:
        filt = "new"
    if not tp:
        tp = "all"

    if tp == "all":
        ft = "%"
    else:
        ft = code2key[request.args.get('topic')]

    if filt == "top":
        psts = Post.query.filter(Post.topic.like(ft), Post.title.like(val)).order_by(Post.likes.asc()).all()
    if filt == "new":
        psts = Post.query.filter(Post.topic.like(ft), Post.title.like(val)).all()
    if filt == "alphabetical":
        psts = Post.query.filter(Post.topic.like(ft), Post.title.like(val)).order_by(Post.title.asc()).all()
        


    return render_template("browse.html", logged_in=logged_in(), posts=psts)

##################################################
# Run App, Update Database
##################################################

"""try:
        http_server = WSGIServer(('', 5000), app)
        http_server.serve_forever()
        print("Server up and running at https://localhost:5000")
    except:
        print("Server Failed")"""


if __name__ == "__main__":
    #app.run(debug=True,host="0.0.0.0",port=8080)
    try:
        http_server = WSGIServer(('', 5000), app)
        http_server.serve_forever()
        print("Server up and running at https://localhost:5000")
    except:
        print("Server Failed")