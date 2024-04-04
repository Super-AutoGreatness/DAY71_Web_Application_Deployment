
from flask import Flask, abort, render_template, redirect, url_for, flash, g, request                
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
# from flask_gravatar import Gravatar                   
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, LoginForm, RegisterForm, CommentForm               # Import your forms from the forms.py
import datetime
import os
from dotenv import load_dotenv, find_dotenv
import smtplib
from functools import wraps
from hashlib import md5


env_path = find_dotenv()
load_dotenv(env_path)

MY_EMAIL = os.getenv("MY_EMAIL")
PASSWORD = os.getenv("PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")
MY_NAME = "Auto-Greatness"



app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)


# TASK: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE DATABASE BLUEPRINT
class Base(DeclarativeBase):
    pass

# CHOOSE DB ENGINE, CHOOSE DB, INITIALIZE DB
# NOTE: Make sure you've logged out of any active session before deleting the database. Or, alternatively, clear your browser's cache. To avoid a 404 error from the webpage.
# I meant log out of any active session, RE: DAY69, 532-Creating Relational Databases. This part of the lesson: ``Restart your server and register a new admin user.``
# Second alternatively, start a new browser in in-cognito mode. Do this after deleting a database in order to avoid a 404 error.
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DB_URI")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE A USER TEMPLATE TABLE FOR ALL YOUR REGISTERED USERS. 
# THEN: Modify the class ``User(UserMixin, db.Model)``  and ``class BlogPost(db.Model)`` code to create a bidirectional One-to-Many relationship between the two tables.
#  The `User` class is the parent class, and the `BlogPost` class is the child class.
# The `back_populates` parameter specifies the name of the attribute in the BlogPost class that will hold the reference to the `User` object.
class User(UserMixin, db.Model):
    __tablename__ = "users"    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    email: Mapped[str] = mapped_column(String(250), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    posts: Mapped[list["BlogPost"]] = relationship("BlogPost", back_populates="author")   # THIS IS THE MODIFICATION.
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="comment_author")
    
    
# CREATE A BLOGPOST TEMPLATE TABLE IN DATABASE.
# THEN: Modify the class ``User(UserMixin, db.Model)``  and ``class BlogPost(db.Model)`` code to create a bidirectional One-to-Many relationship between the two tables.
# The 'users.id' string in ``ForeignKey("users.id")`` is acting as a namespace or identifier for the id column in any created User table object.
# Also the database table name for the User class is 'users'. As seen above here:  __tablename__ = "users" 
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False) 
    author: Mapped["User"] = relationship("User", back_populates="posts")    # THIS IS THE MODIFICATION.   
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))      # THIS IS THE MODIFICATION.
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="parent_post")
  
    
# TASK: CREATE A COMMENT MODEL IN THE DATABASE.
# Then create a bidirectional One-to-Many relationship between the 3 tables(User, BlogPost, Comment).
# Again, ForeignKey is like saying: this person(user AKA author_id) is the one who wrote the comment. And this is the post(using the post_id as an identifier) they commented on. 
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    comment_author = relationship("User", back_populates="comments")
    parent_post = relationship("BlogPost", back_populates="comments")
    

with app.app_context():
    db.create_all()
    
    # I added this lines below to create a table afer I deleted the old blog database(which deleted all the blog_posts and users table). If not, the webpage will throw a 404 error.
        # new_user = User(name="Admin2", email="admin2@admin.com", password=generate_password_hash("admin123", method='pbkdf2:sha256', salt_length=8))
        # db.session.add(new_user)
        # db.session.commit()



# TASK: Use Werkzeug to hash the user's password when creating a new user. Then log in the new user and redirect them to the home page.
# CODING LESSON: 
"""
# `` new_user = User(name=request.form['name'], email=request.form['email'], password=hashed_salted_password) ``
VERSUS    
# `` new_user = User(name=form.name.data, email=form.email.data, password=hashed_salted_password) ``
"""
# See answer to the coding lesson at the bottom of this page.
# CODING LESSON: See, how flash message works, at the bottom of this page.
@app.route('/register', methods=["GET", "POST"])
def register():
    registration_form = RegisterForm()
    
    if registration_form.validate_on_submit():       
        user = db.session.execute(db.select(User).where(User.email == registration_form.email.data)).scalar()
        if user:
            flash("This email is already associated with an account. Please log in instead.")
            return redirect(url_for('login')) 
               
        hashed_salted_password = generate_password_hash(registration_form.password.data, method='pbkdf2:sha256', salt_length=8)  
              
        new_user = User(name=registration_form.name.data, email=registration_form.email.data, password=hashed_salted_password)
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        
        return redirect(url_for('get_all_posts'))
             
    return render_template("register.html", form=registration_form)
    


# TASK: Retrieve a user from the database based on their email. 
# CODING LESSON: If the forms(LoginForm, RegistrationForm etc) have the ``validators=[DataRequired()]`` in their class definition, 
# we must use the ``validate_on_submit()`` method in the function definition. This applies to all/any function(s) that uses the form.
@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    
    if login_form.validate_on_submit():        
        password = login_form.password.data
        user = db.session.execute(db.select(User).where(User.email == login_form.email.data)).scalar()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    
    return render_template("login.html", form=login_form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# TASK: Add Gravatar to the comment section.
# Gravatar allows you to change the image that you use across the blog websites.
    # gravatar = Gravatar(app, size=50, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


def gravatar_url(email, size=100, rating='g', default='retro', force_default=False):
    hash_value = md5(email.lower().encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{hash_value}?s={size}&d={default}&r={rating}&f={force_default}"


# TASK: Allow only logged-in users to comment on posts.
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):                
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm() 
    
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            submitted_comment = Comment(text=comment_form.comment.data, comment_author=current_user, parent_post=requested_post)
            db.session.add(submitted_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for('login')) 
    
    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form, gravatar_url=gravatar_url)


# TASK: Design an admin-only decorator that redirects the user to the login page if they are not logged in.
# This is similar to flask_login's @login_required decorator.
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


# TASK: create a new function called ``add_new_post()`` that will be used to create a new blog post. ALso, use a decorator so only an admin user can create a new post.
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=datetime.datetime.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    
    return render_template("make-post.html", form=form, current_user=current_user)


# TASK: Create a route so that one can edit a post. Use `edit_post()` to change an existing blog post. Also, use a decorator so only an admin user can edit a post. 
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(title=post.title, subtitle=post.subtitle, img_url=post.img_url, author=post.author, body=post.body)
    
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# TASK: Use ``delete_blogpost()`` to remove a blog post from the database. Also, use a decorator so only an admin user can delete a post.
@app.route("/delete/<int:post_id>", methods=["GET", "POST"])
@admin_only
def delete_blogpost(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


# Instead of creating a custom decorator. The decorator provided by flask is used. 
# ``g`` is a flask global object named `g` where you store information about the current user(amidst other capabilities of g as a flask session object).
@app.before_request
def add_current_year_and_name():
    g.current_year = datetime.datetime.now().year
    g.my_name = MY_NAME


@app.route("/contact", methods=["GET", "POST"])
def contact():
    success = False
    if request.method == "POST":
        
        user_name = request.form["name"]                
        user_email = request.form["email"]
        user_phone = request.form["phone"]
        user_message = request.form["message"]
                       
        success = True
        
        send_email(user_name, user_email, user_phone, user_message)
        
    return render_template(
        "contact.html", 
        name=user_name if success else None, 
        email=user_email if success else None, 
        phone=user_phone if success else None, 
        message=user_message if success else None,
        success=success,
        this_year=g.current_year, 
        my_name=g.my_name,
        current_user=current_user,
        )
    
    
def send_email(name, email, phone, message):
    email_message = f"Subject:Flask with Bootstrap Tutorial\n\nName: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"   
    
    with smtplib.SMTP_SSL("smtp.gmail.com") as email_connection:        
        email_connection.login(user=MY_EMAIL, password=PASSWORD)
        email_connection.sendmail(from_addr=MY_EMAIL, to_addrs=RECEIVER_EMAIL, msg=email_message)






if __name__ == "__main__":
    app.run(debug=False)












# NOTE:
# CODING LESSON EXPLANATION:
""" 
The difference between the two lines of code lies in how the data is being accessed from the form.

In the first line: ``new_user = User(name=request.form['name'], email=request.form['email'], password=hashed_salted_password)``, 
you’re directly accessing the form data sent in the HTTP request(data submitted from an HTML form). 
This is a part of Flask’s request object, which contains the data sent by the client(via the browser).

In the second line: ``new_user = User(name=form.name.data, email=form.email.data, password=hashed_salted_password)``, 
you’re accessing the data through the ``registration_form`` instance of RegisterForm(). 
Here, ``registration_form.name.data`` and ``registration_form.email.data`` are accessing the data that the user inputted into the name and email fields of the registration form.

Both methods are used to achieve the same result, but the way they access the data differs. 
The second method is more commonly used when you’re using Flask-WTF or Flask-Form, where form validation and CSRF protection are handled automatically. 
The first method is a more “raw” way of handling form data and doesn’t provide these additional features. It’s important to choose the method that best fits your application’s needs.

"""


# NOTE:
# How flash message works.
# How come the flash message: `flash("This email is already associated with an account. Please log in instead.")` only shows up in the login route i.e. login.html?
""" 
Flash messages in Flask are stored in a session until they are popped (i.e., shown to the user). 
When you redirect to another route, the flashed message goes with the session. 
So, the message will appear wherever you render your flashed messages in the HTML of the next route you redirect to.

Though the message is coded in the register route, The flash message will show up in the login route because after flashing the message, 
you’re redirecting the user to the login route with return redirect(url_for('login')).
"""


# NOTE:
# ``current_user`` is an object that contains information about the current user.
""" 
Everytime you call render_template(), you pass the current_user over to the template.
This will mean the nav bar will always show the correct options.
current_user.is_authenticated will be True if they are logged in/authenticated after registering.
You can check for this is header.html
"""