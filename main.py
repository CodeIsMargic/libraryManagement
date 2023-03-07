from functools import wraps
import werkzeug.security
from flask_bootstrap import Bootstrap
from flask import Flask, session, render_template, request, url_for, redirect, flash, send_from_directory, abort
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user



app = Flask(__name__)
app.app_context().push()

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    books = relationship("Books", back_populates="reader")
    borrowed_book = relationship("Borrowed", back_populates="borrower")


class Books(db.Model):
    __tablename__ = "books"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    reader = relationship("User", back_populates="books")
    borrowed_book = relationship("Borrowed", back_populates="book_that_was_borrowed")


class Borrowed(db.Model):
    __tablename__ = "borrowed_books"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    book_id = db.Column(db.Integer, db.ForeignKey("books.id"))
    borrower = relationship("User", back_populates="borrowed_book")
    book_that_was_borrowed = relationship("Books", back_populates="borrowed_book")
    title = db.Column(db.String(100), nullable=False)


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route('/add-books', methods=["POST", "GET"])
@login_required
@admin_only
def add_books():
    if request.method == "POST":
        book_title = request.form.get("book_title")
        book_author = request.form.get("author")
        book_quantity = request.form.get("quantity")
        existing_book = db.session.query(Books).filter_by(title=book_title).first()
        if existing_book:
            if (existing_book.title == book_title) and (existing_book.author == book_author):
                existing_book.quantity += int(book_quantity)
                db.session.commit()
                flash("Book added successfully")
                return redirect(url_for("add_books"))
            elif (existing_book.title == book_title) and (existing_book.author != book_author):
                new_book = Books(
                    title=book_title,
                    author=book_author,
                    quantity=book_quantity
                )
                db.session.add(new_book)
                db.session.commit()
                flash("Book added successfully")
                return redirect(url_for("add_books"))
        else:
            new_book = Books(
                title=book_title,
                author=book_author,
                quantity=book_quantity
            )
            db.session.add(new_book)
            db.session.commit()
            flash("Book added successfully")
            return redirect(url_for("add_books"))
    return render_template("add_books.html", logged_in=True)


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/dashboard')
@login_required
def dashboard():
    name = request.args.get("name")
    return render_template("dashboard.html", name=name, logged_in=True, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        user_pass = request.form.get("password")
        user = db.session.query(User).filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, user_pass):
                login_user(user)
                return redirect(url_for("dashboard", name=user.name))
            else:
                flash("Password is incorrect. Please try again")
        else:
            flash("This email does not exist. Please try again")
    return render_template("login.html", logged_in=current_user.is_authenticated, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        users = db.session.query(User).filter_by(email=email).first()
        if users:
            flash("You've already signed in with that email. Log in instead!")
            return redirect(url_for("login"))
        else:
            password = request.form.get("password")
            hash_password = generate_password_hash(
                password=password,
                method="pbkdf2:sha256",
                salt_length=8
            )

            new_user = User(
                email=request.form.get('email'),
                name=request.form.get('name'),
                password=hash_password
            )

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("dashboard", name=new_user.name))
    return render_template("register.html", logged_in=current_user.is_authenticated, current_user=current_user)


@app.route("/books", methods=["POST", "GET"])
@login_required
def books():
    all_books = db.session.query(Books).all()
    return render_template("books.html", all_books=all_books, logged_in=True, current_user=current_user)


@app.route("/borrow/<int:book_id>", methods=["POST", "GET"])
def borrow(book_id):
    book_to_borrow = Books.query.get(book_id)
    book_to_borrow.quantity -= 1
    book_to_borrow_title = book_to_borrow.title
    name = current_user.name

    new_borrowed_book = Borrowed(
        borrower=current_user,
        book_that_was_borrowed=book_to_borrow,
        title=book_to_borrow_title
    )
    db.session.add(new_borrowed_book)
    db.session.commit()
    return redirect(url_for("dashboard", name=name, current_user=current_user))


@app.route("/return/<int:book_id>", methods=["POST", "GET"])
def return_book(book_id):
    name = current_user.name
    book_to_return = Borrowed.query.get(book_id)
    book_returned = db.session.query(Books).get(book_to_return.book_id)
    book_returned.quantity += 1
    db.session.delete(book_to_return)
    db.session.commit()
    return redirect(url_for("dashboard", name=name, current_user=current_user))


@app.route("/borrowed-books", methods=["POST", "GET"])
def book_borrowed():
    global NO_BOOK
    borrowed_books = db.session.query(Borrowed).all()
    return render_template("borrowed_books.html", borrowed_books=borrowed_books, current_user=current_user, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
