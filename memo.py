from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user, login_required
#パスワードを生成するものとパスワードがあっているか確認するもの
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///memo.db'
#セッションを暗号化するためのキー
#ランダムな値を生成、これがないとエラーが出る
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)
#インスタンス
login_manager = LoginManager()
#ログインマネジャーとアプリを紐づける
login_manager.init_app(app)


class Memo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text(), nullable=False)

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(10), nullable=False, unique=True)
    user_password = db.Column(db.String(256), nullable=False)

#必ずこれを記載する
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#新規登録
@app.route("/",methods=["GET","POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")
    #フォームが入力されたら
    else:
        user_name = request.form.get("user_name")
        user_password = request.form.get("user_password")
        # ユーザー名がすでに存在するか確認
        existing_user = User.query.filter_by(user_name=user_name).first()
        if existing_user:
            return render_template("signup.html", error="このユーザー名は既に使用されています。別の名前を入力してください。")
        #sha256はハッシュ関数で256ビットのハッシュ値を生成する,入力されたuser_passwordをハッシュ化してuser_passwordに格納する
        new_user = User(user_name=user_name,user_password=generate_password_hash(user_password,method="pbkdf2:sha256"))
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    
#ログイン
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    else:
        user_name = request.form.get("user_name")
        #これはプレーンなパスワード
        user_password = request.form.get("user_password")
        #入力されたuser_nameがUserの中のuser_nameと一致するユーザーを取得
        #こっちに入力されているのはハッシュ化されたパスワード
        user = User.query.filter_by(user_name=user_name).first()
        #パスワードが一致するか確認
        if check_password_hash(user.user_password,user_password):
            #2行前のuserをログインさせる
            login_user(user)
            return redirect("/top")
        else:
            #パスワードが一致しない場合はログイン画面に戻る
            return render_template("login.html",error="ユーザー名もしくはパスワードが間違っています")

#ログアウト
@app.route("/logout")
#ログインしていないとログアウト画面にアクセスできないつまり、アクセス制限している
@login_required
def logout():
    logout_user()
    return redirect("/")



@app.route("/top",methods=["GET","POST"])
@login_required
def index():
    if request.method == "GET":
        memos = Memo.query.all()
        return render_template("index.html",memos=memos)
    else:
        title = request.form.get("title")
        content = request.form.get("content")
        new_memo = Memo(title=title,content=content,user_id=current_user.id)

        db.session.add(new_memo)
        db.session.commit()

        return redirect("/top")


@app.route("/create")
@login_required
def create():
    return render_template("create.html")

@app.route("/detail/<int:id>")
@login_required
def detail(id):
    memo = Memo.query.get(id)
    return render_template("detail.html",memo=memo)

@app.route("/update/<int:id>",methods=["GET","POST"])
@login_required
def update(id):
    memo = Memo.query.get(id)
    #updatepage
    if request.method == "GET":
        return render_template("update.html",memo=memo)
    else:
        memo.title = request.form.get("title")
        memo.content = request.form.get("content")
        db.session.commit()
        return redirect("/top")

@app.route("/delete/<int:id>")
@login_required
def delete(id):
    memo = Memo.query.get(id)
    db.session.delete(memo)
    db.session.commit()
    return redirect("/top")


if __name__ == "__main__":
    app.run(debug=True)

