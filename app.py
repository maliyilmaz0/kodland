import requests
from flask import Flask, request, render_template, redirect, make_response, jsonify
from datetime import datetime, timedelta
import locale
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, decode_token
import hashlib
import random
from bson import ObjectId

app = Flask(__name__, static_folder='templates')
bcrypt = Bcrypt(app)
locale.setlocale(locale.LC_TIME, 'tr_TR.utf8')
app.config["MONGO_URI"] = "mongodb+srv://kodland:kodland@kodland.tnzp46n.mongodb.net/kodland_asignment"
client = PyMongo(app)
db = client.db
user_collection = db["users"]
sessions_collection = db["sessions"]
questions_collection = db["questions"]

app.secret_key = "maliyilmaz0"
app.config['JWT_SECRET_KEY'] = "maliyilmaz0"  # Güvenli bir JWT anahtarı seçin
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=2)
jwt = JWTManager(app)

weather_api_key = '097404219b06b14c36e05f873d36e019'
weather_api_url = 'https://api.openweathermap.org/data/2.5/weather'


@app.route('/', methods=['GET', 'POST'])
def home_page():
    city = None
    forecasts = []

    if request.method == 'POST':
        city = request.form.get('city')

        if city:
            forecasts = get_3_day_weather_forecast(city)

    return render_template('index.html', city=city, forecasts=forecasts)


def get_3_day_weather_forecast(city):
    api_key = '097404219b06b14c36e05f873d36e019'
    api_url = 'https://api.openweathermap.org/data/2.5/forecast'

    params = {
        'q': city,
        'appid': api_key,
        'units': 'metric'
    }

    response = requests.get(api_url, params=params)
    weather_data = response.json()

    forecasts = []
    current_day = None

    for forecast in weather_data['list']:
        date_str = forecast['dt_txt'].split()[0]
        date = datetime.strptime(date_str, '%Y-%m-%d')
        day_name = date.strftime('%A')

        if day_name != current_day:
            temperature = forecast['main']['temp']
            description = forecast['weather'][0]['description']
            forecasts.append(
                {'date': date_str, 'day_name': day_name, 'temperature': temperature, 'description': description})
            current_day = day_name

    return forecasts[:3]


@app.route("/api/v1/users", methods=["POST"])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if not username or not email or not password:
        return jsonify({'msg': 'Kullanıcı adı, e-posta ve şifre zorunludur'}), 400

    password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

    existing_user = user_collection.find_one({"username": username})
    if existing_user:
        return jsonify({'msg': 'Kullanıcı adı zaten mevcut'}), 409

    new_user = {
        "username": username,
        "email": email,
        "password": password_hash,
        "points": 0
    }
    user_collection.insert_one(new_user)

    return redirect("/login")


@app.route("/api/v1/login", methods=["POST"])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    user_from_db = user_collection.find_one({'email': email})  # search for user in database
    if user_from_db:
        encrpted_password = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if encrpted_password == user_from_db['password']:
            access_token = create_access_token(identity=user_from_db['username'])  # create jwt token

            sessions_collection.insert_one({"username": user_from_db['username'], "access_token": access_token})
            response = make_response(redirect("/dashboard"))
            response.set_cookie("access_token", access_token, httponly=True)

            return response

    return jsonify({'msg': 'The username or password is incorrect'}), 401


@app.route('/login', methods=["GET"])
def loginPage():
    return render_template("login.html")


@app.route('/register', methods=["GET"])
def registerPage():
    return render_template("register.html")


@app.route('/dashboard', methods=["GET", "POST"])
@jwt_required(optional=True)
def dashboard():
    access_token_cookie = request.cookies.get('access_token')
    user_answer = None
    correct_answer = None

    if access_token_cookie:
        try:
            token_data = decode_token(access_token_cookie)
        except Exception as e:
            return redirect('/logout')

        kullanici_adi = token_data['sub']

        user_info = user_collection.find_one({"username": kullanici_adi})
        if not user_info:
            return redirect("/logout")

        user_username = user_info["username"]
        user_points = user_info["points"]
    else:
        return redirect("/logout")

    if request.method == "GET":
        random_question = get_random_question()
    elif request.method == "POST":
        user_answer = request.form.get('answer')
        question_id = request.form.get('question_id')

        if not question_id:
            return jsonify({'msg': 'Sorunun kimliği eksik'}), 400  # 400 Bad Request

        random_question = get_question_by_id(question_id)

        if not random_question:
            return jsonify({'msg': 'Soru bulunamadı veya hata oluştu'}), 500

        if "correct_option" in random_question:
            correct_option = random_question["correct_option"]

            print(user_answer)
            print(random_question)
            if user_answer == random_question["options"][correct_option]:
                print("Yey")
                correct_answer = True
                user_collection.update_one(
                    {"username": kullanici_adi},
                    {"$inc": {"points": 1}}
                )
                redirect('/dashboard')
            else:
                correct_answer = False
                redirect('/dashboard')
            random_question = get_random_question()
    leaderboard = list(user_collection.find().sort("points", -1))
    return render_template('dashboard.html', user_username=user_username, user_points=user_points,
                           question=random_question, user_answer=user_answer, correct_answer=correct_answer,
                           leaderboard=leaderboard)


def get_random_question():
    all_questions = list(questions_collection.find())
    if all_questions:
        random_question_data = random.choice(all_questions)
        return random_question_data
    else:
        return None


def get_question_by_id(question_id):
    try:
        question = questions_collection.find_one({'_id': ObjectId(question_id)})
        if question:
            return question
        else:
            return None
    except Exception as e:
        return None


@app.route('/logout', methods=["GET"])
def logout():
    access_token = request.cookies.get('access_token')
    if access_token:
        sessions_collection.delete_one({"access_token": access_token})
        response = make_response(redirect("/login"))
        response.delete_cookie("access_token")

        return response

    return redirect("/login")


if __name__ == '__main__':
    app.run(debug=True)
