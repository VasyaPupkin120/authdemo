""" Начинаем приложение """
# для указания опцинональности кук - могут быть, а могут и не быть
from typing import Optional

# все для создания приложений, обработки данных из форм, кук, из тела запроса
from fastapi import FastAPI, Form, Cookie, Body

# для возможности отсылания ответов в браузер
# Объект Response инкапсулирует в себе ответ. 
from fastapi import Response

# Для подписи кук
import hmac
import hashlib

# Для нормализации электронной почты - чтобы избавиться от точки в адресе
import base64

#для передачи данных в формате json
import json


#Экземпляр нашего приложения
app = FastAPI()

# Ключи, которые стоит хранить в переменных окружения
# Секретный код для подписи кук
SECRET_KEY = "d679301f3106445dc974be3989a38cce462daacc469bcbc77657eb70d34f6950"
# Соль для хэширования паролей 
PASSWORD_SALT = "7c342e6db4a5e905622bb2725d1abaa88c5803f6e8e76ca2cb8834fee3befc84"

# Словарик с паролями вместо нормальной DB
users = {
        "vasya@pupkin.com": {
            "name": "Vasya",
            "password": "eb0864f06eef90afb379f038d20515b7f8f912fd4d4b6842b10f93ccc3983083", #1111
            "balance": 100_000
            }, 
        "petr@utkin.com": {
            "name": "Petr",
            "password": "d3095336ba9153e858783759b313047e268cc94a6d1f7cd3c5c89b0b97e48697", #2222
            "balance": 555_555
            }
}


def password_verification(username: str, password: str) -> bool:
    """
        Проверяет совпдают ли хэш от введеного пароля с солью и хэш,
        хранящийся в словарике.
    """
    input_password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).\
            hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return input_password_hash == stored_password_hash


def sign_data(data: str) -> str:
    """
        Возвращает подписанные данные data
        Возвращает подпись, пригодную для присоединения к username
    """
    return hmac.new(
            SECRET_KEY.encode(),
            msg=data.encode(),
            digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_form_signed_cookie(username_signed: str) -> Optional[str]:
    """
        Вызов этой функции вернет либо корректный email - если подпись верна, либо None.
        Слегка другое имя, чем у Голобурдина - зато точноее.
        Получает username из длинной строки-куки вида 'ddfa1234.dfd3332a'.
        Возвращает Optional() занчение - может оказаться что куки еще просто 
        нет или она неправильная или она для другого пользователя
    """

    # проверка на то, что куку можно разбить по точке
    try: 
        username_base64, sign = username_signed.split(".")
    except ValueError:
        return None

    # проверка на то, что передали куку, закодированную в base64
    try: 
        username = base64.b64decode(username_base64.encode()).decode() # получили юзернейм из куки
    except UnicodeDecodeError:
        return None

    # генерируем правильную подпись для данного юзернейма
    valid_sign = sign_data(username) 

    #сравниваем сгенерированную подись на основе переданного имени и ту, которая была передана от браузера
    if hmac.compare_digest(valid_sign, sign): # если эта функция верент True - значит подписи совпадают и можно вернуть username
        return username # теперь этот username можно использовать для обращения к словарику с паролями. Иначе вернется None


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    """
        Функция, выводящая один из двух вариантов заглавных страничек -
        либо приветствие вернувшемуся юзеру либо страничку ввода пароля.
        Удаляет неверную куку. 
        Просто функция, которая будет обрабатывать http-запрос браузера и отправлять ответ, тело которого - строка. 
        Простая распечатка объекта Response выводит только id объекта, видно не перегружена нормально print()
        Функция вызывается сервером uvicorn.
        Шаблон html странички ввода пароля берется из файла
        Шаблон html странички приветствия - строка: f"Hello, {users[valid_username]['name']}!"
    """
    with open("./templates/login.html", 'r') as html_file:
        login_page = html_file.read()

    # в коде ниже может быть проблема, наша функция-валидатор get_username_form_signed_cookie ждет str, 
    # а ей может быть передано или str или None (так как username:Options()), 
    # поэтому нужно проверить здесь на тип. Кроме того, если куки нет,
    # то и проверять ее нет смысла, не нужно нагружать систему вызовами функций и криптографией
    # как вариант, конечно, настроить функцию-валидатор на прием того ж типа - Optional[str]

    # если нам послали куку, то выделяем из куки имя пользователя
    # если куки нет, то просто отправляем пользователя логиниться 
    if username:
        valid_username = get_username_form_signed_cookie(username) 
    else:
        return Response(login_page, media_type="text/html")

    # если кука есть, то проверяем ее на валидность - формат и верная подиись
    # есл она невалидная, то тоже отпраляем на страничку ввода
    if not valid_username: 
        response =  Response(login_page, media_type="text/html") # если пользователя нет, то пусть логинится
        response.delete_cookie(key="username") # удаляем неправильную куку
        return response

    # проверка, есть ли пользователь, который записан в переданной на сервер куке 
    try:
        user = users[valid_username]
    except: 
        # если пользователя нет, то пусть логинится, удаляем неправильную куку 
        response =  Response(login_page, media_type="text/html") 
        response.delete_cookie(key="username")  
        return response

    # все верно, это вернувшийся юзер, возвращаем ответ, похожий на стандартный ответ после аутентификации
    return Response(
        f"Добро пожаловать, {users[valid_username]['name']}!</br>\
        Ваш баланс {users[valid_username]['balance']} EUR.</br>\
        Кука в вашем браузере верна и позволила сгенерировать эту страничку",
        media_type="text/html") 


@app.post("/login")
def process_login_page(data: dict = Body(...)):
#def process_login_page(username: str = Form(...), password: str = Form(...)): - версия с передачей данных типа FormData
    """
       Устанавливает куку после логина.
       Проверяет наличие логина и пароля в базе, если есть - допускает к сайту.
       Функция, выводящая страничку после логина:
       два варианта, какую страничку может выдать - либо вывод приветствие+вывод баланса - строка.
       либо вывод информации что не аутентифицирован - пароль не верен.
       base64 для email - чтобы избавиться от точки и собаки для удобного сплита по точке.
    """

    # тестовая распечатка данных, полученных в виде json и выделение из него данных по ключам, для дальнейшей работы
    print("data is: ", data)
    username = data["username"]
    password = data["password"]

    # получаем из словаря запись, совпадающую по ключу с переданным логином, или None - если такого ключа нет
    user = users.get(username) 

    # формируем ответ для случая неправильного ввода пароля или логина
    if not user or not password_verification(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Вы кто такие? Я вас не звал! Идите нахрен!"
            }), 
            media_type="application/json")

    # формируем ответ для случая успешной проверки пароля
    response = Response(
            json.dumps({
                "sucess": True,
                "message": f"Добро пожаловать {user['name']}!<br />Ваш баланс: {user['balance']} EUR"
            }),
            media_type="application/json")

    # формируем подпись и вносим эту подпись в куку, общий вид: {username_base64}.{sign_username_sha256} 
    username_signed = \
            base64.b64encode(username.encode()).decode() +\
            "." +\
            sign_data(username) 
    response.set_cookie(key="username", value=username_signed, expires=3600)
    return response
