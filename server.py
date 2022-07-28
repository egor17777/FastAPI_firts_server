import hmac
import hashlib
import base64
import json

from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "a05f2a0015e3b66bb740f1df1e60eef17e0d59f066fa4e1933a1387e475b7986"
PASSWORD_SALT = "768d6ff9470a6befffaade6d0419f4aed7ee0fc008ba7515be7f2bc76cba1b40"


def sign_data(data: str) -> str:
    """Возвращает подписанные данные"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_singed: str) -> Optional[str]:
    try:
        username_base64, sign = username_singed.split(".")
        username = base64.b64decode(username_base64.encode()).decode()
        valid_sign = sign_data(username)
        if hmac.compare_digest(valid_sign, sign):
            return username
    except Exception:
        return None


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()) \
        .hexdigest().lower()
    stored_password_hash=users[username]["password"].lower()
    return password_hash == stored_password_hash



users = {
    'egor@gmail.com': {
        "name": "Егор",
        "password": "44acf8f66152930ba2361ca30a86e4916fe261df7b823befdc1a6a586598e22b",
        "balance": 100_000
    },
    'danil@gmail.com': {
        "name": "Данил",
        "password": "6827217f3e27d92afd53c893fc4716be248ed0a698b049e71c0b5b19f7f2abdf",
        "balance": 150_000
    }
}


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open("templates/login.html", "r") as file:
        login_page = file.read()
    if not username:
        return Response(login_page, media_type="text/html")

    valid_username = get_username_from_signed_string(username)

    if not valid_username:
        responce = Response(login_page, media_type="text/html")
        responce.delete_cookie(key="username")
        return responce
    try:
        user = users[valid_username]
    except KeyError:
        responce = Response(login_page, media_type="text/html")
        responce.delete_cookie(key="username") 
        return responce
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Баланс: {users[valid_username]['balance']}",
        media_type="text/html")


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user:
        return Response(
            json.dumps({
                "success":False,
                "message":"Я вас не знаю"
            }),
            media_type="aplication/json")
    elif not verify_password(username, password):
        return Response(
            json.dumps({
                "success":False,
                "message":"Не верный пароль!"
            }),
            media_type="aplication/json")

    response = Response(
        json.dumps({
                "success":True,
                "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}"
        }),
        media_type="aplication/json")

    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
