from flask import Flask, render_template, request, Response, url_for, redirect, session, jsonify
from datetime import datetime
import sys, bcrypt
from db import users, check_connection, rules
from bson.objectid import ObjectId

app = Flask(__name__)

app.config['SECRET_KEY'] = "your-very-secret-key"

check_connection()
@app.route("/")
def logIn():
    return render_template('login.html')

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    user = users.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        session["username"] = username
        print("로그인 시 username:", username)
        return redirect("/chat")
    else:
        return render_template("login.html", login_failed=True)

@app.route("/signup")
def signUp():
    return render_template('signup.html')

@app.route("/signupdata", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    users.insert_one({
        "username": username,
        "password": hashed_pw,
        "created_at": datetime.utcnow(),
        "point": 500
    })
    return redirect(url_for("logIn"))

@app.route("/catchpokemon", methods=["POST"])
def catch_pokemon():
    data = request.get_json()
    username = data["username"]
    amount = data["amount"]
    user = users.find_one({"username": username})
    if not user:
        return {"success": False, "message": "사용자 없음"}, 404

    current_point = user.get("point", 0)
    if current_point + amount < 0:
        return {"success": False, "message": "포인트가 부족해."}, 400
    users.update_one(
        {"username": username},
        {"$inc": {"point": amount}}
    )
    return {"success": True, "new_point": current_point + amount}
    
    
@app.route("/chat")
def chat_app():
    username = session.get("username", None)
    print("채팅방 입장 시 username:", username)
    if username is None:
        return redirect("/")
    user = users.find_one({"username": username})
    point = user.get("point", 0)
    return render_template("chat.html", username=username, point=point)

@app.route("/give_point", methods=["POST"])
def give_point():
    data = request.get_json()
    to_user = data.get("to")
    from_user = session.get("username")
    amount = data.get("amount", 0)
    if not from_user or not to_user or amount <= 0:
        return jsonify(success=False, message="잘못된 요청이야.")

    if from_user == to_user:
        return jsonify(success=False, message="자기 자신에게는 줄 수 없어")

    sender = users.find_one({"username": from_user})
    receiver = users.find_one({"username": to_user})

    if not receiver:
        return jsonify(success=False, message=f"{to_user} 님은 없어.")

    if sender["point"] < amount:
        return jsonify(success=False, message="포인트가 부족합니다.")

    # 포인트 이동
    users.update_one({"username": from_user}, {"$inc": {"point": amount}})
    users.update_one({"username": to_user}, {"$inc": {"point": amount}})
    new_point = sender["point"] - amount

    return jsonify(success=True, message=f"{to_user}님에게 {amount}포인트를 전달했어요!", new_point=new_point)

@app.route("/add_rule", methods=["POST"])
def add_rule():
    data = request.get_json()
    content = data.get("content", "").strip()
    if content:
        rules.insert_one({
            "content": content,
            "created_at": datetime.now()#관리자 유저 이름 기반으로 채팅방 나누고 관리자마다 관리하는 학생, 채팅방 규칙 데이터베이스에 저장하기
        })
        return jsonify(success=True)
    return jsonify(success=False, message="빈 규칙입니다.", id=rules["_id"])

@app.route("/get_rules")
def get_rules():
    rule_list = list(rules.find({}, {"_id": 1, "content": 1}))
    for r in rule_list:
        r['_id'] = str(r['_id'])
    return jsonify(rule_list)

@app.route("/update_rule", methods=["POST"])
def update_rule():
    data = request.get_json()
    rule_id = data["id"]
    new_content = data["content"]

    result = rules.update_one(
        {"_id": ObjectId(rule_id)},
        {"$set": {"content": new_content}}
    )

    return jsonify({"success": result.modified_count == 1})

@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    data = request.get_json()
    rule_id = data.get('id')
    if not rule_id:
        return jsonify({'success': False, 'message': 'ID 없음'}), 400

    result = rules.delete_one({'_id': ObjectId(rule_id)})
    if result.deleted_count == 1:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': '삭제 실패'})


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
