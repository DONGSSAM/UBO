from flask import Flask, render_template, request, Response, url_for, redirect, session, jsonify
from datetime import datetime
import sys, bcrypt, qrcode
from db import users, check_connection, rules, chat_rooms
from bson.objectid import ObjectId

app = Flask(__name__)

app.config['SECRET_KEY'] = "your-very-secret-key"

# github test

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
        session["role"] = user.get("role")
        print("로그인 시 username:", username)
        # chat_rooms에서 해당 유저의 approved 상태 확인
        chat_rooms_list = user.get("chat_rooms", [])
        approved = True
        for room_name in chat_rooms_list:
            chat_room = chat_rooms.find_one({"admin_name": room_name})
            if chat_room:
                user_info = next((u for u in chat_room.get("users", []) if u.get("username") == username), None)
                if user_info and not user_info.get("approved", False):
                    approved = False
                    break

        if not approved:
            print("승인 대기중인 사용자:", username)
            return render_template("standby.html")
        return redirect(f"/chat")
    else:
        return render_template("login.html", login_failed=True)

@app.route("/signup_user")
def signUpUser():
    return render_template('signup_user.html')

@app.route("/signup_admin")
def signUpAdmin():
    return render_template('signup_admin.html')

@app.route("/signup_admindata", methods=["POST"])
def register_admin():
    username = request.form["username"]
    password = request.form["password"]
    role = request.form.get("role")

    if users.find_one({"username": username}):
        return jsonify(success=False, message="이미 존재하는 아이디입니다.")    

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    users.insert_one({
        "username": username,
        "password": hashed_pw,
        "created_at": datetime.utcnow(),
        "role": role,
        "approved": True,
    })

    if role == "admin":
        chat_rooms.insert_one({
            "name": f"{username}의 채팅방",
            "admin_name": username,
            "created_at": datetime.utcnow(),
            "point": 5000,
            "users": [],
            "rules": []
        })

    return jsonify(success=True, redirect=url_for("logIn"))

@app.route("/signup_userdata", methods=["POST"])
def register_user():
    username = request.form["username"]
    password = request.form["password"]
    admin = request.form["admin"]
    role = request.form.get("role")

    if users.find_one({"username": username}):
        return jsonify(success=False)    

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    users.insert_one({
        "username": username,
        "password": hashed_pw,
        "created_at": datetime.utcnow(),
        "role": role,
        "chat_rooms": [admin]
    })
    chat_rooms.update_one(
        {"admin_name": admin},
        {"$push": {"users": {"username": username, "point": 500, "approved": False}}}
    )
    return jsonify(success=True, redirect=url_for("logIn"))

#아이디가 중복되는지 확인하는 코드
@app.route("/check_username", methods=["POST"])
def check_username():
    username = request.form["username"]
    exists = users.find_one({"username": username}) is not None
    return jsonify(exists=exists)

@app.route("/catchpokemon", methods=["POST"])
def catch_pokemon():
    data = request.get_json()#채팅방 정보에서 username amount admin를 json형태로 받음
    username = data["username"]
    amount = data["amount"]
    admin = data.get("admin")  # 어떤 채팅방(관리자)에서 포인트를 변경할지 프론트에서 전달해야 함

    chat_room = chat_rooms.find_one({"admin_name": admin})
    if not chat_room:
        return {"success": False, "message": "채팅방 없음"}, 404

    user_info = next((u for u in chat_room.get("users", []) if u.get("username") == username), None)
    if not user_info:
        return {"success": False, "message": "관리자는 던질 수 없어."}, 404

    current_point = user_info.get("point", 0)
    if current_point + amount < 0:
        return {"success": False, "message": "포인트가 부족해."}, 400

    # users 배열에서 해당 유저의 포인트 업데이트
    chat_rooms.update_one(
        {"admin_name": admin, "users.username": username},
        {"$inc": {"users.$.point": amount}}
    )
    return {"success": True, "new_point": current_point + amount}
    
    
@app.route("/chat")
def chat_redirect():
    session_username = session.get("username")
    role = session.get("role")

    if not session_username:
        return redirect("/")

    user = users.find_one({"username": session_username})
    if not user:
        return redirect("/")

    room_name = get_room_name(user, role, session_username)
    if not room_name:
        return "채팅방이 없습니다. 관리자에게 문의하세요.", 403

    # 최종적으로 같은 주소로 이동
    return redirect(f"/chat/{room_name}")


@app.route("/chat/<room_name>")
def chat_app(room_name):
    session_username = session.get("username")
    role = session.get("role")

    if not session_username:
        return redirect("/")

    user = users.find_one({"username": session_username})
    if not user:
        return redirect("/")
    room_name = get_room_name(user, role, session_username)
    if not room_name:
        return "채팅방이 없습니다. 관리자에게 문의하세요.", 403
    
    chat_room = chat_rooms.find_one({"admin_name": room_name})
    point = 0
    if role =="admin":
        point = chat_room.get("point", 0) if chat_room else 0
    elif role =="user":
        if chat_room:
            user_info = next((u for u in chat_room.get("users", []) if u.get("username") == session_username), None)
            if user_info:
                point = user_info.get("point", 0)

    return render_template("chat.html", 
                           username=session_username, 
                           point=point, 
                           role=role, 
                           room_name=room_name)

def get_room_name(user, role, session_username):
    if role == "admin":
        return session_username
    elif role == "user":
        chat_rooms_list = user.get("chat_rooms", [])
        if not chat_rooms_list:
            return None
        return chat_rooms_list[0]
    else:
        return "권한 없음", 403

@app.route('/get_approve_users')
def get_approve_users():
    admin = request.args.get("admin")
    chat_room = chat_rooms.find_one({"admin_name": admin})
    # 조건: admin 필드가 현재 관리자 username이고, approved가 False인 유저만
    user_list = []
    for user in chat_room.get("users", []):
        if not user.get("approved", False):
            user_list.append({
                "username": user["username"],
                "point": user.get("point", 0)
            })
    return jsonify(user_list)

@app.route('/approve_user', methods=['POST'])
def approve_user():
    data = request.get_json()
    username = data.get('username')
    admin = data.get('admin')
    if not username or not admin:
        return jsonify(success=False, message="username 또는 admin 없음"), 400

    result = chat_rooms.update_one(#채팅방 데이터에서 approved 수정
        {"admin_name": admin, "users.username": username},
        {"$set": {"users.$.approved": True}}
    )
    if result.modified_count == 1:
        return jsonify(success=True)
    else:
        return jsonify(success=False, message="승인 실패")

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
    users.update_one({"username": from_user}, {"$inc": {"point": -amount}})
    users.update_one({"username": to_user}, {"$inc": {"point": amount}})
    new_point = sender["point"] - amount

    return jsonify(success=True, message=f"{to_user}님에게 {amount}포인트를 전달했어요!", new_point=new_point)

@app.route("/give_score", methods=["POST"])
def give_score():
    data = request.get_json()
    rule_id = data.get("ruleId")
    user_id = data.get("userId")

    if not rule_id or not user_id:
        return jsonify(success=False, message="잘못된 요청"), 400

    # 규칙에서 score 가져오기
    rule = rules.find_one({"_id": ObjectId(rule_id)})
    if not rule:
        return jsonify(success=False, message="규칙을 찾을 수 없음"), 404

    score = rule.get("score", 0)

    # 유저에게 점수 부여
    result = users.update_one(
        {"_id": ObjectId(user_id)},
        {"$inc": {"point": score}}
    )

    if result.modified_count == 1:
        return jsonify(success=True, score=score)
    else:
        return jsonify(success=False, message="유저 점수 업데이트 실패"), 400

@app.route("/add_rule", methods=["POST"])
def add_rule():
    data = request.get_json()
    content = data.get("content", "").strip()
    try:
        score = int(data.get("score", 0))
    except (TypeError, ValueError):
        score = 0
    admin_name = session.get("username")

    if content:
        rule_doc = {
            "content": content,
            "score": score,
            "created_at": datetime.utcnow()
        }
        result = rules.insert_one(rule_doc)#관리자 유저 이름 기반으로 채팅방 나누고 관리자마다 관리하는 학생, 채팅방 규칙 데이터베이스에 저장하기
        rule_id = str(result.inserted_id)
        rule_doc["_id"] = rule_id

        chat_rooms.update_one(
            {"admin_name": admin_name},
            {"$push": {"rules": rule_doc}}
        )
        return jsonify(success=True, id=rule_id, rule=rule_doc)
    return jsonify(success=False, message="빈 규칙입니다.")

@app.route("/get_rules")
def get_rules():
    rule_list = list(rules.find({}, {"_id": 1, "content": 1, "score": 1}))
    for r in rule_list:
        r['_id'] = str(r['_id'])
    return jsonify(rule_list)

@app.route("/update_rule", methods=["POST"])
def update_rule():
    data = request.get_json()
    rule_id = data.get("id")
    new_content = data.get("content", "").strip()
    new_score = data.get("score")

    if not rule_id or not new_content:
        return jsonify(success=False, message="ID와 내용은 필수입니다.")

    update_fields = {"content": new_content}

    # 점수가 None이 아니고 숫자라면 같이 업데이트
    if new_score is not None:
        try:
            update_fields["score"] = float(new_score)
        except ValueError:
            return jsonify(success=False, message="점수는 숫자여야 합니다.")

    result = rules.update_one(
        {"_id": ObjectId(rule_id)},
        {"$set": update_fields}
    )

    if result.modified_count > 0:
        return jsonify(success=True)
    else:
        return jsonify(success=False, message="수정 실패 또는 변경 사항 없음")

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

@app.route('/get_users')
def get_users():
    # MongoDB에서 username과 id만 가져오기
    user_list = list(users.find({"role": "user"}, {"_id": 1, "username": 1}))  # _id는 ObjectId라 필요하면 str로 변환
    # ObjectId를 문자열로 변환
    for user in user_list:
        user["id"] = str(user["_id"])
        del user["_id"]
    return jsonify(user_list)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
