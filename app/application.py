from flask import Flask, render_template, request, Response, url_for, redirect, session, jsonify
from datetime import datetime
from flask_socketio import SocketIO, emit
import sys, bcrypt, qrcode
from db import users, check_connection,  chat_rooms
from bson.objectid import ObjectId

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

app.config['SECRET_KEY'] = "your-very-secret-key"

# 계정관련 코드

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
        "role": role
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

#유저 관련 코드

#아이디가 중복되는지 확인하는 코드
@app.route("/check_username", methods=["POST"])
def check_username():
    username = request.form["username"]
    exists = users.find_one({"username": username}) is not None
    return jsonify(exists=exists)  
    
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

@app.route('/approve_user', methods=['POST'])#//한 번 거절하면 ban되는 기능 추가해야함
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
    
@app.route('/get_users') #점수부여할 유저 리스트 가져오기
def get_users():
    admin_name = session.get("username") #현재 로그인한 관리자 이름
    chat_room = chat_rooms.find_one(
        {"admin_name": admin_name},
        {
            "users": {
                "$filter": {
                    "input": "$users",
                    "as": "user",
                    "cond": {"$eq": ["$$user.approved", True]}
                }
            }
        }
    )
    if not chat_room or "users" not in chat_room:
        return jsonify([])

    return jsonify(chat_room["users"])

#채팅방 관련 코드

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
    time = datetime.now().strftime('%H:%M')  # 현재 시간 (시:분) 형식으로 저장

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
                           room_name=room_name,
                           time=time)

def get_room_name(user, role, session_username):
    if role == "admin":
        return session_username
    elif role == "user":
        chat_rooms_list = user.get("chat_rooms", [])
        if not chat_rooms_list:
            return None
        return chat_rooms_list[0]#채팅방 리스트 중에 첫번째로 이동함 나중에 채팅방 여러개면 선택하는 페이지 만들기
    else:
        return "권한 없음", 403
    
# 실시간 채팅 관련 코드
@socketio.on('message')
def handle_message(data):
    user = data.get('user', '익명')#username이 페이지렌더링할때 이름이랑 겹쳐서 user로 바꿈
    message = data.get('message', '')
    time = data.get('time', '')
    emit('message', {'user': user, 'message': message, 'time': time}, broadcast=True)



# 포인트 관련 코드

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

@app.route("/give_point", methods=["POST"])
def give_point():
    data = request.get_json()
    to_user = data.get("to")
    from_user = session.get("username")
    amount = data.get("amount", 0)
    admin = data.get("admin")  # 어떤 채팅방(관리자)에서 포인트를 이동할지 프론트에서 전달해야 함

    chat_room = chat_rooms.find_one({"admin_name": admin})#데이터베이스에서 채팅방 가져오기
    if not from_user or not to_user or amount <= 0:
        return jsonify(success=False, message="잘못된 요청이야.")

    if from_user == to_user:
        return jsonify(success=False, message="자기 자신에게는 줄 수 없어")

    #주는 사람이 admin인지 확인
    if from_user == admin:
        sender = admin
        receiver = next((u for u in chat_room.get("users", []) if u.get("username") == to_user), None)
        point = chat_room.get("point", 0)
        if not receiver:
         return jsonify(success=False, message=f"{to_user} 님은 없어.")
        if point < amount:
            return jsonify(success=False, message="포인트가 부족합니다.")
        chat_rooms.update_one(
            {"admin_name": admin, "users.username": to_user},
            {"$inc": {"users.$.point": amount}}
        )
        chat_rooms.update_one(
            {"admin_name": admin},
            {"$inc": {"point": -amount}}
        )
        new_point = point - amount
        return jsonify(success=True, message=f"관리자가 {to_user}님에게 {amount}포인트를 전달했어요!", new_point=new_point)
    #주는 사람이 user인지 확인
    else:#sender와 receiver 정보 가져오기 딕셔너리형태로 가져와서 sender[username]올바르게 조회해야함
        sender = next((u for u in chat_room.get("users", []) if u.get("username") == from_user), None)
        receiver = next((u for u in chat_room.get("users", []) if u.get("username") == to_user), None)
    
    point = sender["point"] if sender else 0
    if not receiver:
        return jsonify(success=False, message=f"{to_user} 님은 없어.")

    if point < amount:
        return jsonify(success=False, message="포인트가 부족합니다.")
    # 1) sender 포인트 차감
    chat_rooms.update_one(
        {"admin_name": admin, "users.username": sender["username"]},
        {"$inc": {"users.$.point": -amount}}
    )
    # 2) receiver 포인트 증가
    chat_rooms.update_one(
        {"admin_name": admin, "users.username": receiver["username"]},
        {"$inc": {"users.$.point": amount}}
    )
    new_point = point - amount#새로운 점수 계산

    return jsonify(success=True, message=f"{to_user}님에게 {amount}포인트를 전달했어요!", new_point=new_point)

# 규칙 관련 코드

@app.route("/give_score", methods=["POST"])
def give_score():
    data = request.get_json()
    rule_id = data.get("ruleId")
    user = data.get("user")
    admin_name = session.get("username")

    if not rule_id or not user:
        return jsonify(success=False, message="잘못된 요청"), 400

    # 규칙에서 score 가져오기
    rule_list = chat_rooms.find_one(
        {"admin_name": admin_name, "rules._id": ObjectId(rule_id)},
        {"rules.$": 1}
    )

    if not rule_list:
        return jsonify(success=False, message="규칙을 찾을 수 없음"), 404

    rule = rule_list["rules"][0] # 규칙 하나 가져와서 규칙 설정함
    score = rule.get("score", 0)

    # 유저에게 점수 부여
    result = chat_rooms.update_one(
        {
            "admin_name": admin_name,
            "users.username": user
        },
        {
            "$inc": {"users.$.point": score}
        }
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
    admin_name = session.get("username")#일단 관리자마다 하나씩만 채팅방 만듦

    if content:
        rule_doc = {#규칙별로 id부여해서 클릭했을때 고유한 규칙으로서 판단함
            "_id": ObjectId(),# 배열 내부 규칙에도 고유 ID 부여
            "content": content,
            "score": score,
            "created_at": datetime.utcnow()
        }
        rule_id = rule_doc["_id"]

        chat_rooms.update_one(
            {"admin_name": admin_name},
            {"$push": {"rules": rule_doc}}
        )
        return jsonify(success=True, id=str(rule_id), rule={**rule_doc, "_id": str(rule_id)})
    return jsonify(success=False, message="빈 규칙입니다.")

@app.route("/get_rules")
def get_rules():
    if session.get("role") == "admin":
        admin_name = session.get("username")
    else:
        user = users.find_one({"username": session.get("username")})
        if not user or not user.get("chat_rooms"):
            return jsonify([])
        admin_name = user["chat_rooms"][0]  # 첫 번째 채팅방의 관리자 이름 사용
    chat_room = chat_rooms.find_one({"admin_name": admin_name}, {"rules": 1})
    if not chat_room:
        return jsonify([])
    rule_list = []
    for r in chat_room["rules"]:
        r_copy = r.copy()  # 원본 데이터 보호
        r_copy['_id'] = str(r_copy['_id'])  # ObjectId를 문자열로 변환
        rule_list.append(r_copy)
    return jsonify(rule_list)

@app.route("/update_rule", methods=["POST"])
def update_rule():
    data = request.get_json()
    rule_id = data.get("id")
    new_content = data.get("content", "").strip()
    new_score = data.get("score")
    admin_name = session.get("username")

    if not rule_id or not new_content:
        return jsonify(success=False, message="ID와 내용은 필수입니다.")

    #업데이트 할 필드를 미리 정의한 딕셔너리
    update_fields = {"rules.$.content": new_content}
    # 점수가 None이 아니고 숫자라면 같이 업데이트
    if new_score is not None:
        try:
            update_fields["rules.$.score"] = float(new_score)
        except ValueError:
            return jsonify(success=False, message="점수는 숫자여야 합니다.")

    result = chat_rooms.update_one(
        {"admin_name": admin_name, "rules._id": ObjectId(rule_id)},
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
    admin_name = session.get("username")
    if not rule_id:
        return jsonify({'success': False, 'message': 'ID 없음'}), 400

    result = chat_rooms.update_one(
        {"admin_name": admin_name},
        {"$pull": {"rules": {"_id": ObjectId(rule_id)}}}
    )

    if result.deleted_count == 1:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': '삭제 실패'})


if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=80)
