import os
from flask import request, jsonify, render_template, Blueprint
import requests, json
from dotenv import load_dotenv
from pathlib import Path

dotenv_path = Path(__file__).parent / ".env" 
load_dotenv()

project_learning_bp = Blueprint('project_learning', __name__, template_folder='templates', url_prefix="/project-learning")

API_KEY = os.getenv("CLOVA_API_KEY")
API_URL = os.getenv("CLOVA_API_URL") 

SYSTEM_PROMPT_TEMPLATE = """
당신의 역할은 "초등 프로젝트 학습 전문 AI 도우미".
지금부터 내가 말할 프로젝트 대해 초등학생도 이해할 수 있지만,
교육 윤리에 위배되지 않고 풍부한 정보를 줘.
출력은 반드시 아래 JSON 구조만 사용하며, JSON 외의 텍스트는 절대 추가하지 마세요.

다음은 해당 프로젝트에 대한 구체적인 설명.
- 주제: "{title}"
- 발표 방법: "{methods}"  (예: 포스터 만들기, 발표하기, 자료집 만들기 등)
- 필요 자료: "{resources}" (예: 기본 정보, 문화, 음식 등)

{{ "title": "{title}",

"sections": [
  {{ "title": "<주제1>", 
  "content": "<주제1>에 관한 내용 포함>", 
  "references": ["<출처 URL>"] 
  }}
],
"summary": [ "<발표용 핵심 요약 1문장>", "<요약 1문장>", "<요약 1문장>" ] 
}} 

규칙: 
 1) sections의 content는 3~4문장.
 2) references는 신뢰 가능한 1~2개 URL만 사용.
 3) sections 배열의 각 title은 {resources}에 있는 항목 순서대로 생성.
 4) {resources} 항목이 3개보다 적으면, 자동으로 3개까지 추가.
"""

@project_learning_bp.route('/generate', methods=['POST'])
def generate():
    data = request.json
    title = data.get('title', '').strip()
    roles = data.get('roles', '').strip()
    schedule = data.get('schedule', '').strip()
    methods = data.get('methods', '').strip()
    resources = data.get('resources', [])

    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
        title=title,
        roles=roles,
        schedule=schedule,
        methods=methods,
        resources=json.dumps(resources)
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"프로젝트 학습 '{title}'를 시작해 주세요."}
    ]

    payload = {
        "messages": messages,
        "maxTokens": 1000,
        "temperature": 0.5
    }

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(API_URL, headers=headers, json=payload, timeout=60)
        resp.raise_for_status()
        return jsonify(resp.json())
    except requests.RequestException as e:
        return jsonify({'error': str(e)}), 500

rooms = []

@project_learning_bp.route('/rooms', methods=['GET'])
def get_rooms():
    return jsonify(rooms)

@project_learning_bp.route('/rooms', methods=['POST'])
def create_room():
    data = request.json
    new_room = {
        "id": str(len(rooms) + 1),
        "topic": data.get("topic"),
        "createdAt": str(data.get("createdAt", "")),
        "memberCount": 1
    }
    rooms.append(new_room)
    return jsonify(new_room)