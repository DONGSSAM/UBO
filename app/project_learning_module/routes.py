import os
from flask import Flask, request, jsonify, render_template
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

API_KEY = os.getenv("CLOVA_API_KEY")
API_URL = os.getenv("CLOVA_API_URL") 
print(os.getenv("CLOVA_API_KEY"))
print(os.getenv("CLOVA_API_URL"))

SYSTEM_PROMPT_TEMPLATE = """
너는 초등학생의 프로젝트 학습 도우미야.
학습 주제는 **{title}**야.
단계별로 문제 인식 → 계획 수립 → 탐구/자료 수집을 안내하고,
각 단계마다 초등학생이 답할 수 있는 질문 2~3개를 던져줘.
마지막으로 범주 4개와 각 범주별 사진 자료 3장씩 JSON 형식으로 제공해 줘.
"""



@app.route('/')
def index():
    return render_template('project_learning.html')

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    title = data.get('title', '').strip()
    if not title:
        return jsonify({'error': '제목을 입력하세요.'}), 400

    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(title=title)

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

if __name__ == "__main__":
    app.run(debug=True)