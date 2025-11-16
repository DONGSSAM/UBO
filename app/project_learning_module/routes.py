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
당신의 역할은 "초등 프로젝트 교육여행·지리·문화 전문 AI 설명자"입니다.
지금부터 내가 말할 국가에 대해 초등학생도 이해할 수 있지만,
교사가 발표자료로 사용하기 충분할 만큼 풍부한 정보를 JSON 구조로 제공합니다.
출력은 반드시 아래 JSON 구조만 사용하며, JSON 외의 텍스트는 절대 추가하지 마세요.
{{ "country": "{title}", 
"english_name": "<영문명>", 
"images": 
  [ {{ "url": "<대표 이미지 실제 파일 URL (웹 브라우저에서 새 탭에서 열면 이미지 파일만 보여야 함)>",
    "caption": "<이미지 설명>",
    "source": "<출처 (Unsplash, Wikimedia Commons 등 공식 출처)>" }} 
  ], 
"sections": [
  {{ "title": "기본 정보", 
  "content": "<3~5문장 이상의 설명, 실제 지명과 국가 특징 포함, 초등학생 이해 가능>", 
  "references": ["<신뢰 가능한 출처 URL, Wikipedia/Britannica/공식 관광청 등>"] 
  }},
  {{ "title": "지리 & 자연", "content": "<3~5문장 이상의 설명, 산, 강, 기후 등 포함>", 
  "references": ["<신뢰 가능한 출처 URL>"] 
  }}, 
  {{ "title": "문화 & 사람", "content": "<3~5문장 이상의 설명, 언어, 전통, 종교 등 포함>", 
  "references": ["<신뢰 가능한 출처 URL>"] 
  }}, 
  {{ "title": "음식", 
  "content": "<3~5문장 이상의 설명, 대표 요리 및 특징 포함>", "references": ["<신뢰 가능한 출처 URL>"] 
  }}, 
  {{ "title": "경제 & 역사", "content": "<3~5문장 이상의 설명, 주요 산업, 역사적 사건 포함>", "references": ["<신뢰 가능한 출처 URL>"] 
  }}, 
  {{ "title": "관광 포인트", "content": "<3~5문장 이상의 설명, 주요 명소와 특징 포함>", "references": ["<신뢰 가능한 출처 URL>"] 
  }} 
],
"summary": [ "<발표용 핵심 요약 1문장>", "<요약 1문장>", "<요약 1문장>" ] 
}} 

규칙: 
 1) 이미지는 3장을 제공하며, 각 이미지는 저작권 문제가 없는 공식 출처(Unsplash, Wikimedia Commons, NPS 등)만 사용. 
 2) sections의 content는 3~5문장 이상, 구체적 지명/문화 요소 포함, 초등학생 이해 가능, 발표 자료 수준 충분.
 3) references는 신뢰 가능한 1~2개의 출처 URL만 사용.
 4) 출력은 JSON만, 절대 다른 텍스트 추가 금지.
 5) 실제 이미지 파일 URL(a/a7 등 최신 파일 경로) 기준으로 사용.
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