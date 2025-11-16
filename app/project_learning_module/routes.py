import os
from flask import Flask, request, jsonify, render_template
import requests, json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

API_KEY = os.getenv("CLOVA_API_KEY")
API_URL = os.getenv("CLOVA_API_URL") 
print(os.getenv("CLOVA_API_KEY"))
print(os.getenv("CLOVA_API_URL"))

SYSTEM_PROMPT_TEMPLATE = """
당신의 역할은 "초등 프로젝트 학습 전문 AI 도우미"입니다.
지금부터 내가 말할 프로젝트 대해 초등학생도 이해할 수 있지만,
교사가 발표자료로 사용하기 충분할 만큼 풍부한 정보를 JSON 구조로 제공합니다.
출력은 반드시 아래 JSON 구조만 사용하며, JSON 외의 텍스트는 절대 추가하지 마세요.

다음은 해당 프로젝트에 대한 구체적인 설명입니다.
- 주제: "{title}"
- 역할: "{roles}"  (예: 팀 역할, 개인 역할 등)
- 발표 일시: "{schedule}" (예: 11월 12일 3교시 등)
- 발표 방법: "{methods}"  (예: 포스터 만들기, 발표하기, 자료집 만들기 등)
- 필요 자료: "{resources}" (예: 기본 정보, 문화, 음식 등)

{{ "title": "{title}", 
"english_name": "<영문명>", 

"sections": [
  {{ "title": "<주제1>", 
  "content": "<3~5문장 이상의 설명, <주제1>에 관한 내용 포함, 초등학생 이해 가능>", 
  "references": ["<신뢰 가능한 출처 URL, Wikipedia/Britannica/공식 관광청 등>"] 
  }},
  {{ "title": "<주제2>", 
  "content": "<3~5문장 이상의 설명, <주제2>에 관한 내용 포함, 초등학생 이해 가능>", 
  "references": ["<신뢰 가능한 출처 URL>"] 
  }}, 
  {{ "title": "<주제3>", 
  "content": "<3~5문장 이상의 설명, <주제3>에 관한 내용 포함, 초등학생 이해 가능>", 
  "references": ["<신뢰 가능한 출처 URL>"] 
  }}, 
  {{ "title": "<주제4>", 
  "content": "<3~5문장 이상의 설명, <주제4>에 관한 내용 포함, 초등학생 이해 가능>>", 
  "references": ["<신뢰 가능한 출처 URL>"] 
  }}, 
  {{ "title": "<주제5>", 
  "content": "<3~5문장 이상의 설명, <주제5>에 관한 내용 포함, 초등학생 이해 가능>", 
  "references": ["<신뢰 가능한 출처 URL>"] 
  }}
],
"summary": [ "<발표용 핵심 요약 1문장>", "<요약 1문장>", "<요약 1문장>" ] 
}} 

규칙: 
 1) sections의 content는 3~5문장 이상, 초등학생 이해 가능, 발표 자료 수준 충분.
 2) references는 신뢰 가능한 1~2개의 출처 URL만 사용.
 3) 출력은 JSON만, 절대 다른 텍스트 추가 금지.
 4) sections 배열의 각 title은 {resources}에 있는 항목 순서대로 생성.
 5) {resources} 항목이 5개보다 적으면, 자동으로 resources를 5개까지 추가하고 그에 맞게 sections와 images도 생성.
"""

IMAGE_PROMPT_TEMPLATE = """
당신의 역할은 "초등 프로젝트 학습 전문 AI 도우미"입니다.
지금부터 내가 말할 프로젝트 대해 초등학생도 이해할 수 있지만,
교사가 발표자료로 사용하기 충분할 만큼 풍부한 정보를 JSON 구조로 제공합니다.
출력은 반드시 아래 JSON 구조만 사용하며, JSON 외의 텍스트는 절대 추가하지 마세요.

다음은 해당 프로젝트에 대한 구체적인 설명입니다.
- 주제: "{title}"
- 역할: "{roles}"  (예: 팀 역할, 개인 역할 등)
- 발표 일시: "{schedule}" (예: 11월 12일 3교시 등)
- 발표 방법: "{methods}"  (예: 포스터 만들기, 발표하기, 자료집 만들기 등)
- 필요 자료: "{resources}" (예: 기본 정보, 문화, 음식 등)

{{ "title": "{title}", 
"english_name": "<영문명>", 
"images": 
  [
    {{ "url": "<이미지 실제 파일 URL (단순히 페이지 링크가 아니라, 브라우저 새 탭에서 열었을 때 이미지 파일만 보이는 URL이어야 함)>",
    "caption": "<주제 1 이미지 설명>",
    "source": "<출처 (Unsplash, Wikimedia Commons 등 공식 출처)>" }},
    {{ "url": "<이미지 실제 파일 URL (단순히 페이지 링크가 아니라, 브라우저 새 탭에서 열었을 때 이미지 파일만 보이는 URL이어야 함)>",
    "caption": "<주제 2 이미지 설명>",
    "source": "<출처 (Unsplash, Wikimedia Commons 등 공식 출처)>" }},
    {{ "url": "<이미지 실제 파일 URL (단순히 페이지 링크가 아니라, 브라우저 새 탭에서 열었을 때 이미지 파일만 보이는 URL이어야 함)>",
    "caption": "<주제 3 이미지 설명>",
    "source": "<출처 (Unsplash, Wikimedia Commons 등 공식 출처)>" }}
  ], 
"sections": [
  {{ "title": "<주제1>", 
  "content": "<3~5문장 이상의 설명, <주제1>에 관한 내용 포함, 초등학생 이해 가능>", 
  "references": ["<신뢰 가능한 출처 URL, Wikipedia/Britannica/공식 관광청 등>"] 
  }},
  {{ "title": "<주제2>", 
  "content": "<3~5문장 이상의 설명, <주제2>에 관한 내용 포함, 초등학생 이해 가능>", 
  "references": ["<신뢰 가능한 출처 URL>"] 
  }}, 
  {{ "title": "<주제3>", 
  "content": "<3~5문장 이상의 설명, <주제3>에 관한 내용 포함, 초등학생 이해 가능>", 
  "references": ["<신뢰 가능한 출처 URL>"] 
  }}, 
  {{ "title": "<주제4>", 
  "content": "<3~5문장 이상의 설명, <주제4>에 관한 내용 포함, 초등학생 이해 가능>>", 
  "references": ["<신뢰 가능한 출처 URL>"] 
  }}, 
  {{ "title": "<주제5>", 
  "content": "<3~5문장 이상의 설명, <주제5>에 관한 내용 포함, 초등학생 이해 가능>", 
  "references": ["<신뢰 가능한 출처 URL>"] 
  }}
],
"summary": [ "<발표용 핵심 요약 1문장>", "<요약 1문장>", "<요약 1문장>" ] 
}} 

규칙: 
 1) images 배열은 {resources} 항목 순서와 매칭하여 생성, 각 이미지는 저작권 문제가 없는 공식 출처(Unsplash, Wikimedia Commons, NPS 등)만 사용. 
 2) sections의 content는 3~5문장 이상, 초등학생 이해 가능, 발표 자료 수준 충분.
 3) references는 신뢰 가능한 1~2개의 출처 URL만 사용.
 4) 출력은 JSON만, 절대 다른 텍스트 추가 금지.
 5) 실제 이미지 파일 URL(a/a7 등 최신 파일 경로) 기준으로 사용.
 6) sections 배열의 각 title은 {resources}에 있는 항목 순서대로 생성.
 7) images 배열도 {resources}와 관련된 이미지로 순서대로 생성
 8) {resources} 항목이 3개보다 적으면, 자동으로 resources를 3개까지 추가하고 그에 맞게 sections와 images도 생성.
"""



@app.route('/')
def index():
    return render_template('project_learning.html')

@app.route('/generate', methods=['POST'])
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

if __name__ == "__main__":
    app.run(debug=True)