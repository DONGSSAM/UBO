from pymongo import MongoClient

uri = "mongodb+srv://glddiglddi:dkdk1378@user.y0fcfhd.mongodb.net/?retryWrites=true&w=majority&appName=User"
client = MongoClient(uri)
db = client['mydatabase']
users = db['users']
rules = db['rules']

def check_connection():
    try:
        client.admin.command('ping')
        print("MongoDB 연결 성공!")
    except Exception as e:
        print("MongoDB 연결 실패:", e)