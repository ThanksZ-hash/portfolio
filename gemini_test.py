import os

from dotenv import load_dotenv
from google import genai

# .env 파일에 GEMINI_API_KEY=발급받은_API_키 형태로 넣어두면 자동으로 읽습니다.
load_dotenv()

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

interaction = client.interactions.create(
    model="gemini-3.5-flash",
    input="다음 문장을 영어로 번역해줘: 안녕하세요",
)

print(interaction.output_text)
