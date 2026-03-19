import os
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
load_dotenv()

token = os.getenv("SONAR_TOKEN")
org = os.getenv("SONAR_ORG")

url = "https://sonarcloud.io/api/issues/search"

# statuses 파라미터 추가해서 테스트
params = {
    "componentKeys": "vsh-project",
    "organization": org,
    "statuses": "OPEN,REOPENED",
    "resolved": "false"
}
r = requests.get(url, params=params, auth=HTTPBasicAuth(token, ""))
data = r.json()
print("statuses 있을 때 total:", data.get("total"))
print("paging:", data.get("paging"))