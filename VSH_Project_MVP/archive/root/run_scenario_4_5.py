import requests

BASE_URL = "http://localhost:3000"

print("--- Step 4. Accept 처리 ---")
response = requests.get(f"{BASE_URL}/api/logs")
logs = response.json().get("logs", [])

pending_logs = [l for l in logs if l.get("status") == "pending"]
if not pending_logs:
    print("No pending logs found.")
    exit()

first_issue = pending_logs[0]
issue_id = first_issue.get("issue_id")

print(f"Accepting issue: {issue_id}")

accept_response = requests.post(f"{BASE_URL}/api/logs/{issue_id}/accept")
accept_result = accept_response.json()

print(f"API Response Status: {accept_response.status_code}")
print(f"Updated Status in Response: {accept_result.get('status')}")
print(f"Fixed Code returned: {accept_result.get('fixed_code', '')[:50]}...")

print("\\n--- Step 5. Accept 후 log.json 상태 확인 ---")
response_after = requests.get(f"{BASE_URL}/api/logs")
logs_after = response_after.json().get("logs", [])

for log in logs_after:
    print(f"issue_id: {log.get('issue_id')}, status: {log.get('status')}")
