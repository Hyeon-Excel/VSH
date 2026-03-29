import sys, asyncio
sys.path.insert(0, '.')
from dotenv import load_dotenv
load_dotenv()
from l3.llm.gemini_adapter import GeminiAdapter

async def test():
    llm = GeminiAdapter()

    test_cases = [
        ('python:S5131', 'Expression language injection'),
        ('python:S2076', 'OS command injection'),
        ('python:S3649', 'SQL injection'),
    ]

    valid_cwe = ['CWE-89', 'CWE-79', 'CWE-78']
    for rule_id, message in test_cases:
        cwe_id = await llm.classify_cwe(rule_id, message)
        match = cwe_id in valid_cwe
        print(f'rule_id : {rule_id}')
        print(f'message : {message}')
        print(f'cwe_id  : {cwe_id}')
        print(f'매칭 가능: {match}')
        print()

asyncio.run(test())