import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from l3.llm.base import LLMAdapter
from l3.llm.claude_adapter import ClaudeAdapter
from l3.llm.gemini_adapter import GeminiAdapter

def test_claude_returns_cwe_format():
    adapter = ClaudeAdapter()
    adapter.api_key = "test-key"
    with patch("l3.llm.claude_adapter.anthropic.AsyncAnthropic") as mock_anthropic:
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="CWE-89")]
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        mock_anthropic.return_value = mock_client
        
        result = asyncio.run(adapter.classify_cwe("RULE-001", "SQL Injection"))
        assert result == "CWE-89"

def test_gemini_returns_cwe_format():
    adapter = GeminiAdapter()
    adapter.api_key = "test-key"

    mock_response = MagicMock()
    mock_response.text = "CWE-89"

    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    adapter.client = mock_client

    result = asyncio.run(
        adapter.classify_cwe("squid:S2076", "OS injection")
    )
    assert result == "CWE-89"

def test_claude_failure_returns_cwe_unknown():
    adapter = ClaudeAdapter()
    adapter.api_key = "test-key"
    with patch("l3.llm.claude_adapter.anthropic.AsyncAnthropic") as mock_anthropic:
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(side_effect=Exception("API Error"))
        mock_anthropic.return_value = mock_client
        
        result = asyncio.run(adapter.classify_cwe("RULE-001", "SQL Injection"))
        assert result == "CWE-UNKNOWN"

def test_gemini_failure_returns_cwe_unknown():
    adapter = GeminiAdapter()
    adapter.api_key = "test-key"

    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = Exception("API Error")
    adapter.client = mock_client

    result = asyncio.run(
        adapter.classify_cwe("squid:S2076", "OS injection")
    )
    assert result == "CWE-UNKNOWN"

def test_claude_no_api_key_returns_cwe_unknown():
    adapter = ClaudeAdapter()
    adapter.api_key = None
    result = asyncio.run(adapter.classify_cwe("RULE-001", "SQL Injection"))
    assert result == "CWE-UNKNOWN"

def test_gemini_no_api_key_returns_cwe_unknown():
    adapter = GeminiAdapter()
    adapter.api_key = None
    result = asyncio.run(adapter.classify_cwe("RULE-001", "SQL Injection"))
    assert result == "CWE-UNKNOWN"

def test_parses_cwe_from_long_response():
    adapter = ClaudeAdapter()
    adapter.api_key = "test-key"
    with patch("l3.llm.claude_adapter.anthropic.AsyncAnthropic") as mock_anthropic:
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="이 취약점은 CWE-78에 해당합니다.")]
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        mock_anthropic.return_value = mock_client
        
        result = asyncio.run(adapter.classify_cwe("RULE-001", "Command Injection"))
        assert result == "CWE-78"

def test_adapters_share_same_interface():
    assert issubclass(ClaudeAdapter, LLMAdapter) == True
    assert issubclass(GeminiAdapter, LLMAdapter) == True
    assert isinstance(ClaudeAdapter(), LLMAdapter) == True
    assert isinstance(GeminiAdapter(), LLMAdapter) == True
    assert hasattr(ClaudeAdapter(), "classify_cwe") == True
    assert hasattr(GeminiAdapter(), "classify_cwe") == True
