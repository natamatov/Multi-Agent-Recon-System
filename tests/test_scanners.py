import pytest
import asyncio
from unittest.mock import patch, MagicMock
from core.scanner import _run_command_async, run_nmap_async

@pytest.mark.asyncio
@patch("core.scanner.asyncio.create_subprocess_exec")
async def test_run_command_async_success(mock_exec):
    mock_process = MagicMock()
    mock_process.returncode = 0
    # communicate is a coroutine
    async def mock_communicate():
        return b"mock stdout", b"mock stderr"
    mock_process.communicate.return_value = mock_communicate()
    
    mock_exec.return_value = mock_process
    
    result = await _run_command_async("test_tool", ["test_tool", "arg1"])
    assert result.success is True
    assert result.stdout == "mock stdout"
    assert result.stderr == "mock stderr"
    assert result.tool == "test_tool"

@pytest.mark.asyncio
@patch("core.scanner._run_command_async")
async def test_run_nmap_async(mock_run):
    mock_run.return_value = MagicMock(success=True)
    
    await run_nmap_async("example.com")
    mock_run.assert_called_once_with(
        "nmap", ["nmap", "-sV", "-T4", "--open", "-oN", "-", "example.com"], timeout=600
    )
