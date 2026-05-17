import pytest
import asyncio
from unittest.mock import patch, MagicMock
from core.scanner import _run_command_async, run_nmap_async

@pytest.mark.asyncio
@patch("core.scanner.asyncio.create_subprocess_exec")
async def test_run_command_async_success(mock_exec):
    mock_process = MagicMock()
    mock_process.pid = 12345
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

@pytest.mark.asyncio
@patch("core.scanner._run_command_async")
async def test_run_wpscan_async_no_key(mock_run):
    """WPScan should run without an API key (basic scan)."""
    from core.scanner import run_wpscan_async
    mock_run.return_value = MagicMock(success=True)
    
    await run_wpscan_async("http://example.com")
    args, kwargs = mock_run.call_args
    cmd = args[1]
    assert "wpscan" in cmd
    assert "--api-token" not in cmd  # no key provided

@pytest.mark.asyncio
@patch("core.scanner._run_command_async")
async def test_run_wpscan_async_with_key(mock_run):
    """WPScan should include --api-token when key is provided."""
    from core.scanner import run_wpscan_async
    mock_run.return_value = MagicMock(success=True)
    
    await run_wpscan_async("http://example.com", api_key="test-token-123")
    args, kwargs = mock_run.call_args
    cmd = args[1]
    assert "--api-token" in cmd
    assert "test-token-123" in cmd
