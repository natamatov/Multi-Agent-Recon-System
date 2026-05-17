import pytest
from unittest.mock import patch, MagicMock
from core.swarm.orchestrator import MARSSwarmManager

@patch("core.swarm.orchestrator.Crew")
def test_swarm_manager_run_analysis(mock_crew_class):
    # Setup mock
    mock_crew_instance = MagicMock()
    mock_crew_class.return_value = mock_crew_instance
    mock_crew_instance.kickoff.return_value = "Final CrewAI Summary"
    
    # We also need to mock the outputs of the tasks, which is tricky 
    # since they are dynamically created inside run_analysis.
    # Instead, we just test that Crew kickoff is called.
    
    from core.security_mode import AuditMode

    manager = MARSSwarmManager(mode=AuditMode.ASSESSMENT)
    
    # In older versions of CrewAI, outputs are attributes on the task.
    # We will just verify it doesn't crash and returns the mocked summary.
    
    result = manager.run_analysis(raw_logs="fake logs", osint_data="fake osint")
    
    assert result["success"] is True
    assert result["final_summary"] == "Final CrewAI Summary"
    mock_crew_instance.kickoff.assert_called_once()
