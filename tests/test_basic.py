"""Basic test to ensure pipeline runs."""
import pytest
from src.agents.controller_agent import ControllerAgent

@pytest.mark.asyncio
async def test_controller_runs():
    """Test controller executes without error."""
    agent = ControllerAgent()
    result = await agent.run()
    assert result["filtered_cves"] > 0
    assert "predictions" in result

def test_imports_work():
    """Test all imports work."""
    from src.agents.base_agent import BaseAgent
    from src.agents.cve_fetch_agent import CVEFetchAgent
    from src.agents.epss_filter_agent import EPSSFilterAgent
    assert BaseAgent is not None
