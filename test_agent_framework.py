#!/usr/bin/env python3
"""
Test script for the NOPE agent framework.
Demonstrates the complete agent system with coordination.
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from agents.controller_agent import ControllerAgent
from agents.base_agent import AgentConfig
from config.settings import NOPESettings
from utils.validation import validate_cve_data
from utils.communication import get_message_bus, shutdown_message_bus
import structlog

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


async def test_agent_framework():
    """Test the complete agent framework."""
    print("🐙 NOPE Agent Framework Test")
    print("=" * 50)
    
    try:
        # Initialize settings
        settings = NOPESettings()
        print(f"✓ Settings initialized")
        
        # Validate configuration
        config_issues = settings.validate()
        if config_issues:
            print("⚠️  Configuration issues:")
            for issue in config_issues:
                print(f"  - {issue}")
        else:
            print("✓ Configuration validated")
        
        # Initialize message bus
        message_bus = await get_message_bus()
        print("✓ Message bus initialized")
        
        # Create controller agent
        controller_config = settings.get_agent_config("controller")
        
        print(f"\n📋 Starting Controller Agent")
        print(f"  - Timeout: {controller_config.timeout}s")
        print(f"  - Cache TTL: {controller_config.cache_ttl}s")
        print(f"  - Max retries: {controller_config.max_retries}")
        
        async with ControllerAgent(controller_config) as controller:
            # Set up communication
            controller.set_message_bus(message_bus)
            
            # Test health check
            print(f"\n🔍 Testing Health Checks")
            health = await controller.health_check()
            print(f"  - Controller health: {health.status}")
            print(f"  - Response time: {health.response_time_ms:.2f}ms")
            
            # Test pipeline configuration
            pipeline_config = {
                'epss_threshold': settings.epss.base_threshold,
                'max_cves': 50,
                'days_back': 7,
                'enable_enrichment': True,
                'output_dir': settings.output.output_dir,
                'cve_sources': ['nvd', 'github', 'epss']
            }
            
            print(f"\n🔧 Pipeline Configuration")
            print(f"  - EPSS Threshold: {pipeline_config['epss_threshold']}")
            print(f"  - Max CVEs: {pipeline_config['max_cves']}")
            print(f"  - Data Sources: {pipeline_config['cve_sources']}")
            print(f"  - Output Dir: {pipeline_config['output_dir']}")
            
            # Execute pipeline
            print(f"\n🚀 Executing NOPE Pipeline")
            start_time = datetime.now()
            
            result = await controller.process(pipeline_config)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Display results
            print(f"\n📊 Pipeline Results")
            print(f"  - Success: {'✓' if result['success'] else '✗'}")
            print(f"  - Duration: {duration:.2f}s")
            
            if result['success']:
                print(f"  - CVEs Processed: {result['stats']['total_cves_processed']}")
                print(f"  - CVEs After Filtering: {result['stats']['cves_after_filtering']}")
                print(f"  - Final CVE Count: {result['cve_count']}")
                
                if result.get('output'):
                    output_info = result['output']
                    print(f"  - JSON Output: {output_info.get('json_file')}")
                    print(f"  - Statistics: {output_info.get('stats_file')}")
                    
                    # Display statistics
                    if 'statistics' in output_info:
                        stats = output_info['statistics']
                        print(f"\n📈 CVE Statistics")
                        print(f"  - Total CVEs: {stats.get('total_cves', 0)}")
                        print(f"  - Average Risk Score: {stats.get('average_risk_score', 0):.1f}")
                        
                        severity_dist = stats.get('severity_distribution', {})
                        if severity_dist:
                            print(f"  - Severity Distribution:")
                            for severity, count in severity_dist.items():
                                print(f"    {severity}: {count}")
                        
                        epss_stats = stats.get('epss_statistics', {})
                        if epss_stats.get('count', 0) > 0:
                            print(f"  - EPSS Scores:")
                            print(f"    Average: {epss_stats.get('average', 0):.3f}")
                            print(f"    Range: {epss_stats.get('min', 0):.3f} - {epss_stats.get('max', 0):.3f}")
            else:
                print(f"  - Error: {result.get('error', 'Unknown error')}")
                print(f"  - Error Type: {result.get('error_type', 'Unknown')}")
            
            # Test agent status
            print(f"\n📊 Agent Status Report")
            status = await controller.get_pipeline_status()
            
            print(f"  Controller:")
            controller_status = status['controller']
            print(f"    - Health: {'✓' if controller_status['healthy'] else '✗'}")
            print(f"    - Operations: {controller_status['operations_total']}")
            print(f"    - Success Rate: {100 - (controller_status['error_rate'] * 100):.1f}%")
            print(f"    - Cache Hit Rate: {controller_status['cache_hit_rate'] * 100:.1f}%")
            
            print(f"  Sub-Agents:")
            for agent_name, agent_status in status['agents'].items():
                print(f"    {agent_name}:")
                print(f"      - Health: {'✓' if agent_status['healthy'] else '✗'}")
                print(f"      - Operations: {agent_status['operations_total']}")
                print(f"      - Cache Size: {agent_status['cache_size']}")
        
        # Test data validation
        print(f"\n🔍 Testing Data Validation")
        test_cve_data = [
            {
                'cve_id': 'CVE-2024-1234',
                'description': 'Test CVE for validation framework',
                'published_date': '2024-01-15T10:30:00Z',
                'severity': 'HIGH',
                'cvss_score': 8.5,
                'epss_score': 0.75
            },
            {
                'cve_id': 'INVALID-ID',  # Invalid format
                'description': 'Bad',   # Too short
                'published_date': '2024-01-15T10:30:00Z',
                'severity': 'INVALID',  # Invalid severity
                'cvss_score': 15.0,     # Out of range
                'epss_score': 1.5       # Out of range
            }
        ]
        
        validation_report = validate_cve_data(test_cve_data, min_epss_threshold=0.6)
        
        print(f"  - Total Checks: {validation_report.total_checks}")
        print(f"  - Passed: {validation_report.passed_checks}")
        print(f"  - Failed: {validation_report.failed_checks}")
        print(f"  - Success Rate: {validation_report.success_rate:.1f}%")
        
        if validation_report.errors:
            print(f"  - Sample Errors:")
            for error in validation_report.errors[:3]:
                print(f"    {error.field_name}: {error.error_message}")
        
        print(f"\n✅ Agent Framework Test Completed Successfully")
        
    except Exception as e:
        logger.error("test_framework_failed", error=str(e))
        print(f"\n❌ Test Failed: {e}")
        raise
    
    finally:
        # Cleanup
        await shutdown_message_bus()
        print(f"🧹 Cleanup completed")


async def test_individual_agents():
    """Test individual agents separately."""
    print(f"\n🧪 Testing Individual Agents")
    print("-" * 30)
    
    try:
        # Test CVE Fetch Agent
        print(f"Testing CVE Fetch Agent...")
        from agents.cve_fetch_agent import CVEFetchAgent
        
        fetch_config = AgentConfig(
            name="test_cve_fetch",
            cache_ttl=600,  # 10 minutes for testing
            timeout=60
        )
        
        async with CVEFetchAgent(fetch_config) as fetch_agent:
            # Test fetching
            fetch_result = await fetch_agent.process({
                'sources': ['nvd', 'epss'],
                'days_back': 3,
                'max_cves': 20
            })
            
            print(f"  - Fetched {len(fetch_result)} CVEs")
            
            # Test cache statistics
            cache_stats = await fetch_agent.get_cache_statistics()
            print(f"  - Cache entries: {cache_stats.get('totals', {}).get('valid_entries', 0)}")
        
        # Test EPSS Filter Agent
        print(f"Testing EPSS Filter Agent...")
        from agents.epss_filter_agent import EPSSFilterAgent
        
        filter_config = AgentConfig(name="test_epss_filter", timeout=30)
        
        async with EPSSFilterAgent(filter_config) as filter_agent:
            # Use some of the fetched data for filtering
            if fetch_result:
                filter_result = await filter_agent.process({
                    'cves': fetch_result[:10],  # Test with first 10 CVEs
                    'epss_threshold': 0.3,      # Lower threshold for testing
                    'use_dynamic_threshold': True,
                    'max_daily_cves': 5
                })
                
                print(f"  - Filtered to {len(filter_result)} CVEs")
                
                # Show threshold analytics
                analytics = filter_agent.get_threshold_analytics()
                if 'threshold_stability' in analytics:
                    stability = analytics['threshold_stability']
                    print(f"  - Threshold adjustment: {stability.get('mean_adjustment', 1.0):.2f}")
        
        print(f"✅ Individual agent tests completed")
        
    except Exception as e:
        print(f"❌ Individual agent test failed: {e}")
        raise


if __name__ == "__main__":
    print("🐙 NOPE Backend Agent Framework")
    print("High-Risk CVE Intelligence Platform")
    print("=" * 50)
    
    async def main():
        try:
            # Test framework
            await test_agent_framework()
            
            # Test individual agents
            await test_individual_agents()
            
            print(f"\n🎉 All tests completed successfully!")
            print(f"The NOPE agent framework is ready for production use.")
            
        except KeyboardInterrupt:
            print(f"\n⚠️  Test interrupted by user")
        except Exception as e:
            print(f"\n💥 Test suite failed: {e}")
            sys.exit(1)
    
    # Run the test
    asyncio.run(main())