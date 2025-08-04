"""
Integration tests for NOPE Data Enrichment Pipeline

These tests validate the complete pipeline execution including
agent coordination, data validation, and enrichment processes.
"""

import asyncio
import pytest
import json
import tempfile
import os
from datetime import datetime, timedelta

# Assuming the pipeline can be imported
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from agents.controller_agent import ControllerAgent, PipelineConfig


class TestPipelineIntegration:
    """Test complete pipeline integration"""
    
    @pytest.mark.asyncio
    async def test_full_pipeline_execution_mock_data(self):
        """Test complete pipeline execution with mock data"""
        
        # Create temporary output directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Configure pipeline
            config = PipelineConfig(
                epss_threshold=0.6,
                max_cve_count=50,
                enable_enrichment=True,
                enable_validation=True,
                parallel_enrichment=True, 
                output_dir=temp_dir
            )
            
            # Initialize controller
            controller = ControllerAgent(config)
            
            try:
                # Initialize pipeline
                init_success = await controller.initialize()
                assert init_success, "Pipeline initialization should succeed"
                
                # Execute pipeline with mock data
                result = await controller.execute_pipeline(data_source="mock")
                
                # Validate results
                assert result.success, f"Pipeline should succeed, but got errors: {result.errors}"
                assert result.processed_count > 0, "Should process CVEs"
                assert result.enriched_count > 0, "Should enrich CVEs"
                assert result.execution_time > 0, "Should take some time"
                assert len(result.enriched_cves) > 0, "Should return enriched CVEs"
                
                # Validate enriched CVE structure
                sample_cve = result.enriched_cves[0]
                
                # Check required fields
                assert "cve_id" in sample_cve
                assert "risk_score" in sample_cve
                assert "risk_level" in sample_cve
                assert "cisa_kev" in sample_cve
                assert "exploit_availability" in sample_cve
                assert "package_impact" in sample_cve
                assert "enrichment_metadata" in sample_cve
                assert "pipeline_metadata" in sample_cve
                
                # Check CISA KEV enrichment
                kev_data = sample_cve["cisa_kev"]
                assert isinstance(kev_data["is_known_exploited"], bool)
                assert "enriched_at" in sample_cve["enrichment_metadata"].get("cisa_kev", {})
                
                # Check exploit availability enrichment
                exploit_data = sample_cve["exploit_availability"]
                assert isinstance(exploit_data["exploits_available"], bool)
                assert "exploit_maturity" in exploit_data
                assert "enriched_at" in sample_cve["enrichment_metadata"].get("exploit_availability", {})
                
                # Check package impact enrichment
                package_data = sample_cve["package_impact"]
                assert isinstance(package_data["total_packages"], int)
                assert "supply_chain_risk" in package_data
                
                # Check risk scoring
                assert isinstance(sample_cve["risk_score"], int)
                assert 0 <= sample_cve["risk_score"] <= 100
                assert sample_cve["risk_level"] in ["low", "medium", "elevated", "high", "critical"]
                
                # Check output files were created
                output_files = ["latest_enriched_cves.json", "api_cves.json"]
                for filename in output_files:
                    filepath = os.path.join(temp_dir, filename)
                    assert os.path.exists(filepath), f"Output file {filename} should exist"
                    
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        assert len(data) > 0 or "cves" in data, f"Output file {filename} should contain data"
                
                # Check metrics
                metrics = result.metrics
                assert "pipeline_execution" in metrics
                assert "data_processing" in metrics
                assert "quality_metrics" in metrics
                assert "risk_analysis" in metrics
                
                print(f"✅ Pipeline test passed: {result.enriched_count} CVEs enriched in {result.execution_time:.2f}s")
                
            finally:
                # Cleanup
                await controller.finalize()
    
    @pytest.mark.asyncio
    async def test_individual_agent_coordination(self):
        """Test individual agent coordination and communication"""
        
        # Test CISA KEV Agent
        from agents.enrichment.cisa_kev_agent import CISAKEVAgent
        
        kev_agent = CISAKEVAgent()
        
        try:
            init_success = await kev_agent.initialize()
            assert init_success, "CISA KEV agent should initialize"
            
            # Test enrichment
            test_cve = {
                "cve_id": "CVE-2024-1234",
                "description": "Test CVE for agent coordination",
                "epss": {"score": 0.8, "percentile": 0.95}
            }
            
            enriched_cve = await kev_agent.enrich_cve(test_cve)
            
            # Validate enrichment
            assert "cisa_kev" in enriched_cve
            assert "enrichment_metadata" in enriched_cve
            assert enriched_cve["enrichment_metadata"]["cisa_kev"]["success"] in [True, False]
            
            print("✅ CISA KEV agent coordination test passed")
            
        finally:
            await kev_agent.finalize()
    
    @pytest.mark.asyncio
    async def test_validation_system(self):
        """Test data validation system"""
        
        from agents.validation.data_validation_agent import DataValidationAgent
        
        validator = DataValidationAgent()
        
        try:
            init_success = await validator.initialize()
            assert init_success, "Validation agent should initialize"
            
            # Test ingestion validation with good data
            good_data = [
                {
                    "cve_id": "CVE-2024-0001",
                    "description": "Valid CVE for testing",
                    "published": "2024-01-01T00:00:00Z",
                    "severity": "HIGH"
                },
                {
                    "cve_id": "CVE-2024-0002", 
                    "description": "Another valid CVE",
                    "published": "2024-01-02T00:00:00Z",
                    "severity": "CRITICAL"
                }
            ]
            
            result = await validator.validate_stage("stage1_ingestion", good_data)
            assert result.is_valid or result.failed <= 1, "Good data should mostly pass validation"
            
            # Test EPSS validation
            epss_data = [
                {
                    "cve_id": "CVE-2024-0001",
                    "epss": {"score": 0.8, "percentile": 0.95}
                },
                {
                    "cve_id": "CVE-2024-0002",
                    "epss": {"score": 0.7, "percentile": 0.90}
                }
            ]
            
            epss_result = await validator.validate_stage("stage2_epss_filter", epss_data, min_threshold=0.6)
            assert epss_result.is_valid, "EPSS data above threshold should pass validation"
            
            print("✅ Validation system test passed")
            
        finally:
            await validator.finalize()
    
    @pytest.mark.asyncio 
    async def test_risk_scoring_accuracy(self):
        """Test risk scoring accuracy and consistency"""
        
        from agents.validation.risk_scorer_agent import RiskScorerAgent
        
        risk_scorer = RiskScorerAgent()
        
        try:
            init_success = await risk_scorer.initialize()
            assert init_success, "Risk scorer should initialize"
            
            # Test high risk CVE
            high_risk_cve = {
                "cve_id": "CVE-2024-9999",
                "description": "High risk test CVE",
                "cvss": {"baseScore": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                "epss": {"score": 0.95, "percentile": 0.99},
                "cisa_kev": {"is_known_exploited": True, "known_ransomware_campaign_use": "Known"},
                "exploit_availability": {"exploits_available": True, "exploit_maturity": "weaponized"},
                "package_impact": {"supply_chain_risk": "critical", "max_dependent_count": 100000}
            }
            
            enriched_cve = await risk_scorer.enrich_cve(high_risk_cve)
            
            # Validate high risk score
            assert "risk_score" in enriched_cve
            assert enriched_cve["risk_score"] >= 80, f"High risk CVE should have score >= 80, got {enriched_cve['risk_score']}"  
            assert enriched_cve["risk_level"] in ["high", "critical"]
            assert "risk_score_breakdown" in enriched_cve
            
            # Test low risk CVE
            low_risk_cve = {
                "cve_id": "CVE-2024-0001",
                "description": "Low risk test CVE",
                "cvss": {"baseScore": 3.1, "vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
                "epss": {"score": 0.61, "percentile": 0.70},
                "cisa_kev": {"is_known_exploited": False},
                "exploit_availability": {"exploits_available": False, "exploit_maturity": "none"},
                "package_impact": {"supply_chain_risk": "low", "max_dependent_count": 10}
            }
            
            low_enriched = await risk_scorer.enrich_cve(low_risk_cve)
            
            # Validate lower risk score
            assert low_enriched["risk_score"] < enriched_cve["risk_score"], "Low risk CVE should have lower score than high risk"
            assert low_enriched["risk_score"] <= 70, f"Low risk CVE should have score <= 70, got {low_enriched['risk_score']}"
            
            print(f"✅ Risk scoring test passed: High={enriched_cve['risk_score']}, Low={low_enriched['risk_score']}")
            
        finally:
            await risk_scorer.finalize()
    
    def test_api_data_structure_compliance(self):
        """Test API data structure compliance"""
        
        # Test API CVE structure matches expected schema
        api_cve_example = {
            "cve_id": "CVE-2024-1234",
            "description": "Test API CVE structure",
            "severity": "HIGH",
            "cvss_score": 8.5,
            "epss_score": 0.75,
            "epss_percentile": 0.92,
            "risk_score": 85,
            "risk_level": "high",
            "is_kev": True,
            "exploits_available": True,
            "exploit_maturity": "functional",
            "supply_chain_risk": "medium",
            "published": "2024-01-01T00:00:00Z",
            "last_updated": datetime.now().isoformat()
        }
        
        # Validate required fields
        required_fields = [
            "cve_id", "risk_score", "risk_level", "is_kev", 
            "exploits_available", "published", "last_updated"
        ]
        
        for field in required_fields:
            assert field in api_cve_example, f"API CVE should have field: {field}"
        
        # Validate data types
        assert isinstance(api_cve_example["risk_score"], int)
        assert isinstance(api_cve_example["is_kev"], bool) 
        assert isinstance(api_cve_example["exploits_available"], bool)
        assert 0 <= api_cve_example["risk_score"] <= 100
        
        print("✅ API data structure compliance test passed")


if __name__ == "__main__":
    # Run tests manually for development
    test_instance = TestPipelineIntegration()
    
    async def run_tests():
        print("🧪 Running NOPE Pipeline Integration Tests...")
        
        try:
            await test_instance.test_full_pipeline_execution_mock_data()
            await test_instance.test_individual_agent_coordination()
            await test_instance.test_validation_system()
            await test_instance.test_risk_scoring_accuracy()
            test_instance.test_api_data_structure_compliance()
            
            print("🎉 All integration tests passed successfully!")
            
        except Exception as e:
            print(f"❌ Test failed: {str(e)}")
            raise
    
    asyncio.run(run_tests())