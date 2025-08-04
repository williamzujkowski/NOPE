"""
Data Validation Agent

This agent implements multi-stage validation for the NOPE pipeline,
following Great Expectations patterns to ensure data quality and integrity.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import json
import re
from dataclasses import dataclass

from ..base_agent import BaseAgent, AgentResult


@dataclass
class ValidationCheck:
    """Individual validation check result"""
    name: str
    passed: bool
    expected: Any
    actual: Any
    message: str
    severity: str = "error"  # error, warning, info


@dataclass 
class ValidationResult:
    """Aggregated validation result"""
    stage: str
    passed: int
    failed: int
    warnings: int
    total: int
    checks: List[ValidationCheck]
    is_valid: bool
    errors: List[str]
    execution_time: float
    
    @classmethod
    def aggregate(cls, checks: List[ValidationCheck], stage: str = "unknown") -> 'ValidationResult':
        """Aggregate multiple validation checks"""
        
        passed = sum(1 for c in checks if c.passed)
        failed = sum(1 for c in checks if not c.passed and c.severity == "error")
        warnings = sum(1 for c in checks if not c.passed and c.severity == "warning")
        total = len(checks)
        
        errors = [c.message for c in checks if not c.passed and c.severity == "error"]
        is_valid = failed == 0  # Valid if no errors (warnings allowed)
        
        return cls(
            stage=stage,
            passed=passed,
            failed=failed,
            warnings=warnings,
            total=total,
            checks=checks,
            is_valid=is_valid,
            errors=errors,
            execution_time=0.0
        )


class IngestionValidator:
    """Validates raw CVE data from external sources"""
    
    def __init__(self, logger):
        self.logger = logger
    
    async def validate(self, cve_data: List[Dict]) -> ValidationResult:
        """Validate ingested CVE data"""
        
        start_time = datetime.now()
        checks = []
        
        # Check 1: Data structure validation
        checks.extend(await self.check_data_structure(cve_data))
        
        # Check 2: Required fields validation
        checks.extend(await self.check_required_fields(cve_data))
        
        # Check 3: CVE ID format validation
        checks.extend(await self.check_cve_id_format(cve_data))
        
        # Check 4: Date format validation
        checks.extend(await self.check_date_formats(cve_data))
        
        # Check 5: Duplicate detection
        checks.extend(await self.check_duplicates(cve_data))
        
        # Check 6: Data freshness
        checks.extend(await self.check_data_freshness(cve_data))
        
        execution_time = (datetime.now() - start_time).total_seconds()
        result = ValidationResult.aggregate(checks, "ingestion")
        result.execution_time = execution_time
        
        return result
    
    async def check_data_structure(self, cve_data: List[Dict]) -> List[ValidationCheck]:
        """Check basic data structure"""
        checks = []
        
        # Check if data is a list
        checks.append(ValidationCheck(
            name="data_is_list",
            passed=isinstance(cve_data, list),
            expected="list",
            actual=type(cve_data).__name__,
            message="CVE data must be a list"
        ))
        
        # Check if list is not empty
        checks.append(ValidationCheck(
            name="data_not_empty",
            passed=len(cve_data) > 0 if isinstance(cve_data, list) else False,
            expected="> 0",
            actual=len(cve_data) if isinstance(cve_data, list) else 0,
            message="CVE data list cannot be empty"
        ))
        
        # Check reasonable data size (not too large)
        max_reasonable_size = 50000  # Max 50k CVEs per batch
        checks.append(ValidationCheck(
            name="data_size_reasonable",
            passed=len(cve_data) <= max_reasonable_size if isinstance(cve_data, list) else False,
            expected=f"<= {max_reasonable_size}",
            actual=len(cve_data) if isinstance(cve_data, list) else 0,
            message=f"CVE data size exceeds reasonable limit of {max_reasonable_size}",
            severity="warning"
        ))
        
        return checks
    
    async def check_required_fields(self, cve_data: List[Dict]) -> List[ValidationCheck]:
        """Check required fields in CVE records"""
        checks = []
        
        required_fields = ["cve_id", "description"]
        optional_important_fields = ["published", "severity", "cvss"]
        
        if not isinstance(cve_data, list) or len(cve_data) == 0:
            return checks
        
        # Sample first 100 records for field validation
        sample_size = min(100, len(cve_data))
        
        for field in required_fields:
            missing_count = 0
            empty_count = 0
            
            for cve in cve_data[:sample_size]:
                if not isinstance(cve, dict):
                    missing_count += 1
                    continue
                    
                if field not in cve:
                    missing_count += 1
                elif not cve[field] or (isinstance(cve[field], str) and not cve[field].strip()):
                    empty_count += 1
            
            # Check for missing required fields
            missing_rate = missing_count / sample_size
            checks.append(ValidationCheck(
                name=f"required_field_{field}",
                passed=missing_rate <= 0.05,  # Allow up to 5% missing
                expected="<= 5% missing",
                actual=f"{missing_rate*100:.1f}% missing",
                message=f"Required field '{field}' missing in {missing_rate*100:.1f}% of records"
            ))
            
            # Check for empty required fields
            empty_rate = empty_count / sample_size
            checks.append(ValidationCheck(
                name=f"required_field_{field}_not_empty",
                passed=empty_rate <= 0.10,  # Allow up to 10% empty
                expected="<= 10% empty",
                actual=f"{empty_rate*100:.1f}% empty",
                message=f"Required field '{field}' empty in {empty_rate*100:.1f}% of records",
                severity="warning" if empty_rate <= 0.20 else "error"
            ))
        
        # Check optional important fields
        for field in optional_important_fields:
            missing_count = sum(1 for cve in cve_data[:sample_size] 
                              if not isinstance(cve, dict) or field not in cve)
            
            missing_rate = missing_count / sample_size
            checks.append(ValidationCheck(
                name=f"optional_field_{field}",
                passed=missing_rate <= 0.50,  # Allow up to 50% missing for optional
                expected="<= 50% missing",
                actual=f"{missing_rate*100:.1f}% missing",
                message=f"Optional field '{field}' missing in {missing_rate*100:.1f}% of records",
                severity="warning"
            ))
        
        return checks
    
    async def check_cve_id_format(self, cve_data: List[Dict]) -> List[ValidationCheck]:
        """Check CVE ID format validation"""
        checks = []
        
        if not isinstance(cve_data, list) or len(cve_data) == 0:
            return checks
        
        cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
        invalid_count = 0
        sample_size = min(1000, len(cve_data))
        
        for cve in cve_data[:sample_size]:
            if not isinstance(cve, dict):
                invalid_count += 1
                continue
                
            cve_id = cve.get("cve_id", "")
            if not isinstance(cve_id, str) or not cve_pattern.match(cve_id):
                invalid_count += 1
        
        invalid_rate = invalid_count / sample_size
        checks.append(ValidationCheck(
            name="cve_id_format",
            passed=invalid_rate <= 0.01,  # Allow up to 1% invalid
            expected="<= 1% invalid format",
            actual=f"{invalid_rate*100:.1f}% invalid",
            message=f"CVE ID format invalid in {invalid_rate*100:.1f}% of records"
        ))
        
        return checks
    
    async def check_date_formats(self, cve_data: List[Dict]) -> List[ValidationCheck]:
        """Check date format validation"""
        checks = []
        
        if not isinstance(cve_data, list) or len(cve_data) == 0:
            return checks
        
        date_fields = ["published", "modified"]
        sample_size = min(500, len(cve_data))
        
        for field in date_fields:
            invalid_count = 0
            present_count = 0
            
            for cve in cve_data[:sample_size]:
                if not isinstance(cve, dict) or field not in cve:
                    continue
                    
                present_count += 1
                date_value = cve[field]
                
                if not isinstance(date_value, str):
                    invalid_count += 1
                    continue
                
                # Try parsing common date formats
                try:
                    # ISO format with Z
                    if date_value.endswith('Z'):
                        datetime.fromisoformat(date_value.replace('Z', '+00:00'))
                    else:
                        datetime.fromisoformat(date_value)
                except ValueError:
                    invalid_count += 1
            
            if present_count > 0:
                invalid_rate = invalid_count / present_count
                checks.append(ValidationCheck(
                    name=f"date_format_{field}",
                    passed=invalid_rate <= 0.05,  # Allow up to 5% invalid dates
                    expected="<= 5% invalid format",
                    actual=f"{invalid_rate*100:.1f}% invalid",
                    message=f"Date field '{field}' has invalid format in {invalid_rate*100:.1f}% of records",
                    severity="warning"
                ))
        
        return checks
    
    async def check_duplicates(self, cve_data: List[Dict]) -> List[ValidationCheck]:
        """Check for duplicate CVE records"""
        checks = []
        
        if not isinstance(cve_data, list) or len(cve_data) == 0:
            return checks
        
        cve_ids = []
        for cve in cve_data:
            if isinstance(cve, dict) and "cve_id" in cve:
                cve_ids.append(cve["cve_id"])
        
        total_cves = len(cve_ids)
        unique_cves = len(set(cve_ids))
        duplicate_count = total_cves - unique_cves
        
        duplicate_rate = duplicate_count / total_cves if total_cves > 0 else 0
        
        checks.append(ValidationCheck(
            name="no_duplicates",
            passed=duplicate_rate <= 0.01,  # Allow up to 1% duplicates
            expected="<= 1% duplicates",
            actual=f"{duplicate_rate*100:.1f}% duplicates ({duplicate_count} total)",
            message=f"Found {duplicate_count} duplicate CVE records ({duplicate_rate*100:.1f}%)",
            severity="warning" if duplicate_rate <= 0.05 else "error"
        ))
        
        return checks
    
    async def check_data_freshness(self, cve_data: List[Dict]) -> List[ValidationCheck]:
        """Check data freshness"""
        checks = []
        
        if not isinstance(cve_data, list) or len(cve_data) == 0:
            return checks
        
        now = datetime.now()
        recent_count = 0  # CVEs from last 7 days
        very_old_count = 0  # CVEs older than 3 years
        sample_size = min(1000, len(cve_data))
        
        for cve in cve_data[:sample_size]:
            if not isinstance(cve, dict) or "published" not in cve:
                continue
            
            try:
                published_str = cve["published"]
                if isinstance(published_str, str):
                    if published_str.endswith('Z'):
                        published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                    else:
                        published_date = datetime.fromisoformat(published_str)
                    
                    days_old = (now - published_date.replace(tzinfo=None)).days
                    
                    if days_old <= 7:
                        recent_count += 1
                    elif days_old > 1095:  # 3 years
                        very_old_count += 1
                        
            except (ValueError, TypeError):
                continue
        
        recent_rate = recent_count / sample_size
        old_rate = very_old_count / sample_size
        
        # Expect some recent CVEs (indicates fresh data)
        checks.append(ValidationCheck(
            name="has_recent_cves",
            passed=recent_rate >= 0.01,  # At least 1% from last week
            expected=">= 1% recent (last 7 days)",
            actual=f"{recent_rate*100:.1f}% recent",
            message=f"Only {recent_rate*100:.1f}% of CVEs are from last 7 days - data may be stale",
            severity="warning"
        ))
        
        # Flag if too many very old CVEs (may indicate data quality issues)
        checks.append(ValidationCheck(
            name="not_too_many_old_cves",
            passed=old_rate <= 0.80,  # Less than 80% should be over 3 years old
            expected="<= 80% very old (>3 years)",
            actual=f"{old_rate*100:.1f}% very old",
            message=f"{old_rate*100:.1f}% of CVEs are over 3 years old",
            severity="info"
        ))
        
        return checks


class EPSSFilterValidator:
    """Validates EPSS filtering compliance"""
    
    def __init__(self, logger):
        self.logger = logger
    
    async def validate(self, filtered_cves: List[Dict], min_threshold: float = 0.6) -> ValidationResult:
        """Validate EPSS filtering results"""
        
        start_time = datetime.now()
        checks = []
        
        # Check 1: EPSS threshold compliance
        checks.extend(await self.check_epss_threshold_compliance(filtered_cves, min_threshold))
        
        # Check 2: Reasonable CVE count
        checks.extend(await self.check_cve_count_reasonable(filtered_cves, max_count=1000))
        
        # Check 3: Severity distribution
        checks.extend(await self.check_severity_distribution(filtered_cves))
        
        # Check 4: No stale data
        checks.extend(await self.check_no_stale_data(filtered_cves))
        
        # Check 5: EPSS data quality
        checks.extend(await self.check_epss_data_quality(filtered_cves))
        
        execution_time = (datetime.now() - start_time).total_seconds()
        result = ValidationResult.aggregate(checks, "epss_filter")
        result.execution_time = execution_time
        
        return result
    
    async def check_epss_threshold_compliance(self, filtered_cves: List[Dict], min_threshold: float) -> List[ValidationCheck]:
        """Check EPSS threshold compliance"""
        checks = []
        
        if not isinstance(filtered_cves, list):
            checks.append(ValidationCheck(
                name="epss_data_structure",
                passed=False,
                expected="list",
                actual=type(filtered_cves).__name__,
                message="Filtered CVEs must be a list"
            ))
            return checks
        
        if len(filtered_cves) == 0:
            checks.append(ValidationCheck(
                name="epss_has_results",
                passed=True,  # Empty result is valid if no CVEs meet threshold
                expected="list (may be empty)",
                actual="empty list",
                message="No CVEs meet EPSS threshold - this may be valid",
                severity="info"
            ))
            return checks
        
        # Check EPSS compliance
        non_compliant_count = 0
        missing_epss_count = 0
        
        for cve in filtered_cves:
            if not isinstance(cve, dict):
                non_compliant_count += 1
                continue
            
            epss_data = cve.get("epss", {})
            if not isinstance(epss_data, dict):
                missing_epss_count += 1
                non_compliant_count += 1
                continue
            
            epss_score = epss_data.get("score")
            if not isinstance(epss_score, (int, float)) or epss_score < min_threshold:
                non_compliant_count += 1
        
        total_cves = len(filtered_cves)
        compliance_rate = (total_cves - non_compliant_count) / total_cves
        
        checks.append(ValidationCheck(
            name="epss_threshold_compliance",
            passed=compliance_rate >= 0.95,  # 95% must meet threshold
            expected=f">= 95% with EPSS >= {min_threshold}",
            actual=f"{compliance_rate*100:.1f}% compliant",
            message=f"{non_compliant_count} CVEs do not meet EPSS threshold of {min_threshold}"
        ))
        
        # Check for missing EPSS data
        missing_rate = missing_epss_count / total_cves
        checks.append(ValidationCheck(
            name="epss_data_present",
            passed=missing_rate <= 0.05,  # Allow up to 5% missing
            expected="<= 5% missing EPSS",
            actual=f"{missing_rate*100:.1f}% missing",
            message=f"{missing_epss_count} CVEs missing EPSS data"
        ))
        
        return checks
    
    async def check_cve_count_reasonable(self, filtered_cves: List[Dict], max_count: int) -> List[ValidationCheck]:
        """Check CVE count is reasonable"""
        checks = []
        
        actual_count = len(filtered_cves) if isinstance(filtered_cves, list) else 0
        
        # Check maximum count
        checks.append(ValidationCheck(
            name="cve_count_not_excessive",
            passed=actual_count <= max_count,
            expected=f"<= {max_count}",
            actual=actual_count,
            message=f"CVE count {actual_count} exceeds maximum {max_count} - may indicate filtering failure"
        ))
        
        # Check minimum count (warning if too few)
        min_expected = 10  # Expect at least 10 high-risk CVEs normally
        checks.append(ValidationCheck(
            name="cve_count_sufficient",
            passed=actual_count >= min_expected,
            expected=f">= {min_expected}",
            actual=actual_count,
            message=f"Only {actual_count} CVEs found - unusually low, may indicate data issues",
            severity="warning"
        ))
        
        return checks
    
    async def check_severity_distribution(self, filtered_cves: List[Dict]) -> List[ValidationCheck]:
        """Check severity distribution is reasonable"""
        checks = []
        
        if not isinstance(filtered_cves, list) or len(filtered_cves) == 0:
            return checks
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        for cve in filtered_cves:
            if isinstance(cve, dict):
                severity = cve.get("severity", "UNKNOWN").upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts["UNKNOWN"] += 1
        
        total = len(filtered_cves)
        critical_rate = severity_counts["CRITICAL"] / total
        high_rate = severity_counts["HIGH"] / total
        
        # Expect high proportion of CRITICAL and HIGH for EPSS filtered data
        high_severity_rate = (severity_counts["CRITICAL"] + severity_counts["HIGH"]) / total
        
        checks.append(ValidationCheck(
            name="severity_distribution_reasonable",
            passed=high_severity_rate >= 0.60,  # At least 60% should be CRITICAL or HIGH
            expected=">= 60% CRITICAL or HIGH",
            actual=f"{high_severity_rate*100:.1f}% high severity",
            message=f"Only {high_severity_rate*100:.1f}% are CRITICAL or HIGH severity",
            severity="warning"
        ))
        
        return checks
    
    async def check_no_stale_data(self, filtered_cves: List[Dict]) -> List[ValidationCheck]:
        """Check for stale data that should have been cleaned"""
        checks = []
        
        if not isinstance(filtered_cves, list) or len(filtered_cves) == 0:
            return checks
        
        # Check for very old CVEs that might be stale
        now = datetime.now()
        very_old_count = 0
        sample_size = min(100, len(filtered_cves))
        
        for cve in filtered_cves[:sample_size]:
            if not isinstance(cve, dict):
                continue
            
            published_str = cve.get("published")
            if isinstance(published_str, str):
                try:
                    if published_str.endswith('Z'):
                        published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                    else:
                        published_date = datetime.fromisoformat(published_str)
                    
                    days_old = (now - published_date.replace(tzinfo=None)).days
                    if days_old > 2190:  # 6 years
                        very_old_count += 1
                        
                except (ValueError, TypeError):
                    continue
        
        old_rate = very_old_count / sample_size
        
        checks.append(ValidationCheck(
            name="no_excessive_stale_data",
            passed=old_rate <= 0.20,  # Less than 20% should be over 6 years old
            expected="<= 20% very old (>6 years)",
            actual=f"{old_rate*100:.1f}% very old",
            message=f"{old_rate*100:.1f}% of CVEs are over 6 years old - may be stale",
            severity="warning"
        ))
        
        return checks
    
    async def check_epss_data_quality(self, filtered_cves: List[Dict]) -> List[ValidationCheck]:
        """Check EPSS data quality"""
        checks = []
        
        if not isinstance(filtered_cves, list) or len(filtered_cves) == 0:
            return checks
        
        invalid_scores = 0
        missing_percentile = 0
        sample_size = min(200, len(filtered_cves))
        
        for cve in filtered_cves[:sample_size]:
            if not isinstance(cve, dict):
                continue
            
            epss_data = cve.get("epss", {})
            if not isinstance(epss_data, dict):
                invalid_scores += 1
                continue
            
            # Check score validity
            score = epss_data.get("score")
            if not isinstance(score, (int, float)) or not (0 <= score <= 1):
                invalid_scores += 1
            
            # Check percentile presence
            percentile = epss_data.get("percentile")
            if not isinstance(percentile, (int, float)):
                missing_percentile += 1
        
        invalid_rate = invalid_scores / sample_size
        missing_percentile_rate = missing_percentile / sample_size
        
        checks.append(ValidationCheck(
            name="epss_scores_valid",
            passed=invalid_rate <= 0.05,
            expected="<= 5% invalid scores",
            actual=f"{invalid_rate*100:.1f}% invalid",
            message=f"{invalid_rate*100:.1f}% of EPSS scores are invalid"
        ))
        
        checks.append(ValidationCheck(
            name="epss_percentiles_present",
            passed=missing_percentile_rate <= 0.10,
            expected="<= 10% missing percentiles",
            actual=f"{missing_percentile_rate*100:.1f}% missing",
            message=f"{missing_percentile_rate*100:.1f}% of EPSS percentiles are missing",
            severity="warning"
        ))
        
        return checks


class DataValidationAgent(BaseAgent):
    """Agent for multi-stage data validation"""
    
    def __init__(self):
        super().__init__("DataValidationAgent")
        self.validators = {
            "stage1_ingestion": IngestionValidator(self.logger),
            "stage2_epss_filter": EPSSFilterValidator(self.logger),
        }
        
    async def initialize(self) -> bool:
        """Initialize agent"""
        init_success = await super().initialize()
        if not init_success:
            return False
            
        await self.notify_progress(f"Initialized with {len(self.validators)} validation stages")
        return True
    
    async def validate_stage(self, stage: str, data: Any, **kwargs) -> ValidationResult:
        """Validate data at specific pipeline stage"""
        
        validator = self.validators.get(stage)
        if not validator:
            raise ValueError(f"Unknown validation stage: {stage}")
        
        try:
            await self.notify_progress(f"Starting validation for stage: {stage}")
            
            # Run validation
            result = await validator.validate(data, **kwargs)
            
            # Store validation results
            await self.store_coordination_data(f"validation_{stage}", {
                "stage": stage,
                "passed": result.passed,
                "failed": result.failed,
                "warnings": result.warnings,
                "total": result.total,
                "is_valid": result.is_valid,
                "execution_time": result.execution_time,
                "timestamp": datetime.now().isoformat()
            })
            
            await self.notify_progress(
                f"Stage {stage} validation: {result.passed}/{result.total} passed, "
                f"{result.failed} failed, {result.warnings} warnings"
            )
            
            if not result.is_valid:
                self.logger.error(
                    "validation_failed",
                    stage=stage,
                    errors=result.errors[:5]  # Log first 5 errors
                )
            
            return result
            
        except Exception as e:
            self.logger.error("validation_error", stage=stage, error=str(e))
            raise ValueError(f"Stage {stage} validation failed: {str(e)}")
    
    async def enrich_cve(self, cve: Dict) -> Dict:
        """This agent doesn't enrich individual CVEs"""
        return cve