"""Tests for the unified audit service."""
import pytest
from unittest.mock import AsyncMock, MagicMock, Mock

from scout.unified_audit_service import (
    UnifiedAuditService,
    UnifiedAuditRequest,
    UnifiedAuditResult,
)


@pytest.fixture
def mock_database():
    """Mock database manager."""
    db = MagicMock()
    return db


@pytest.fixture
def mock_w3():
    """Mock Web3 instance."""
    w3 = MagicMock()
    w3.eth.get_code.return_value = bytes.fromhex("6080604052")
    return w3


@pytest.fixture
def mock_backend_client():
    """Mock backend client."""
    client = AsyncMock()
    client.patch = AsyncMock(return_value=MagicMock(status_code=200))
    return client


@pytest.fixture
def mock_glm_orchestrator():
    """Mock GLM orchestrator."""
    orchestrator = MagicMock()
    orchestrator.analyze_contract = AsyncMock(return_value=[])
    return orchestrator


@pytest.fixture
def mock_token_holder_scout():
    """Mock token holder scout."""
    scout = MagicMock()
    scout.collect_and_store = AsyncMock(return_value={
        "provider": "test",
        "holder_count": 100,
        "metrics": {"gini_coefficient": 0.5},
    })
    return scout


@pytest.fixture
def mock_liquidity_analyzer_scout():
    """Mock liquidity analyzer scout."""
    scout = MagicMock()
    scout.analyze_liquidity = AsyncMock(
        return_value=MagicMock(
            score=75.0,
            risk_level="medium",
            metrics=MagicMock(
                total_tvl_usd=1000000,
                total_pairs=3,
                flags=["low_tvl"],
            ),
            recommendations=["Add more liquidity"],
            analyzed_at="2024-01-01T00:00:00",
        )
    )
    scout.close = AsyncMock()
    return scout


@pytest.fixture
def mock_tokenomics_analyzer_scout():
    """Mock tokenomics analyzer scout."""
    scout = MagicMock()
    scout.analyze_tokenomics = AsyncMock(
        return_value=MagicMock(
            score=80.0,
            risk_level="low",
            metrics=MagicMock(
                supply_tier="capped",
                total_holders=500,
                flags=["uncapped_mint"],
            ),
            recommendations=["Monitor minting"],
            analyzed_at="2024-01-01T00:00:00",
        )
    )
    scout.close = AsyncMock()
    return scout


class TestUnifiedAuditService:
    """Test UnifiedAuditService."""

    def test_init(
        self, mock_database, mock_w3, mock_backend_client, mock_glm_orchestrator
    ):
        """Test service initialization."""
        service = UnifiedAuditService(
            database=mock_database,
            w3=mock_w3,
            backend_client=mock_backend_client,
            glm_orchestrator=mock_glm_orchestrator,
        )

        assert service.database == mock_database
        assert service.w3 == mock_w3
        assert service.backend_client == mock_backend_client
        assert service.glm_orchestrator == mock_glm_orchestrator
        assert service.bytecode_scanner is not None

    @pytest.mark.asyncio
    async def test_run_unified_audit_verified_contract(
        self,
        mock_database,
        mock_w3,
        mock_backend_client,
        mock_glm_orchestrator,
        mock_token_holder_scout,
        mock_liquidity_analyzer_scout,
        mock_tokenomics_analyzer_scout,
    ):
        """Test unified audit for verified contract."""
        # Mock contract_audit_scout
        mock_contract_audit_scout = MagicMock()
        mock_contract_audit_scout.audit_contract = AsyncMock(
            return_value=MagicMock(
                to_dict=MagicMock(
                    return_value={
                        "token_address": "0x1234567890123456789012345678901234567890",
                        "chain_id": "1",
                        "is_verified": True,
                        "overall_score": 85.0,
                        "risk_level": "low",
                        "ai_audit_findings": [],
                        "flags": [],
                    }
                )
            )
        )
        mock_contract_audit_scout.explorer_client.get_source_code = AsyncMock(
            return_value={
                "source_code": "pragma solidity ^0.8.0;",
                "abi": [],
            }
        )

        service = UnifiedAuditService(
            database=mock_database,
            w3=mock_w3,
            backend_client=mock_backend_client,
            glm_orchestrator=mock_glm_orchestrator,
            token_holder_scout=mock_token_holder_scout,
            liquidity_analyzer_scout=mock_liquidity_analyzer_scout,
            tokenomics_analyzer_scout=mock_tokenomics_analyzer_scout,
        )
        service.contract_audit_scout = mock_contract_audit_scout

        result = await service.run_unified_audit(
            project_id="test-project-id",
            token_address="0x1234567890123456789012345678901234567890",
            chain_id=1,
            audit_types=["code", "distribution", "liquidity", "tokenomics"],
        )

        assert isinstance(result, UnifiedAuditResult)
        assert result.project_id == "test-project-id"
        assert result.code_audit is not None
        assert result.distribution_metrics is not None
        assert result.liquidity_metrics is not None
        assert result.tokenomics_metrics is not None
        assert result.overall_score > 0

    @pytest.mark.asyncio
    async def test_run_unified_audit_unverified_contract(
        self,
        mock_database,
        mock_w3,
        mock_backend_client,
        mock_glm_orchestrator,
    ):
        """Test unified audit for unverified contract (bytecode+ABI)."""
        # Mock contract_audit_scout to return not verified
        mock_contract_audit_scout = MagicMock()
        mock_contract_audit_scout.explorer_client.get_source_code = AsyncMock(
            return_value=None
        )

        service = UnifiedAuditService(
            database=mock_database,
            w3=mock_w3,
            backend_client=mock_backend_client,
            glm_orchestrator=mock_glm_orchestrator,
        )
        service.contract_audit_scout = mock_contract_audit_scout

        result = await service.run_unified_audit(
            project_id="test-project-id",
            token_address="0x1234567890123456789012345678901234567890",
            chain_id=1,
            audit_types=["code"],
        )

        assert isinstance(result, UnifiedAuditResult)
        assert result.code_audit is not None
        # Unverified contract should have lower score
        assert result.code_audit.get("overall_score", 100) < 100

    def test_calculate_overall_score(self, mock_database, mock_w3, mock_backend_client):
        """Test overall score calculation."""
        service = UnifiedAuditService(
            database=mock_database,
            w3=mock_w3,
            backend_client=mock_backend_client,
        )

        # Create result with high scores
        result = UnifiedAuditResult(
            project_id="test",
            token_address="0x1234567890123456789012345678901234567890",
            chain_id=1,
            code_audit={"overall_score": 85.0},
            distribution_metrics={
                "metrics": {"gini_coefficient": 0.3}
            },
            liquidity_metrics={"score": 75.0},
            tokenomics_metrics={"score": 80.0},
        )

        score = service._calculate_overall_score(result)
        assert score > 70  # Should be high with all good scores

    def test_determine_risk_level(self, mock_database, mock_w3, mock_backend_client):
        """Test risk level determination."""
        service = UnifiedAuditService(
            database=mock_database,
            w3=mock_w3,
            backend_client=mock_backend_client,
        )

        assert service._determine_risk_level(90) == "low"
        assert service._determine_risk_level(70) == "medium"
        assert service._determine_risk_level(50) == "high"
        assert service._determine_risk_level(20) == "critical"

    def test_aggregate_flags(self, mock_database, mock_w3, mock_backend_client):
        """Test flag aggregation."""
        service = UnifiedAuditService(
            database=mock_database,
            w3=mock_w3,
            backend_client=mock_backend_client,
        )

        result = UnifiedAuditResult(
            project_id="test",
            token_address="0x1234567890123456789012345678901234567890",
            chain_id=1,
            code_audit={"flags": ["flag1", "flag2"]},
            liquidity_metrics={
                "metrics": MagicMock(flags=["flag3", "flag1"])
            },
        )

        flags = service._aggregate_flags(result)
        assert "flag1" in flags
        assert "flag2" in flags
        assert "flag3" in flags
        # Should deduplicate
        assert flags.count("flag1") == 1

    @pytest.mark.asyncio
    async def test_close(
        self,
        mock_database,
        mock_w3,
        mock_backend_client,
        mock_liquidity_analyzer_scout,
        mock_tokenomics_analyzer_scout,
    ):
        """Test closing resources."""
        service = UnifiedAuditService(
            database=mock_database,
            w3=mock_w3,
            backend_client=mock_backend_client,
            liquidity_analyzer_scout=mock_liquidity_analyzer_scout,
            tokenomics_analyzer_scout=mock_tokenomics_analyzer_scout,
        )

        await service.close()

        # Verify close was called
        mock_liquidity_analyzer_scout.close.assert_called_once()
        mock_tokenomics_analyzer_scout.close.assert_called_once()


# ------------------------------------------------------------------
# Tests for code-snippet enrichment helpers
# ------------------------------------------------------------------

class TestParseLocation:
    """Test _parse_location helper."""

    def setup_method(self):
        self.service = UnifiedAuditService(
            database=MagicMock(),
            w3=MagicMock(),
            backend_client=AsyncMock(),
        )

    def test_empty_location(self):
        result = self.service._parse_location("", "DefaultContract")
        assert result == {"contract_name": "DefaultContract"}

    def test_none_like_location(self):
        result = self.service._parse_location("", "DefaultContract")
        assert result["contract_name"] == "DefaultContract"

    def test_contract_line_number(self):
        result = self.service._parse_location("WETH.sol:142", "Default")
        assert result["contract_name"] == "WETH.sol"
        assert result["line_number"] == 142

    def test_contract_function(self):
        result = self.service._parse_location("WETH:deposit()", "Default")
        assert result["contract_name"] == "WETH"
        assert result["function_name"] == "deposit"

    def test_contract_function_with_args(self):
        result = self.service._parse_location("Token:transfer(address,uint256)", "Default")
        assert result["contract_name"] == "Token"
        assert result["function_name"] == "transfer"

    def test_function_alone(self):
        result = self.service._parse_location("withdraw()", "DefaultContract")
        assert result["contract_name"] == "DefaultContract"
        assert result["function_name"] == "withdraw"

    def test_unparseable_location(self):
        result = self.service._parse_location("some random text", "DefaultContract")
        assert result["contract_name"] == "DefaultContract"


class TestExtractFunctionSnippet:
    """Test _extract_function_snippet helper."""

    def setup_method(self):
        self.service = UnifiedAuditService(
            database=MagicMock(),
            w3=MagicMock(),
            backend_client=AsyncMock(),
        )
        self.sample_source = (
            "pragma solidity ^0.8.0;\n"
            "\n"
            "contract Token {\n"
            "    mapping(address => uint256) public balances;\n"
            "\n"
            "    function deposit() public payable {\n"
            "        balances[msg.sender] += msg.value;\n"
            "    }\n"
            "\n"
            "    function withdraw(uint256 amount) public {\n"
            "        require(balances[msg.sender] >= amount, \"Insufficient\");\n"
            "        balances[msg.sender] -= amount;\n"
            "        payable(msg.sender).transfer(amount);\n"
            "    }\n"
            "}\n"
        )

    def test_extract_by_function_name(self):
        result = self.service._extract_function_snippet(
            self.sample_source, function_name="deposit"
        )
        assert result is not None
        assert "function deposit()" in result
        assert "balances[msg.sender] += msg.value" in result

    def test_extract_by_line_number(self):
        result = self.service._extract_function_snippet(
            self.sample_source, line_number=8
        )
        assert result is not None
        # Should contain context around line 8
        assert len(result) > 0

    def test_extract_nonexistent_function(self):
        result = self.service._extract_function_snippet(
            self.sample_source, function_name="nonexistent"
        )
        assert result is None

    def test_extract_empty_source(self):
        result = self.service._extract_function_snippet("")
        assert result is None

    def test_extract_no_params(self):
        result = self.service._extract_function_snippet(self.sample_source)
        assert result is None


class TestExtractBlock:
    """Test _extract_block helper."""

    def setup_method(self):
        self.service = UnifiedAuditService(
            database=MagicMock(),
            w3=MagicMock(),
            backend_client=AsyncMock(),
        )

    def test_simple_block(self):
        lines = [
            "function foo() {",
            "    uint256 x = 1;",
            "}",
        ]
        result = self.service._extract_block(lines, 0)
        assert result is not None
        assert "function foo()" in result
        assert "uint256 x = 1;" in result

    def test_nested_braces(self):
        lines = [
            "function bar() {",
            "    if (true) {",
            "        doSomething();",
            "    }",
            "}",
        ]
        result = self.service._extract_block(lines, 0)
        assert result is not None
        assert "doSomething()" in result

    def test_empty_lines(self):
        result = self.service._extract_block([], 0)
        assert result is None


class TestComputeHighlight:
    """Test _compute_highlight helper."""

    def setup_method(self):
        self.service = UnifiedAuditService(
            database=MagicMock(),
            w3=MagicMock(),
            backend_client=AsyncMock(),
        )

    def test_keyword_match(self):
        snippet = (
            "function withdraw(uint256 amount) public {\n"
            "    require(balances[msg.sender] >= amount);\n"
            "    balances[msg.sender] -= amount;\n"
            "}\n"
        )
        start, end = self.service._compute_highlight(
            snippet, "The withdraw function has a reentrancy vulnerability in amount"
        )
        # Should highlight a line that contains "withdraw" or "amount"
        assert end > start
        highlighted = snippet[start:end]
        assert len(highlighted) > 0

    def test_empty_snippet(self):
        start, end = self.service._compute_highlight("", "some description")
        assert start == 0
        assert end == 0

    def test_no_keyword_match(self):
        snippet = (
            "// comment line\n"
            "uint256 x = 1;\n"
        )
        start, end = self.service._compute_highlight(snippet, "completely unrelated")
        # Should fall back to first non-comment, non-empty line
        assert end > start

    def test_fallback_skips_comments(self):
        snippet = (
            "// This is a comment\n"
            "/* block comment */\n"
            "uint256 actualCode = 42;\n"
        )
        start, end = self.service._compute_highlight(snippet, "xyzzy")
        highlighted = snippet[start:end]
        assert "actualCode" in highlighted


class TestEnrichFindingWithSnippet:
    """Test _enrich_finding_with_snippet end-to-end."""

    def setup_method(self):
        self.service = UnifiedAuditService(
            database=MagicMock(),
            w3=MagicMock(),
            backend_client=AsyncMock(),
        )
        self.sample_source = (
            "pragma solidity ^0.8.0;\n"
            "\n"
            "contract Token {\n"
            "    mapping(address => uint256) public balances;\n"
            "\n"
            "    function deposit() public payable {\n"
            "        balances[msg.sender] += msg.value;\n"
            "    }\n"
            "}\n"
        )

    def test_verified_contract_enrichment(self):
        finding = {
            "location": "Token:deposit()",
            "description": "The deposit function lacks access control",
            "category": "Access Control",
        }
        result = self.service._enrich_finding_with_snippet(
            finding, self.sample_source, "Token", is_verified=True
        )

        assert result["location_detail"]["contract_name"] == "Token"
        assert result["location_detail"]["function_name"] == "deposit"
        assert result["location_detail"]["is_verified"] is True
        assert result["code_snippet"] is not None
        assert "function deposit()" in result["code_snippet"]
        assert result["highlight_start"] is not None
        assert result["highlight_end"] is not None

    def test_unverified_contract_no_snippet(self):
        finding = {
            "location": "Token:deposit()",
            "description": "Some issue",
        }
        result = self.service._enrich_finding_with_snippet(
            finding, self.sample_source, "Token", is_verified=False
        )

        assert result["location_detail"]["is_verified"] is False
        assert result["code_snippet"] is None
        assert result["highlight_start"] is None
        assert result["highlight_end"] is None

    def test_empty_source_code(self):
        finding = {
            "location": "Token:deposit()",
            "description": "Issue",
        }
        result = self.service._enrich_finding_with_snippet(
            finding, "", "Token", is_verified=True
        )

        assert result["code_snippet"] is None
        assert result["highlight_start"] is None

    def test_line_number_location(self):
        finding = {
            "location": "Token.sol:7",
            "description": "Reentrancy risk in balances mapping",
        }
        result = self.service._enrich_finding_with_snippet(
            finding, self.sample_source, "Token", is_verified=True
        )

        assert result["location_detail"]["contract_name"] == "Token.sol"
        assert result["location_detail"]["line_number"] == 7
        assert result["code_snippet"] is not None

    def test_empty_location_uses_default_contract(self):
        finding = {
            "location": "",
            "description": "Some issue",
        }
        result = self.service._enrich_finding_with_snippet(
            finding, self.sample_source, "DefaultContract", is_verified=True
        )

        assert result["location_detail"]["contract_name"] == "DefaultContract"
        # No function name or line number, so snippet extraction may return None
        # depending on the source structure -- but location_detail should be set
        assert "location_detail" in result
