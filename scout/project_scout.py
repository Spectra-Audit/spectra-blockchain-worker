"""Project scouting utilities."""

from __future__ import annotations

import argparse
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .backend_client import BackendClient
from .database_manager import DatabaseManager
from .env_loader import load_env_file

LOGGER = logging.getLogger(__name__)


@dataclass
class ProjectMetrics:
    """Metrics for a project used in scoring and ranking."""
    project_id: str
    name: str
    creator_address: str
    description: str
    category: Optional[str] = None
    created_at: Optional[str] = None
    total_funding: Optional[float] = None
    backer_count: Optional[int] = None
    featured_bid: Optional[float] = None
    round_participation: Optional[int] = None
    success_rate: Optional[float] = None
    social_links: Optional[Dict[str, str]] = None
    tags: Optional[List[str]] = None

    # Computed metrics
    engagement_score: float = 0.0
    growth_score: float = 0.0
    quality_score: float = 0.0
    overall_score: float = 0.0
    last_updated: float = field(default_factory=time.time)


@dataclass
class ScanConfig:
    """Configuration for project scanning."""
    # Filter criteria
    min_funding: float = 0.0
    max_funding: Optional[float] = None
    min_backers: int = 0
    max_backers: Optional[int] = None
    categories: Optional[List[str]] = None
    exclude_categories: Optional[List[str]] = None
    min_success_rate: float = 0.0

    # Scoring weights
    funding_weight: float = 0.3
    engagement_weight: float = 0.25
    growth_weight: float = 0.25
    quality_weight: float = 0.2

    # Time-based filters
    days_since_creation: Optional[int] = None
    active_in_last_days: int = 30

    # Results
    max_results: int = 100
    sort_by: str = "overall_score"  # overall_score, funding, engagement, growth, quality


class ProjectScout:
    """Scout responsible for discovering and analyzing promising projects."""

    def __init__(
        self,
        backend_client: BackendClient,
        database_manager: DatabaseManager,
        config: Optional[ScanConfig] = None,
    ) -> None:
        """Initialize the ProjectScout.

        Args:
            backend_client: HTTP client for backend API communication
            database_manager: Shared database manager for persistence
            config: Scanning configuration (uses defaults if None)
        """
        self._backend = backend_client
        self._db = database_manager
        self._config = config or ScanConfig()
        self._lock = threading.RLock()
        self._last_scan_time: Optional[float] = None
        self._cached_projects: List[ProjectMetrics] = []

        # Ensure project data schema exists
        self._ensure_project_schema()

    def _ensure_project_schema(self) -> None:
        """Create tables needed for project scouting data."""
        with self._db.write_connection() as conn:
            # Table for storing project metrics
            conn.execute("""
                CREATE TABLE IF NOT EXISTS project_metrics (
                    project_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    creator_address TEXT NOT NULL,
                    description TEXT,
                    category TEXT,
                    created_at TEXT,
                    total_funding REAL,
                    backer_count INTEGER,
                    featured_bid REAL,
                    round_participation INTEGER,
                    success_rate REAL,
                    social_links TEXT,  -- JSON
                    tags TEXT,  -- JSON
                    engagement_score REAL DEFAULT 0.0,
                    growth_score REAL DEFAULT 0.0,
                    quality_score REAL DEFAULT 0.0,
                    overall_score REAL DEFAULT 0.0,
                    last_updated REAL,
                    raw_data TEXT  -- Complete JSON response
                )
            """)

            # Table for scan results and snapshots
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_timestamp REAL NOT NULL,
                    total_projects INTEGER,
                    new_projects INTEGER,
                    updated_projects INTEGER,
                    top_projects TEXT,  -- JSON array of top project IDs
                    config_hash TEXT,  -- Hash of configuration used
                    notes TEXT
                )
            """)

            # Table for tracking project trends
            conn.execute("""
                CREATE TABLE IF NOT EXISTS project_trends (
                    project_id TEXT,
                    timestamp REAL NOT NULL,
                    funding REAL,
                    backers INTEGER,
                    engagement_score REAL,
                    overall_score REAL,
                    PRIMARY KEY (project_id, timestamp),
                    FOREIGN KEY (project_id) REFERENCES project_metrics(project_id)
                )
            """)

            conn.commit()

    def scan(self, force_refresh: bool = False) -> List[ProjectMetrics]:
        """Scan for projects and analyze them for opportunities.

        Args:
            force_refresh: If True, bypass cache and fetch fresh data

        Returns:
            List of analyzed project metrics sorted by overall score
        """
        LOGGER.info("Starting project scan with config: %s", asdict(self._config))

        try:
            # Fetch projects from backend API
            projects_data = self._fetch_projects()
            LOGGER.info("Fetched %d projects from backend", len(projects_data))

            # Analyze and score projects
            analyzed_projects = []
            for project_data in projects_data:
                try:
                    metrics = self._analyze_project(project_data)
                    if self._passes_filters(metrics):
                        analyzed_projects.append(metrics)
                except Exception as e:
                    LOGGER.warning("Failed to analyze project %s: %s",
                                 project_data.get('id', 'unknown'), e)
                    continue

            # Sort by overall score (descending)
            analyzed_projects.sort(key=lambda p: p.overall_score, reverse=True)

            # Limit results
            analyzed_projects = analyzed_projects[:self._config.max_results]

            # Store results in database
            self._store_scan_results(analyzed_projects)

            # Update cache and scan time
            with self._lock:
                self._cached_projects = analyzed_projects
                self._last_scan_time = time.time()

            # Store last scan timestamp in database
            self._db.set_meta("project_last_scan", str(self._last_scan_time))

            LOGGER.info("Scan completed: %d projects analyzed and scored",
                       len(analyzed_projects))
            return analyzed_projects

        except Exception as e:
            LOGGER.error("Project scan failed: %s", e)
            raise

    def _fetch_projects(self) -> List[Dict[str, Any]]:
        """Fetch project data from the backend API."""
        projects = []

        try:
            # Fetch projects with pagination
            page = 1
            per_page = 100

            while True:
                response = self._backend.get(
                    f"/projects?page={page}&per_page={per_page}&include_stats=true"
                )

                if not response.ok:
                    raise Exception(f"Failed to fetch projects: {response.status_code}")

                data = response.json()
                page_projects = data.get("projects", [])

                if not page_projects:
                    break

                projects.extend(page_projects)

                # Check if we have more pages
                if len(page_projects) < per_page:
                    break

                page += 1

        except Exception as e:
            LOGGER.error("Failed to fetch projects from backend: %s", e)
            raise

        return projects

    def _analyze_project(self, project_data: Dict[str, Any]) -> ProjectMetrics:
        """Analyze a single project and compute metrics."""
        project_id = project_data.get("id", "")

        # Basic metrics
        metrics = ProjectMetrics(
            project_id=project_id,
            name=project_data.get("name", ""),
            creator_address=project_data.get("creator_address", ""),
            description=project_data.get("description", ""),
            category=project_data.get("category"),
            created_at=project_data.get("created_at"),
            total_funding=float(project_data.get("total_funding", 0)),
            backer_count=int(project_data.get("backer_count", 0)),
            featured_bid=float(project_data.get("featured_bid", 0)) if project_data.get("featured_bid") else None,
            round_participation=int(project_data.get("round_participation", 0)),
            success_rate=float(project_data.get("success_rate", 0)) if project_data.get("success_rate") else None,
            social_links=project_data.get("social_links", {}),
            tags=project_data.get("tags", []),
        )

        # Compute engagement score
        metrics.engagement_score = self._compute_engagement_score(metrics)

        # Compute growth score
        metrics.growth_score = self._compute_growth_score(project_data)

        # Compute quality score
        metrics.quality_score = self._compute_quality_score(metrics, project_data)

        # Compute overall weighted score
        metrics.overall_score = (
            metrics.engagement_score * self._config.engagement_weight +
            metrics.growth_score * self._config.growth_weight +
            metrics.quality_score * self._config.quality_weight +
            self._normalize_funding_score(metrics.total_funding) * self._config.funding_weight
        )

        return metrics

    def _compute_engagement_score(self, metrics: ProjectMetrics) -> float:
        """Compute engagement score based on backers, social presence, etc."""
        score = 0.0

        # Backer engagement (0-40 points)
        if metrics.backer_count:
            # Logarithmic scale: 1 backer = 5 points, 100 backers = 35 points, 1000+ = 40 points
            backer_score = min(40, 5 + math.log10(max(1, metrics.backer_count)) * 12)
            score += backer_score

        # Social links (0-20 points)
        if metrics.social_links:
            social_count = len([v for v in metrics.social_links.values() if v])
            social_score = min(20, social_count * 5)
            score += social_score

        # Featured participation (0-20 points)
        if metrics.round_participation and metrics.round_participation > 0:
            # Multiple round participation shows sustained engagement
            participation_score = min(20, metrics.round_participation * 10)
            score += participation_score

        # Success rate (0-20 points)
        if metrics.success_rate:
            success_score = metrics.success_rate * 20
            score += success_score

        return min(100, score)

    def _compute_growth_score(self, project_data: Dict[str, Any]) -> float:
        """Compute growth score based on project trajectory."""
        score = 50.0  # Base score

        try:
            # Get historical data from database
            project_id = project_data.get("id")
            if not project_id:
                return score

            with self._db.read_connection() as conn:
                cursor = conn.execute("""
                    SELECT timestamp, funding, backers, overall_score
                    FROM project_trends
                    WHERE project_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 10
                """, (project_id,))

                historical_data = cursor.fetchall()

            if len(historical_data) >= 2:
                # Compare with previous data point
                latest = historical_data[0]
                previous = historical_data[1]

                # Funding growth
                if latest[1] and previous[1]:  # funding
                    funding_growth = (latest[1] - previous[1]) / max(1, previous[1])
                    score += min(25, funding_growth * 100)

                # Backer growth
                if latest[2] and previous[2]:  # backers
                    backer_growth = (latest[2] - previous[2]) / max(1, previous[2])
                    score += min(25, backer_growth * 50)

        except Exception as e:
            LOGGER.debug("Failed to compute growth score: %s", e)

        return min(100, max(0, score))

    def _compute_quality_score(self, metrics: ProjectMetrics, project_data: Dict[str, Any]) -> float:
        """Compute quality score based on project completeness and professionalism."""
        score = 0.0

        # Description quality (0-30 points)
        if metrics.description:
            desc_length = len(metrics.description)
            if desc_length > 500:
                score += 30
            elif desc_length > 200:
                score += 20
            elif desc_length > 50:
                score += 10

        # Project completeness (0-30 points)
        completeness_fields = [
            metrics.category,
            metrics.social_links,
            metrics.tags,
            project_data.get("cover_image"),
            project_data.get("demo_url"),
            project_data.get("github_url"),
        ]
        filled_fields = sum(1 for field in completeness_fields if field)
        score += min(30, filled_fields * 5)

        # Professional features (0-20 points)
        professional_features = [
            project_data.get("demo_url"),
            project_data.get("github_url"),
            project_data.get("whitepaper_url"),
            project_data.get("roadmap_url"),
        ]
        feature_count = sum(1 for feature in professional_features if feature)
        score += min(20, feature_count * 5)

        # Featured bid presence (0-20 points)
        if metrics.featured_bid and metrics.featured_bid > 0:
            score += min(20, metrics.featured_bid / 100)  # Scale by bid amount

        return min(100, score)

    def _normalize_funding_score(self, funding: Optional[float]) -> float:
        """Normalize funding to a 0-100 score using logarithmic scale."""
        if not funding or funding <= 0:
            return 0.0

        # Logarithmic scale: $1 = 10 points, $100 = 40 points, $10K = 70 points, $1M = 100 points
        return min(100, 10 + math.log10(max(1, funding)) * 15)

    def _passes_filters(self, metrics: ProjectMetrics) -> bool:
        """Check if project passes configured filters."""
        # Funding filters
        if metrics.total_funding < self._config.min_funding:
            return False
        if self._config.max_funding and metrics.total_funding > self._config.max_funding:
            return False

        # Backer filters
        if metrics.backer_count < self._config.min_backers:
            return False
        if self._config.max_backers and metrics.backer_count > self._config.max_backers:
            return False

        # Category filters
        if self._config.categories and metrics.category not in self._config.categories:
            return False
        if self._config.exclude_categories and metrics.category in self._config.exclude_categories:
            return False

        # Success rate filter
        if metrics.success_rate and metrics.success_rate < self._config.min_success_rate:
            return False

        # Time-based filters
        if self._config.days_since_creation and metrics.created_at:
            # Simple date comparison (would need proper date parsing in production)
            pass

        return True

    def _store_scan_results(self, projects: List[ProjectMetrics]) -> None:
        """Store scan results in the database."""
        with self._db.write_connection() as conn:
            new_count = 0
            updated_count = 0

            for project in projects:
                # Check if project exists
                cursor = conn.execute(
                    "SELECT project_id FROM project_metrics WHERE project_id = ?",
                    (project.project_id,)
                )
                exists = cursor.fetchone() is not None

                # Store project metrics
                conn.execute("""
                    INSERT OR REPLACE INTO project_metrics
                    (project_id, name, creator_address, description, category,
                     created_at, total_funding, backer_count, featured_bid,
                     round_participation, success_rate, social_links, tags,
                     engagement_score, growth_score, quality_score, overall_score,
                     last_updated, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    project.project_id, project.name, project.creator_address,
                    project.description, project.category, project.created_at,
                    project.total_funding, project.backer_count, project.featured_bid,
                    project.round_participation, project.success_rate,
                    json.dumps(project.social_links) if project.social_links else None,
                    json.dumps(project.tags) if project.tags else None,
                    project.engagement_score, project.growth_score, project.quality_score,
                    project.overall_score, project.last_updated,
                    json.dumps(asdict(project))
                ))

                if exists:
                    updated_count += 1
                else:
                    new_count += 1

            # Create scan snapshot
            top_projects = [p.project_id for p in projects[:10]]  # Top 10
            conn.execute("""
                INSERT INTO scan_snapshots
                (scan_timestamp, total_projects, new_projects, updated_projects,
                 top_projects, config_hash, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                time.time(), len(projects), new_count, updated_count,
                json.dumps(top_projects), str(hash(str(asdict(self._config)))),
                f"Scan completed with {len(projects)} projects"
            ))

            conn.commit()

    def report(self, format_type: str = "text") -> str:
        """Generate a comprehensive report of project discoveries.

        Args:
            format_type: Output format ("text", "json", or "csv")

        Returns:
            Formatted report string
        """
        LOGGER.info("Generating project discovery report in %s format", format_type)

        # Get latest scan data if cache is empty
        if not self._cached_projects:
            self._load_latest_scan()

        if not self._cached_projects:
            return "No project data available. Run scan() first."

        if format_type.lower() == "json":
            return self._generate_json_report()
        elif format_type.lower() == "csv":
            return self._generate_csv_report()
        else:
            return self._generate_text_report()

    def _load_latest_scan(self) -> None:
        """Load the most recent scan results from database."""
        with self._db.read_connection() as conn:
            cursor = conn.execute("""
                SELECT raw_data FROM project_metrics
                ORDER BY overall_score DESC, last_updated DESC
                LIMIT 100
            """)

            self._cached_projects = []
            for row in cursor.fetchall():
                project_dict = json.loads(row[0])
                project = ProjectMetrics(**project_dict)
                self._cached_projects.append(project)

    def _generate_text_report(self) -> str:
        """Generate a text-based report."""
        projects = self._cached_projects

        report_lines = [
            "PROJECT DISCOVERY REPORT",
            "=" * 50,
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Projects Analyzed: {len(projects)}",
            f"Configuration: {asdict(self._config)}",
            "",
            "TOP 20 PROJECTS BY OVERALL SCORE",
            "-" * 50,
        ]

        for i, project in enumerate(projects[:20], 1):
            report_lines.extend([
                f"{i:2d}. {project.name} (Score: {project.overall_score:.1f})",
                f"    ID: {project.project_id}",
                f"    Category: {project.category or 'N/A'}",
                f"    Funding: ${project.total_funding:,.2f}",
                f"    Backers: {project.backer_count:,}",
                f"    Engagement: {project.engagement_score:.1f}/100",
                f"    Growth: {project.growth_score:.1f}/100",
                f"    Quality: {project.quality_score:.1f}/100",
                f"    Creator: {project.creator_address}",
                "",
            ])

        # Summary statistics
        if projects:
            avg_funding = sum(p.total_funding for p in projects) / len(projects)
            avg_backers = sum(p.backer_count for p in projects) / len(projects)
            avg_score = sum(p.overall_score for p in projects) / len(projects)

            report_lines.extend([
                "SUMMARY STATISTICS",
                "-" * 20,
                f"Average Overall Score: {avg_score:.1f}/100",
                f"Average Funding: ${avg_funding:,.2f}",
                f"Average Backers: {avg_backers:.1f}",
                "",
                "CATEGORY BREAKDOWN",
                "-" * 20,
            ])

            # Category distribution
            categories = {}
            for project in projects:
                cat = project.category or "Uncategorized"
                categories[cat] = categories.get(cat, 0) + 1

            for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(projects)) * 100
                report_lines.append(f"{cat}: {count} projects ({percentage:.1f}%)")

        return "\n".join(report_lines)

    def _generate_json_report(self) -> str:
        """Generate a JSON-based report."""
        projects_data = [asdict(p) for p in self._cached_projects]

        report = {
            "generated_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "total_projects": len(self._cached_projects),
            "config": asdict(self._config),
            "projects": projects_data,
            "summary": {
                "avg_overall_score": sum(p.overall_score for p in self._cached_projects) / len(self._cached_projects) if self._cached_projects else 0,
                "avg_funding": sum(p.total_funding for p in self._cached_projects) / len(self._cached_projects) if self._cached_projects else 0,
                "avg_backers": sum(p.backer_count for p in self._cached_projects) / len(self._cached_projects) if self._cached_projects else 0,
            }
        }

        return json.dumps(report, indent=2)

    def _generate_csv_report(self) -> str:
        """Generate a CSV-based report."""
        if not self._cached_projects:
            return "No data available"

        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "rank", "project_id", "name", "category", "creator_address",
            "total_funding", "backer_count", "engagement_score",
            "growth_score", "quality_score", "overall_score"
        ])

        # Data rows
        for i, project in enumerate(self._cached_projects, 1):
            writer.writerow([
                i, project.project_id, project.name, project.category,
                project.creator_address, project.total_funding, project.backer_count,
                project.engagement_score, project.growth_score,
                project.quality_score, project.overall_score
            ])

        return output.getvalue()

    def get_top_projects(self, limit: int = 10, category: Optional[str] = None) -> List[ProjectMetrics]:
        """Get top projects by score with optional category filtering.

        Args:
            limit: Maximum number of projects to return
            category: Optional category filter

        Returns:
            List of top projects
        """
        projects = self._cached_projects

        if category:
            projects = [p for p in projects if p.category == category]

        return projects[:limit]

    def update_config(self, config: ScanConfig) -> None:
        """Update scanning configuration."""
        self._config = config
        LOGGER.info("Updated ProjectScout configuration")

    @classmethod
    def from_env(cls, backend_client: BackendClient, database_manager: DatabaseManager) -> "ProjectScout":
        """Create ProjectScout from environment configuration."""
        load_env_file()

        config = ScanConfig(
            min_funding=float(os.getenv("PROJECT_MIN_FUNDING", "0")),
            max_funding=float(os.getenv("PROJECT_MAX_FUNDING", "0")) or None,
            min_backers=int(os.getenv("PROJECT_MIN_BACKERS", "0")),
            max_backers=int(os.getenv("PROJECT_MAX_BACKERS", "0")) or None,
            categories=os.getenv("PROJECT_CATEGORIES", "").split(",") if os.getenv("PROJECT_CATEGORIES") else None,
            exclude_categories=os.getenv("PROJECT_EXCLUDE_CATEGORIES", "").split(",") if os.getenv("PROJECT_EXCLUDE_CATEGORIES") else None,
            min_success_rate=float(os.getenv("PROJECT_MIN_SUCCESS_RATE", "0")),
            max_results=int(os.getenv("PROJECT_MAX_RESULTS", "100")),
        )

        return cls(backend_client, database_manager, config)


# Add missing import for math
import math
