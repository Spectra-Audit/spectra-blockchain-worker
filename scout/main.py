"""Main entry point for the Scout package."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from .featured_scout import FeaturedScout
from .pro_scout import ProScout
from .project_scout import ProjectScout


class ScoutApp:
    """Primary application facade for the Scout package."""

    def __init__(self) -> None:
        """Initialize the application and compose the scout components."""
        self.project_scout = ProjectScout()
        self.pro_scout = ProScout()
        self.featured_scout = FeaturedScout()

    def run(self) -> None:
        """Execute the default workflow.

        TODO: Implement actual orchestration logic.
        """
        self.project_scout.scan()
        self.pro_scout.evaluate()
        self.featured_scout.highlight()

    def status(self) -> str:
        """Return a human-readable application status summary."""
        # TODO: Produce a real status report based on component state.
        return "Scout application status: TODO"


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point used by ``python -m scout``."""
    parser = argparse.ArgumentParser(description="Scout command line interface")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="Run the Scout workflow")
    subparsers.add_parser("status", help="Show the current Scout status")

    args = parser.parse_args(argv)

    app = ScoutApp()

    if args.command == "run":
        app.run()
        return 0

    if args.command == "status":
        print(app.status())
        return 0

    return 1


if __name__ == "__main__":  # pragma: no cover - convenience for direct execution
    raise SystemExit(main())
