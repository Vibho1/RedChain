from __future__ import annotations

import json
import os
from pathlib import Path

from redchain.models.attack_trace import AuditReport

class JSONReporter:
    """
    Saves a completed AuditReport to disk as a formatted JSON file.

    Output location: RECHAIN_REPORT_DIR env var (default: ./redchain_data/reports/)
    Filename format: attack_{session_id[:8]}.json
    """

    def __init__(self, reports_dir: str | None = None) -> None:
        self.reports_dir = Path(
            reports_dir
            or os.getenv("REDCHAIN_REPORTS_DIR", "./redchain_data/reports")
        )
    

    def save(self, report: AuditReport) -> Path:
        """
        Serialize the AuditReport to JSON and write to disk.

        Args:
            report: The completed AuditReport to save.

        Returns:
            The Path where the file was written.
        """

        # Ensure output directory exists
        self.reports_dir.mkdir(parents = True, exist_ok = True)

        # Build filename from session ID short hash
        filename = f"attack_{report.session_id[:8]}.json"
        output_path = self.reports_dir / filename

        # Serialize using Pydantic's built-in JSON serializer
        # model_dump() converts to dict, including nested models
        data = report.model_dump(mode = "json")

        with open(output_path, "w", encoding = "utf-8") as f:
            json.dump(data, f, indent = 2, default = str)

        return output_path

    
    def load(self, session_id: str) -> AuditReport:
        """
        Load a previously saved AuditReport from disk by session ID or filename.

        Args:
            session_id: The session ID (first 8 chars used for filename), prefix or full file name.

        Returns:
            The deserialized AuditReport.

        Raises:
            FileNotFoundError if no report exists for this session ID.
        """

        clean_id = session_id.strip()

        if clean_id.startswith("attack_"):
            clean_id = clean_id[7:]
            
        if clean_id.endswith(".json"):
            clean_id = clean_id[:-5]

        filename = f"attack_{clean_id[:8]}.json"
        path = self.reports_dir / filename

        if not path.exists():
            # Fallback: check if exact file matches directly
            direct_path = self.reports_dir / session_id
            if direct_path.exists():
                path = direct_path
            else:
                raise FileNotFoundError(
                    f"No report found for session '{session_id}' at {path}"
                )

        with open(path, "r", encoding = "utf-8") as f:
            data = json.load(f)

        return AuditReport.model_validate(data)


    def list_all(self) -> list[AuditReport]:
        """
        Load all saved AuditReports sorted by creation time (newest first).
        """

        if not self.reports_dir.exists():
            return []
        
        reports: list[AuditReport] = []
        
        json_files = sorted(
            self.reports_dir.glob("attack_*.json"),
            key = lambda p: p.stat().st_mtime,
            reverse = True,
        )

        for path in json_files:
            try:
                with open(path, "r", encoding = "utf-8") as f:
                    data = json.load(f)
                
                reports.append(AuditReport.model_validate(data))
            
            except Exception:
                continue

                
        return reports