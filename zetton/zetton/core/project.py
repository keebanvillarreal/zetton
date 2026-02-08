"""
Project management for Zetton.

Projects provide a way to organize analysis of multiple related binaries,
store analysis results, and maintain session state.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from zetton.core.binary import Binary


@dataclass
class AnalysisResult:
    """Container for analysis results."""
    timestamp: datetime
    analysis_type: str
    quantum_enabled: bool
    results: dict
    binary_hash: str


@dataclass
class Project:
    """
    Zetton analysis project.
    
    A project groups related binaries and their analysis results together,
    enabling persistent storage and organized investigation workflows.
    
    Attributes:
        name: Project name
        uuid: Unique project identifier
        created: Creation timestamp
        binaries: List of loaded binaries
        results: Analysis results keyed by binary hash
        notes: User notes
        tags: Classification tags
    """
    
    name: str | None = None
    uuid: str = field(default_factory=lambda: str(uuid4()))
    created: datetime = field(default_factory=datetime.now)
    modified: datetime = field(default_factory=datetime.now)
    binaries: list[Binary] = field(default_factory=list)
    results: dict[str, list[AnalysisResult]] = field(default_factory=dict)
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    
    def __post_init__(self):
        if self.name is None:
            self.name = f"zetton_project_{self.uuid[:8]}"
    
    def add_binary(self, binary: Binary) -> None:
        """
        Add a binary to the project.
        
        Args:
            binary: Binary object to add
        """
        self.binaries.append(binary)
        self.modified = datetime.now()
        
        # Initialize results list for this binary
        if binary.sha256 not in self.results:
            self.results[binary.sha256] = []
    
    def remove_binary(self, binary: Binary) -> bool:
        """
        Remove a binary from the project.
        
        Args:
            binary: Binary to remove
            
        Returns:
            True if removed, False if not found
        """
        try:
            self.binaries.remove(binary)
            self.modified = datetime.now()
            return True
        except ValueError:
            return False
    
    def add_result(
        self,
        binary: Binary,
        analysis_type: str,
        results: dict,
        quantum_enabled: bool = False
    ) -> None:
        """
        Store analysis results for a binary.
        
        Args:
            binary: Binary that was analyzed
            analysis_type: Type of analysis performed
            results: Analysis results dictionary
            quantum_enabled: Whether quantum acceleration was used
        """
        result = AnalysisResult(
            timestamp=datetime.now(),
            analysis_type=analysis_type,
            quantum_enabled=quantum_enabled,
            results=results,
            binary_hash=binary.sha256,
        )
        
        if binary.sha256 not in self.results:
            self.results[binary.sha256] = []
        
        self.results[binary.sha256].append(result)
        self.modified = datetime.now()
    
    def get_results(
        self,
        binary: Binary | None = None,
        analysis_type: str | None = None
    ) -> list[AnalysisResult]:
        """
        Retrieve analysis results with optional filtering.
        
        Args:
            binary: Filter by specific binary
            analysis_type: Filter by analysis type
            
        Returns:
            List of matching analysis results
        """
        results = []
        
        # Collect results
        if binary:
            results = self.results.get(binary.sha256, [])
        else:
            for result_list in self.results.values():
                results.extend(result_list)
        
        # Filter by type
        if analysis_type:
            results = [r for r in results if r.analysis_type == analysis_type]
        
        return sorted(results, key=lambda r: r.timestamp, reverse=True)
    
    def save(self, path: str | Path) -> None:
        """
        Save project to file.
        
        Args:
            path: Path to save project file
        """
        path = Path(path)
        
        # Convert to serializable format
        data = {
            "name": self.name,
            "uuid": self.uuid,
            "created": self.created.isoformat(),
            "modified": datetime.now().isoformat(),
            "binaries": [
                {
                    "path": str(b.path),
                    "sha256": b.sha256,
                    "format": b.format.name,
                    "architecture": b.architecture.name,
                }
                for b in self.binaries
            ],
            "results": {
                hash_: [
                    {
                        "timestamp": r.timestamp.isoformat(),
                        "analysis_type": r.analysis_type,
                        "quantum_enabled": r.quantum_enabled,
                        "results": r.results,
                        "binary_hash": r.binary_hash,
                    }
                    for r in results
                ]
                for hash_, results in self.results.items()
            },
            "notes": self.notes,
            "tags": self.tags,
        }
        
        with path.open("w") as f:
            json.dump(data, f, indent=2)
    
    @classmethod
    def load(cls, path: str | Path) -> Project:
        """
        Load project from file.
        
        Args:
            path: Path to project file
            
        Returns:
            Loaded Project object
        """
        from zetton.core.binary import Binary
        
        path = Path(path)
        
        with path.open() as f:
            data = json.load(f)
        
        project = cls(
            name=data["name"],
            uuid=data["uuid"],
            created=datetime.fromisoformat(data["created"]),
            modified=datetime.fromisoformat(data["modified"]),
            notes=data.get("notes", ""),
            tags=data.get("tags", []),
        )
        
        # Reload binaries
        for binary_info in data.get("binaries", []):
            try:
                binary = Binary.from_file(binary_info["path"])
                project.binaries.append(binary)
            except FileNotFoundError:
                # Binary file no longer exists, skip
                pass
        
        # Restore results
        for hash_, results in data.get("results", {}).items():
            project.results[hash_] = [
                AnalysisResult(
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    analysis_type=r["analysis_type"],
                    quantum_enabled=r["quantum_enabled"],
                    results=r["results"],
                    binary_hash=r["binary_hash"],
                )
                for r in results
            ]
        
        return project
    
    def summary(self) -> dict:
        """
        Get project summary.
        
        Returns:
            Dictionary with project statistics
        """
        total_results = sum(len(r) for r in self.results.values())
        quantum_results = sum(
            1 for results in self.results.values()
            for r in results if r.quantum_enabled
        )
        
        return {
            "name": self.name,
            "uuid": self.uuid,
            "created": self.created.isoformat(),
            "modified": self.modified.isoformat(),
            "binary_count": len(self.binaries),
            "total_analyses": total_results,
            "quantum_analyses": quantum_results,
            "tags": self.tags,
        }
