"""
Event timeline reconstruction for Zetton.

Reconstructs execution timelines from binary artifacts including
file metadata, embedded timestamps, log references, and behavioral patterns.
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zetton.core.binary import Binary

logger = logging.getLogger(__name__)


class EventType(Enum):
    COMPILATION = auto()
    LINKING = auto()
    SIGNING = auto()
    DEBUG_INFO = auto()
    RESOURCE = auto()
    CERTIFICATE = auto()
    NETWORK_IOC = auto()
    FILE_REFERENCE = auto()
    STRING_DATE = auto()
    EPOCH_TIMESTAMP = auto()
    PE_EXPORT = auto()
    RICH_HEADER = auto()


class EventConfidence(Enum):
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    UNCERTAIN = auto()


@dataclass
class TimelineEvent:
    timestamp: datetime
    event_type: EventType
    description: str
    confidence: EventConfidence = EventConfidence.MEDIUM
    source_offset: int = 0
    source_section: str = ""
    raw_value: int | str = 0
    metadata: dict = field(default_factory=dict)

    def __str__(self) -> str:
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"[{ts}] [{self.confidence.name}] {self.event_type.name}: {self.description}"

    def __lt__(self, other: TimelineEvent) -> bool:
        return self.timestamp < other.timestamp


@dataclass
class Timeline:
    binary_name: str
    events: list[TimelineEvent] = field(default_factory=list)
    earliest: datetime | None = None
    latest: datetime | None = None
    analysis_notes: list[str] = field(default_factory=list)

    def add_event(self, event: TimelineEvent) -> None:
        self.events.append(event)
        self.events.sort()
        if self.events:
            self.earliest = self.events[0].timestamp
            self.latest = self.events[-1].timestamp

    @property
    def duration(self) -> str:
        if not self.earliest or not self.latest:
            return "N/A"
        delta = self.latest - self.earliest
        days = delta.days
        hours = delta.seconds // 3600
        if days > 365:
            return f"{days // 365} years, {days % 365} days"
        if days > 0:
            return f"{days} days, {hours} hours"
        return f"{hours} hours, {(delta.seconds % 3600) // 60} minutes"

    def filter_by_confidence(self, min_confidence: EventConfidence) -> list[TimelineEvent]:
        levels = {EventConfidence.HIGH: 3, EventConfidence.MEDIUM: 2, EventConfidence.LOW: 1, EventConfidence.UNCERTAIN: 0}
        min_level = levels[min_confidence]
        return [e for e in self.events if levels[e.confidence] >= min_level]

    def filter_by_type(self, event_type: EventType) -> list[TimelineEvent]:
        return [e for e in self.events if e.event_type == event_type]

    def to_dict(self) -> dict:
        return {
            "binary": self.binary_name,
            "event_count": len(self.events),
            "earliest": self.earliest.isoformat() if self.earliest else None,
            "latest": self.latest.isoformat() if self.latest else None,
            "duration": self.duration,
            "events": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "type": e.event_type.name,
                    "confidence": e.confidence.name,
                    "description": e.description,
                    "offset": f"0x{e.source_offset:x}" if e.source_offset else "",
                }
                for e in self.events
            ],
            "notes": self.analysis_notes,
        }


class TimelineReconstructor:
    """
    Reconstructs execution timelines from binary artifacts.

    Example:
        >>> reconstructor = TimelineReconstructor(binary)
        >>> timeline = reconstructor.reconstruct()
        >>> for event in timeline.events:
        ...     print(event)
    """

    DATE_PATTERNS = [
        (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "%Y-%m-%dT%H:%M:%S"),
        (r"\d{4}-\d{2}-\d{2}", "%Y-%m-%d"),
        (r"\d{2}/\d{2}/\d{4}", "%m/%d/%Y"),
        (r"\w{3} \d{2} \d{4} \d{2}:\d{2}:\d{2}", "%b %d %Y %H:%M:%S"),
    ]

    MIN_TIMESTAMP = 946684800   # 2000-01-01
    MAX_TIMESTAMP = 1893456000  # 2030-01-01

    def __init__(self, binary: Binary, max_events: int = 10_000):
        self.binary = binary
        self.max_events = max_events

    def reconstruct(self) -> Timeline:
        """Perform full timeline reconstruction."""
        timeline = Timeline(binary_name=str(self.binary.path))

        self._extract_header_timestamps(timeline)
        self._extract_string_dates(timeline)
        self._extract_epoch_timestamps(timeline)
        self._check_anomalies(timeline)

        if len(timeline.events) > self.max_events:
            timeline.events = timeline.events[:self.max_events]
            timeline.analysis_notes.append(f"Truncated to {self.max_events} events")

        return timeline

    def _extract_header_timestamps(self, timeline: Timeline) -> None:
        from zetton.core.binary import BinaryFormat

        if self.binary.format == BinaryFormat.PE:
            self._extract_pe_timestamps(timeline)
        elif self.binary.format == BinaryFormat.ELF:
            self._extract_elf_timestamps(timeline)

    def _extract_pe_timestamps(self, timeline: Timeline) -> None:
        data = self.binary.raw_data
        if len(data) < 64:
            return
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 8 > len(data):
                return
            timestamp = struct.unpack_from("<I", data, pe_offset + 8)[0]

            if self.MIN_TIMESTAMP <= timestamp <= self.MAX_TIMESTAMP:
                dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                timeline.add_event(TimelineEvent(
                    timestamp=dt,
                    event_type=EventType.COMPILATION,
                    description="PE COFF header compilation timestamp",
                    confidence=EventConfidence.HIGH,
                    source_offset=pe_offset + 8,
                    raw_value=timestamp,
                ))
            elif timestamp != 0:
                timeline.analysis_notes.append(
                    f"PE timestamp 0x{timestamp:x} outside reasonable range"
                )
        except (struct.error, ValueError):
            pass

    def _extract_elf_timestamps(self, timeline: Timeline) -> None:
        for section in self.binary.sections:
            if ".note" in section.name.lower():
                timeline.analysis_notes.append(
                    f"ELF note section '{section.name}' may contain build metadata"
                )

    def _extract_string_dates(self, timeline: Timeline) -> None:
        data = self.binary.raw_data
        strings = self._extract_strings(data, min_length=8)

        for offset, string_val in strings:
            for pattern, fmt in self.DATE_PATTERNS:
                match = re.search(pattern, string_val)
                if match:
                    try:
                        date_str = match.group(0).replace("T", " ")
                        dt = datetime.strptime(date_str, fmt.replace("T", " "))
                        dt = dt.replace(tzinfo=timezone.utc)

                        if self.MIN_TIMESTAMP <= dt.timestamp() <= self.MAX_TIMESTAMP:
                            timeline.add_event(TimelineEvent(
                                timestamp=dt,
                                event_type=EventType.STRING_DATE,
                                description=f'Date string: "{match.group(0)}"',
                                confidence=EventConfidence.MEDIUM,
                                source_offset=offset,
                                source_section=self._get_section(offset),
                                raw_value=match.group(0),
                            ))
                    except (ValueError, OverflowError):
                        continue
                    break

    def _extract_epoch_timestamps(self, timeline: Timeline) -> None:
        data = self.binary.raw_data

        for i in range(0, len(data) - 4, 4):
            value = struct.unpack_from("<I", data, i)[0]
            if self.MIN_TIMESTAMP <= value <= self.MAX_TIMESTAMP:
                section = self._get_section(i)
                if section and "text" in section.lower():
                    continue

                try:
                    dt = datetime.fromtimestamp(value, tz=timezone.utc)
                    timeline.add_event(TimelineEvent(
                        timestamp=dt,
                        event_type=EventType.EPOCH_TIMESTAMP,
                        description=f"Raw epoch timestamp in {section or 'data'}",
                        confidence=EventConfidence.LOW,
                        source_offset=i,
                        source_section=section or "",
                        raw_value=value,
                    ))
                except (ValueError, OverflowError, OSError):
                    continue

    def _check_anomalies(self, timeline: Timeline) -> None:
        compilation = [e for e in timeline.events if e.event_type == EventType.COMPILATION]
        if compilation:
            comp_time = compilation[0].timestamp
            now = datetime.now(timezone.utc)
            if comp_time > now:
                timeline.analysis_notes.append(
                    f"WARNING: Compilation timestamp ({comp_time}) is in the future - likely spoofed"
                )
            if comp_time.year == 1970:
                timeline.analysis_notes.append(
                    "WARNING: Compilation timestamp is epoch (1970) - likely zeroed"
                )

    def _extract_strings(self, data: bytes, min_length: int = 8) -> list[tuple[int, str]]:
        strings = []
        current = []
        start = 0
        for i, byte in enumerate(data):
            if 32 <= byte < 127:
                if not current:
                    start = i
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append((start, "".join(current)))
                current = []
        if len(current) >= min_length:
            strings.append((start, "".join(current)))
        return strings

    def _get_section(self, offset: int) -> str:
        for section in self.binary.sections:
            if section.raw_offset <= offset < section.raw_offset + section.raw_size:
                return section.name
        return ""
