import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


REQUIRED_COLUMNS = {
    "Flow ID",
    "Start",
    "Subject IP Address",
    "Peer IP Address",
}

USEFUL_COLUMNS = {
    "Flow ID",
    "Domain",
    "Start",
    "End",
    "Duration",
    "Flow Action",
    "Subject ASN",
    "Subject ASN Assignment",
    "Subject IP Address",
    "Subject Hostname",
    "Subject Orientation",
    "Subject Port/Protocol",
    "Subject Location",
    "Subject Bytes",
    "Subject Packets",
    "Appliance",
    "Application",
    "Byte Rate",
    "Total Bytes",
    "Packet Rate",
    "Total Packets",
    "protocol",
    "Service",
    "TCP Connections",
    "TCP Retransmissions",
    "TCP Retransmission Ratio",
    "Peer ASN",
    "Peer ASN Assignment",
    "Peer IP Address",
    "Peer Hostname",
    "Peer Orientation",
    "Peer Port/Protocol",
    "Peer Location",
    "Peer Bytes",
    "Peer Packets",
    "Actions",
}


@dataclass(frozen=True)
class SNAHeaderReport:
    columns: list[str]
    missing_required: list[str]
    recognized: list[str]
    ignored: list[str]

    @property
    def is_valid(self) -> bool:
        return not self.missing_required


def read_header(path: Path, encoding: str, delimiter: str = ",") -> SNAHeaderReport:
    with path.open("r", encoding=encoding, newline="") as handle:
        reader = csv.reader(handle, delimiter=delimiter)
        try:
            columns = next(reader)
        except StopIteration:
            columns = []

    normalized_columns = [column.strip() for column in columns]
    present = set(normalized_columns)
    return SNAHeaderReport(
        columns=normalized_columns,
        missing_required=sorted(REQUIRED_COLUMNS - present),
        recognized=[column for column in normalized_columns if column in USEFUL_COLUMNS],
        ignored=[column for column in normalized_columns if column not in USEFUL_COLUMNS],
    )


def iter_rows(path: Path, encoding: str, delimiter: str = ",") -> Iterator[tuple[int, dict[str, str]]]:
    with path.open("r", encoding=encoding, newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        for index, row in enumerate(reader, start=2):
            yield index, {str(key).strip(): value for key, value in row.items() if key is not None}
