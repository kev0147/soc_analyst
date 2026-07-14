import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


REQUIRED_COLUMN_GROUPS = {
    "Flow ID": {"Flow ID", "id"},
    "Start": {"Start", "firstActiveTime"},
    "Subject IP Address": {"Subject IP Address", "searchSubject.ipAddress"},
    "Peer IP Address": {"Peer IP Address", "peer.ipAddress"},
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
    "id",
    "domainId",
    "deviceId",
    "firstActiveTime",
    "lastActiveTime",
    "activeDuration",
    "searchSubject.ipAddress",
    "searchSubject.name",
    "searchSubject.percentTransferBytes",
    "searchSubject.transferBytes",
    "searchSubject.transferPackets",
    "searchSubject.transferByteRate",
    "searchSubject.transferPacketRate",
    "searchSubject.orientation",
    "searchSubject.hostGroups",
    "searchSubject.interfaces.flowAction",
    "searchSubject.portProtocol.port",
    "searchSubject.portProtocol.protocol",
    "peer.ipAddress",
    "peer.name",
    "peer.percentTransferBytes",
    "peer.transferBytes",
    "peer.transferPackets",
    "peer.transferByteRate",
    "peer.transferPacketRate",
    "peer.orientation",
    "peer.hostGroups",
    "peer.portProtocol.port",
    "peer.portProtocol.protocol",
    "connection.transferBytes",
    "connection.transferPackets",
    "connection.transferByteRate",
    "connection.transferPacketRate",
    "connection.tcpConnections",
    "connection.tcpRetransmissions",
    "connection.application.name",
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
    missing_required = [
        canonical
        for canonical, aliases in REQUIRED_COLUMN_GROUPS.items()
        if not present.intersection(aliases)
    ]
    return SNAHeaderReport(
        columns=normalized_columns,
        missing_required=missing_required,
        recognized=[column for column in normalized_columns if column in USEFUL_COLUMNS],
        ignored=[column for column in normalized_columns if column not in USEFUL_COLUMNS],
    )


def iter_rows(path: Path, encoding: str, delimiter: str = ",") -> Iterator[tuple[int, dict[str, str]]]:
    with path.open("r", encoding=encoding, newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        for index, row in enumerate(reader, start=2):
            yield index, {str(key).strip(): value for key, value in row.items() if key is not None}
