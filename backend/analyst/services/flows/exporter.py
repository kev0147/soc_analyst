import csv


FLOW_EXPORT_COLUMNS = [
    "id",
    "structure",
    "network",
    "sna_flow_id",
    "started_at",
    "ended_at",
    "duration_seconds",
    "direction",
    "src_ip",
    "src_port",
    "src_role",
    "src_hostname",
    "src_location",
    "src_bytes",
    "src_packets",
    "dst_ip",
    "dst_port",
    "dst_role",
    "dst_hostname",
    "dst_location",
    "dst_bytes",
    "dst_packets",
    "protocol",
    "service",
    "application",
    "total_bytes",
    "total_packets",
    "byte_rate",
    "packet_rate",
    "tcp_connections",
    "tcp_retransmissions",
    "tcp_retransmission_ratio",
    "actions",
]


class Echo:
    def write(self, value):
        return value


def _flow_export_row(flow) -> list:
    return [
        flow.id,
        flow.network.structure.code,
        flow.network.name,
        flow.sna_flow_id,
        flow.started_at.isoformat() if flow.started_at else "",
        flow.ended_at.isoformat() if flow.ended_at else "",
        flow.duration_seconds or "",
        flow.direction,
        flow.src_ip,
        flow.src_port or "",
        flow.src_role,
        flow.src_hostname,
        flow.src_location,
        flow.src_bytes or "",
        flow.src_packets or "",
        flow.dst_ip,
        flow.dst_port or "",
        flow.dst_role,
        flow.dst_hostname,
        flow.dst_location,
        flow.dst_bytes or "",
        flow.dst_packets or "",
        flow.protocol,
        flow.service,
        flow.application,
        flow.total_bytes or "",
        flow.total_packets or "",
        flow.byte_rate or "",
        flow.packet_rate or "",
        flow.tcp_connections or "",
        flow.tcp_retransmissions or "",
        flow.tcp_retransmission_ratio if flow.tcp_retransmission_ratio is not None else "",
        flow.actions,
    ]


def flow_export_rows(queryset):
    writer = csv.writer(Echo())
    yield writer.writerow(FLOW_EXPORT_COLUMNS)
    for flow in queryset.iterator(chunk_size=1000):
        yield writer.writerow(_flow_export_row(flow))
