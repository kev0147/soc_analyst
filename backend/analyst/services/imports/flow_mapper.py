import ipaddress
from dataclasses import dataclass

from analyst.models import Network
from analyst.models.choices import EndpointRole, FlowDirection, MappingMethod

from .normalizer import (
    datetime_utc,
    duration_seconds,
    floating,
    integer,
    port_protocol,
    text_or_blank,
)


@dataclass(frozen=True)
class Endpoint:
    ip: str
    hostname: str
    port: int | None
    role: str
    location: str
    asn: int | None
    asn_assignment: str
    bytes: int | None
    packets: int | None


def _role(value: str | None) -> str:
    normalized = text_or_blank(value).lower()
    if normalized == "client":
        return EndpointRole.CLIENT
    if normalized == "server":
        return EndpointRole.SERVER
    return EndpointRole.UNKNOWN


def _endpoint(row: dict[str, str], prefix: str) -> Endpoint:
    port, protocol_from_port = port_protocol(row.get(f"{prefix} Port/Protocol"))
    return Endpoint(
        ip=text_or_blank(row.get(f"{prefix} IP Address")),
        hostname=text_or_blank(row.get(f"{prefix} Hostname")),
        port=port,
        role=_role(row.get(f"{prefix} Orientation")),
        location=text_or_blank(row.get(f"{prefix} Location")),
        asn=integer(row.get(f"{prefix} ASN")),
        asn_assignment=text_or_blank(row.get(f"{prefix} ASN Assignment")),
        bytes=integer(row.get(f"{prefix} Bytes")),
        packets=integer(row.get(f"{prefix} Packets")),
    )


def _ip_is_internal(ip: str, internal_networks: tuple[ipaddress.IPv4Network, ...]) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in network for network in internal_networks)


def _direction(src_ip: str, dst_ip: str, internal_networks: tuple[ipaddress.IPv4Network, ...]) -> str:
    src_internal = _ip_is_internal(src_ip, internal_networks)
    dst_internal = _ip_is_internal(dst_ip, internal_networks)
    if src_internal and dst_internal:
        return FlowDirection.INTERNAL
    if src_internal and not dst_internal:
        return FlowDirection.OUTBOUND
    if not src_internal and dst_internal:
        return FlowDirection.INBOUND
    return FlowDirection.EXTERNAL


def internal_cidrs_for_network(network: Network) -> tuple[ipaddress.IPv4Network, ...]:
    return tuple(ipaddress.ip_network(cidr.cidr, strict=False) for cidr in network.cidrs.all())


def map_sna_row(row: dict[str, str], network: Network, internal_cidrs: tuple[ipaddress.IPv4Network, ...] | None = None) -> dict:
    subject = _endpoint(row, "Subject")
    peer = _endpoint(row, "Peer")
    if not subject.ip:
        raise ValueError("Subject IP Address manquante.")
    if not peer.ip:
        raise ValueError("Peer IP Address manquante.")
    ipaddress.ip_address(subject.ip)
    ipaddress.ip_address(peer.ip)

    if subject.role == EndpointRole.CLIENT:
        src, dst = subject, peer
        mapping_method = MappingMethod.ORIENTATION
    elif subject.role == EndpointRole.SERVER:
        src, dst = peer, subject
        mapping_method = MappingMethod.ORIENTATION
    else:
        src, dst = subject, peer
        mapping_method = MappingMethod.SUBJECT_PEER_FALLBACK

    started_at = datetime_utc(row.get("Start"))
    if not started_at:
        raise ValueError("Start invalide ou manquant.")

    subject_port, subject_protocol = port_protocol(row.get("Subject Port/Protocol"))
    peer_port, peer_protocol = port_protocol(row.get("Peer Port/Protocol"))
    protocol = text_or_blank(row.get("protocol")) or subject_protocol or peer_protocol
    protocol = protocol.upper()
    cidrs = internal_cidrs if internal_cidrs is not None else internal_cidrs_for_network(network)

    return {
        "network": network,
        "sna_flow_id": text_or_blank(row.get("Flow ID")),
        "domain": text_or_blank(row.get("Domain")),
        "started_at": started_at,
        "ended_at": datetime_utc(row.get("End")),
        "duration_seconds": duration_seconds(row.get("Duration")),
        "flow_action": text_or_blank(row.get("Flow Action")),
        "mapping_method": mapping_method,
        "direction": _direction(src.ip, dst.ip, cidrs),
        "src_ip": src.ip,
        "src_hostname": src.hostname,
        "src_port": src.port,
        "src_role": src.role,
        "src_location": src.location,
        "src_asn": src.asn,
        "src_asn_assignment": src.asn_assignment,
        "src_bytes": src.bytes,
        "src_packets": src.packets,
        "dst_ip": dst.ip,
        "dst_hostname": dst.hostname,
        "dst_port": dst.port,
        "dst_role": dst.role,
        "dst_location": dst.location,
        "dst_asn": dst.asn,
        "dst_asn_assignment": dst.asn_assignment,
        "dst_bytes": dst.bytes,
        "dst_packets": dst.packets,
        "protocol": protocol,
        "service": text_or_blank(row.get("Service")),
        "application": text_or_blank(row.get("Application")),
        "appliance": text_or_blank(row.get("Appliance")),
        "byte_rate": floating(row.get("Byte Rate")),
        "packet_rate": floating(row.get("Packet Rate")),
        "total_bytes": integer(row.get("Total Bytes")),
        "total_packets": integer(row.get("Total Packets")),
        "tcp_connections": integer(row.get("TCP Connections")),
        "tcp_retransmissions": integer(row.get("TCP Retransmissions"), column="TCP Retransmissions"),
        "tcp_retransmission_ratio": floating(row.get("TCP Retransmission Ratio"), column="TCP Retransmission Ratio"),
        "actions": text_or_blank(row.get("Actions")),
    }
