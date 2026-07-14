from pathlib import Path
from io import StringIO

from django.core.management import call_command, CommandError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase

from django.utils import timezone

from .models import (
    Bulletin,
    BulletinFinding,
    BulletinIP,
    BulletinResponse,
    BulletinTypeCatalog,
    Flow,
    FlowImport,
    IPReputation,
    Network,
    NetworkCIDR,
    PeerObservation,
    PeerObservationRisk,
    RecommendationCatalog,
    RiskCatalog,
    RiskProfile,
    Structure,
    User,
)
from .models.choices import (
    BulletinIPRole,
    BulletinSeverity,
    FlowDirection,
    ImportStatus,
    MappingMethod,
    ReputationSource,
    ReputationStatus,
    ReputationVerdict,
    UserRole,
)
from .services.flows import apply_flow_filters, flow_export_rows
from .services.imports import confirm_flow_import, preview_flow_import_upload
from .services.ip_intelligence import build_ip_timeline
from .services.bulletins import create_bulletin_from_findings, create_bulletin_with_links, find_duplicate_bulletins
from .services.analytics import build_dashboard_overview, top_conversations, top_peers, top_ports_protocols, top_talkers
from .services.security import audit_action_catalog, permission_matrix
from .controllers.audit import record_audit
from .services.ip_reputation import candidate_ips, run_reputation_analysis
from .services.ip_reputation.clients import ReputationClientResult
from .services.peer_observations import sync_peer_observations


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
TEST_MEDIA_ROOT = WORKSPACE_ROOT / "backend" / "media_test"


class CoreModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="ANALYST@EXAMPLE.COM",
            password="a-long-test-password",
            role=UserRole.ANALYST,
        )
        self.structure = Structure.objects.create(name="Structure test", code="test")
        self.network = Network.objects.create(structure=self.structure, name="Réseau principal")

    def test_user_email_and_structure_code_are_normalized(self):
        self.assertEqual(self.user.email, "analyst@example.com")
        self.assertEqual(self.structure.code, "TEST")

    def test_cidr_is_normalized(self):
        cidr = NetworkCIDR.objects.create(network=self.network, cidr="192.0.2.17/24")
        self.assertEqual(cidr.cidr, "192.0.2.0/24")

    def test_flow_builds_canonical_conversation(self):
        flow = Flow.objects.create(
            network=self.network,
            sna_flow_id="42",
            started_at="2026-06-24T08:26:23Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="192.0.2.20",
            dst_ip="8.8.8.8",
        )
        self.assertEqual(flow.conversation_ip_a, "8.8.8.8")
        self.assertEqual(flow.conversation_ip_b, "192.0.2.20")

    def test_bulletin_reference_and_ip_signature(self):
        bulletin = Bulletin.objects.create(
            structure=self.structure,
            external_reference="OLD-REF-001",
            severity=BulletinSeverity.HIGH,
            created_by=self.user,
            updated_by=self.user,
        )
        BulletinIP.objects.create(
            bulletin=bulletin,
            ip_address="203.0.113.10",
            role=BulletinIPRole.SOURCE,
            port=443,
        )
        bulletin.refresh_from_db()
        self.assertRegex(bulletin.reference, r"^TEST-\d{4}-001$")
        self.assertEqual(len(bulletin.ip_signature), 64)
        self.assertEqual(bulletin.external_reference, "OLD-REF-001")

    def test_risk_profile_peer_observation_and_bulletin_finding_defaults(self):
        reputation = IPReputation.objects.create(
            ip_address="203.0.113.50",
            verdict=ReputationVerdict.MALICIOUS,
            score=91,
            country="BF",
        )
        observation = PeerObservation.objects.create(
            peer_reputation=reputation,
            network=self.network,
            host_ip="192.0.2.10",
            host_port=22,
            host_service="ssh",
            host_port_category="Administration distante",
            flow_count=4,
            total_bytes=12000,
        )
        risk_profile = RiskProfile.objects.create(
            name="Communication SSH longue avec IP malveillante",
            impact="Risque de compromission ou d'accès distant non autorisé.",
            recommendation="Vérifier la légitimité de la session SSH et restreindre l'accès.",
            default_severity=BulletinSeverity.HIGH,
        )

        observation_risk = PeerObservationRisk.objects.create(
            peer_observation=observation,
            risk_profile=risk_profile,
        )
        bulletin = Bulletin.objects.create(
            structure=self.structure,
            severity=BulletinSeverity.HIGH,
            created_by=self.user,
            updated_by=self.user,
        )
        finding = BulletinFinding.objects.create(
            bulletin=bulletin,
            peer_observation=observation,
            risk_profile=risk_profile,
        )

        self.assertEqual(observation.peer_ip, "203.0.113.50")
        self.assertEqual(observation.peer_country, "BF")
        self.assertEqual(observation_risk.severity, BulletinSeverity.HIGH)
        self.assertEqual(finding.severity, BulletinSeverity.HIGH)
        self.assertEqual(finding.impact_snapshot, risk_profile.impact)
        self.assertEqual(finding.recommendation_snapshot, risk_profile.recommendation)

# Create your tests here.


class SecurityAuditTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email="security@example.com",
            password="a-long-test-password",
            role=UserRole.ADMIN,
        )

    def test_permission_matrix_and_audit_action_catalog_are_exposed_as_data(self):
        matrix = permission_matrix()
        actions = audit_action_catalog()

        self.assertIn(UserRole.ADMIN, matrix)
        self.assertIn("audit", matrix[UserRole.ADMIN])
        self.assertTrue(any(item["action"] == "AUTH_LOGIN_SUCCESS" for item in actions))

    def test_record_audit_enriches_details(self):
        request = self.factory.get("/", HTTP_USER_AGENT="test-agent")
        request.user = self.user

        record_audit(request, "AUTH_LOGIN_SUCCESS", self.user, {"custom": "value"})

        event = self.user.audit_events.get()
        self.assertEqual(event.details["custom"], "value")
        self.assertEqual(event.details["actor_role"], UserRole.ADMIN)
        self.assertTrue(event.details["known_action"])
        self.assertEqual(event.details["user_agent"], "test-agent")

    def test_init_admin_command_creates_first_admin_and_requires_force_afterwards(self):
        User.objects.all().delete()
        output = StringIO()

        call_command(
            "init_admin",
            email="first-admin@example.com",
            password="a-long-test-password",
            stdout=output,
        )

        admin = User.objects.get(email="first-admin@example.com")
        self.assertEqual(admin.role, UserRole.ADMIN)
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.check_password("a-long-test-password"))

        with self.assertRaises(CommandError):
            call_command(
                "init_admin",
                email="second-admin@example.com",
                password="another-long-password",
            )


class FlowImportServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="importer@example.com",
            password="a-long-test-password",
            role=UserRole.ANALYST,
        )
        self.structure = Structure.objects.create(name="Structure import", code="IMP")
        self.network = Network.objects.create(structure=self.structure, name="Réseau import")
        NetworkCIDR.objects.create(network=self.network, cidr="10.10.0.0/16")

    def _csv_upload(self, body: str) -> SimpleUploadedFile:
        return SimpleUploadedFile("flows.csv", body.encode("utf-8"), content_type="text/csv")

    def test_preview_and_confirm_import_sna_csv(self):
        csv_body = (
            "Flow ID,Domain,Start,End,Duration,Flow Action,Subject ASN,Subject ASN Assignment,"
            "Subject IP Address,Subject Hostname,Subject Orientation,Subject Port/Protocol,Subject Location,"
            "Subject Bytes,Subject Packets,Appliance,Application,Byte Rate,Total Bytes,Packet Rate,Total Packets,"
            "protocol,Service,TCP Connections,TCP Retransmissions,TCP Retransmission Ratio,Peer ASN,Peer ASN Assignment,"
            "Peer IP Address,Peer Hostname,Peer Orientation,Peer Port/Protocol,Peer Location,Peer Bytes,Peer Packets,Actions\n"
            "2137403419,pacyr-bf-com,2026-06-24T08:26:23.000+0000,2026-06-24T08:34:58.000+0000,8min 35s,--,--,--,"
            "10.10.1.20,--,Server,443/TCP,Unknown,--,--,pav (10.0.0.1),HTTPS (unclassified),25.89 K,1.93 M,143.67 ,11.21 K,"
            "TCP,https,--,-1,-0.01,--,--,198.51.100.10,--,Client,15781/TCP,France,1.93 M,11.21 K,\n"
        )

        with self.settings(MEDIA_ROOT=TEST_MEDIA_ROOT):
            preview = preview_flow_import_upload(self._csv_upload(csv_body), self.structure, self.user)
            self.assertTrue(preview["is_valid"])
            self.assertEqual(preview["preview_rows"][0]["row_number"], 2)

            flow_import = confirm_flow_import(FlowImport.objects.get(pk=preview["import_id"]))

        self.assertEqual(flow_import.status, ImportStatus.COMPLETED)
        self.assertEqual(flow_import.total_rows, 1)
        self.assertEqual(flow_import.accepted_rows, 1)
        self.assertEqual(flow_import.rejected_rows, 0)

        flow = Flow.objects.get(sna_flow_id="2137403419")
        self.assertEqual(flow.direction, FlowDirection.INBOUND)
        self.assertEqual(flow.mapping_method, MappingMethod.ORIENTATION)
        self.assertEqual(flow.src_ip, "198.51.100.10")
        self.assertEqual(flow.src_port, 15781)
        self.assertEqual(flow.dst_ip, "10.10.1.20")
        self.assertEqual(flow.dst_port, 443)
        self.assertEqual(flow.duration_seconds, 515)
        self.assertEqual(flow.total_bytes, 1_930_000)
        self.assertIsNone(flow.tcp_retransmissions)

    def test_confirm_import_keeps_valid_rows_and_writes_rejections(self):
        csv_body = (
            "Flow ID,Start,Subject IP Address,Subject Orientation,Subject Port/Protocol,Peer IP Address,Peer Orientation,Peer Port/Protocol,protocol\n"
            "ok-1,2026-06-24T08:26:23.000+0000,10.10.1.20,Client,12345/TCP,203.0.113.5,Server,443/TCP,TCP\n"
            "bad-1,not-a-date,10.10.1.20,Client,12345/TCP,203.0.113.5,Server,443/TCP,TCP\n"
        )

        with self.settings(MEDIA_ROOT=TEST_MEDIA_ROOT):
            preview = preview_flow_import_upload(self._csv_upload(csv_body), self.structure, self.user)
            flow_import = confirm_flow_import(FlowImport.objects.get(pk=preview["import_id"]))

        self.assertEqual(flow_import.status, ImportStatus.COMPLETED_WITH_ERRORS)
        self.assertEqual(flow_import.accepted_rows, 1)
        self.assertEqual(flow_import.rejected_rows, 1)
        self.assertEqual(Flow.objects.filter(sna_flow_id="ok-1").count(), 1)

    def test_preview_and_confirm_import_technical_sna_csv(self):
        csv_body = (
            'id,"domainId","firstActiveTime","lastActiveTime","activeDuration",'
            '"searchSubject.ipAddress","searchSubject.orientation","searchSubject.portProtocol.port","searchSubject.portProtocol.protocol",'
            '"peer.ipAddress","peer.orientation","peer.portProtocol.port","peer.portProtocol.protocol",'
            '"connection.transferBytes","connection.transferPackets","connection.transferByteRate","connection.transferPacketRate",'
            '"connection.tcpConnections","connection.tcpRetransmissions","connection.application.name"\n'
            '2246437167,"301","Wed Jul 08 22:44:40 UTC 2026","Wed Jul 08 22:44:41 UTC 2026","1000",'
            '"10.10.30.40","server","5060","UDP",'
            '"192.95.20.52","client","4040","UDP",'
            '"1272","2","1272.0","2.0","0","-1","SIP (unclassified)"\n'
        )

        with self.settings(MEDIA_ROOT=TEST_MEDIA_ROOT):
            preview = preview_flow_import_upload(self._csv_upload(csv_body), self.structure, self.user)
            self.assertTrue(preview["is_valid"])
            self.assertIn("id", preview["columns"]["recognized"])
            flow_import = confirm_flow_import(FlowImport.objects.get(pk=preview["import_id"]))

        self.assertEqual(flow_import.status, ImportStatus.COMPLETED)
        flow = Flow.objects.get(sna_flow_id="2246437167")
        self.assertEqual(flow.direction, FlowDirection.INBOUND)
        self.assertEqual(flow.src_ip, "192.95.20.52")
        self.assertEqual(flow.src_port, 4040)
        self.assertEqual(flow.dst_ip, "10.10.30.40")
        self.assertEqual(flow.dst_port, 5060)
        self.assertEqual(flow.protocol, "UDP")
        self.assertEqual(flow.application, "SIP (unclassified)")
        self.assertEqual(flow.duration_seconds, 1)
        self.assertEqual(flow.total_bytes, 1272)
        self.assertEqual(flow.total_packets, 2)
        self.assertIsNone(flow.tcp_retransmissions)

    def test_one_structure_import_routes_rows_to_multiple_networks(self):
        second_network = Network.objects.create(structure=self.structure, name="Réseau secondaire")
        NetworkCIDR.objects.create(network=second_network, cidr="10.20.0.0/16")
        csv_body = (
            "Flow ID,Start,Subject IP Address,Subject Orientation,Subject Port/Protocol,"
            "Peer IP Address,Peer Orientation,Peer Port/Protocol,protocol\n"
            "multi-a,2026-07-08T10:00:00Z,10.10.1.20,Client,50000/TCP,198.51.100.1,Server,443/TCP,TCP\n"
            "multi-b,2026-07-08T10:01:00Z,10.20.1.20,Client,50001/TCP,198.51.100.2,Server,443/TCP,TCP\n"
        )

        with self.settings(MEDIA_ROOT=TEST_MEDIA_ROOT):
            preview = preview_flow_import_upload(self._csv_upload(csv_body), self.structure, self.user)
            detected_ids = {item["network_id"] for item in preview["network_detection"]["networks"]}
            self.assertEqual(detected_ids, {self.network.id, second_network.id})
            flow_import = confirm_flow_import(FlowImport.objects.get(pk=preview["import_id"]))

        self.assertEqual(flow_import.structure, self.structure)
        self.assertEqual(flow_import.accepted_rows, 2)
        self.assertEqual(Flow.objects.get(sna_flow_id="multi-a").network, self.network)
        self.assertEqual(Flow.objects.get(sna_flow_id="multi-b").network, second_network)

    def test_import_rejects_unmatched_and_cross_network_rows(self):
        second_network = Network.objects.create(structure=self.structure, name="Réseau secondaire")
        NetworkCIDR.objects.create(network=second_network, cidr="10.20.0.0/16")
        csv_body = (
            "Flow ID,Start,Subject IP Address,Subject Orientation,Subject Port/Protocol,"
            "Peer IP Address,Peer Orientation,Peer Port/Protocol,protocol\n"
            "outside,2026-07-08T10:00:00Z,198.51.100.1,Client,50000/TCP,203.0.113.1,Server,443/TCP,TCP\n"
            "cross,2026-07-08T10:01:00Z,10.10.1.20,Client,50001/TCP,10.20.1.20,Server,443/TCP,TCP\n"
        )

        with self.settings(MEDIA_ROOT=TEST_MEDIA_ROOT):
            preview = preview_flow_import_upload(self._csv_upload(csv_body), self.structure, self.user)
            flow_import = confirm_flow_import(FlowImport.objects.get(pk=preview["import_id"]))

        self.assertEqual(flow_import.status, ImportStatus.COMPLETED_WITH_ERRORS)
        self.assertEqual(flow_import.accepted_rows, 0)
        self.assertEqual(flow_import.rejected_rows, 2)

    def test_most_specific_cidr_selects_the_network(self):
        specific_network = Network.objects.create(structure=self.structure, name="Réseau spécifique")
        NetworkCIDR.objects.create(network=specific_network, cidr="10.10.1.0/24")
        csv_body = (
            "Flow ID,Start,Subject IP Address,Subject Orientation,Subject Port/Protocol,"
            "Peer IP Address,Peer Orientation,Peer Port/Protocol,protocol\n"
            "specific,2026-07-08T10:00:00Z,10.10.1.20,Client,50000/TCP,198.51.100.1,Server,443/TCP,TCP\n"
        )

        with self.settings(MEDIA_ROOT=TEST_MEDIA_ROOT):
            preview = preview_flow_import_upload(self._csv_upload(csv_body), self.structure, self.user)
            flow_import = confirm_flow_import(FlowImport.objects.get(pk=preview["import_id"]))

        self.assertEqual(flow_import.accepted_rows, 1)
        self.assertEqual(Flow.objects.get(sna_flow_id="specific").network, specific_network)


class FlowExplorationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="viewer@example.com",
            password="a-long-test-password",
            role=UserRole.VIEWER,
        )
        self.structure = Structure.objects.create(name="Structure exploration", code="EXP")
        self.network = Network.objects.create(structure=self.structure, name="Réseau exploration")
        self.other_network = Network.objects.create(structure=self.structure, name="Autre réseau")
        self.flow_a = Flow.objects.create(
            network=self.network,
            sna_flow_id="flow-a",
            started_at="2026-06-24T08:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.10.1.10",
            src_port=51515,
            dst_ip="198.51.100.10",
            dst_port=443,
            protocol="TCP",
            service="https",
            application="HTTPS",
            total_bytes=2_000,
        )
        self.flow_b = Flow.objects.create(
            network=self.other_network,
            sna_flow_id="flow-b",
            started_at="2026-06-24T09:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.INBOUND,
            src_ip="203.0.113.20",
            src_port=44444,
            dst_ip="10.10.1.11",
            dst_port=22,
            protocol="TCP",
            service="ssh",
            application="SSH",
            total_bytes=500,
        )

    def test_apply_flow_filters_by_ip_port_network_and_ordering(self):
        queryset = apply_flow_filters(
            Flow.objects.all(),
            {
                "network_id": str(self.network.id),
                "ip": "198.51.100.10",
                "port": "443",
                "ordering": "total_bytes",
            },
        )

        self.assertEqual(list(queryset), [self.flow_a])

    def test_flow_export_uses_filtered_queryset(self):
        queryset = apply_flow_filters(Flow.objects.all(), {"service": "ssh"})
        csv_text = "".join(flow_export_rows(queryset))

        self.assertIn("flow-b", csv_text)
        self.assertIn("ssh", csv_text)
        self.assertNotIn("flow-a", csv_text)


class AnalyticsDashboardTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="dashboard@example.com",
            password="a-long-test-password",
            role=UserRole.VIEWER,
        )
        self.structure = Structure.objects.create(name="Structure dashboard", code="DSH")
        self.network = Network.objects.create(structure=self.structure, name="Réseau dashboard")
        self.flow_a = Flow.objects.create(
            network=self.network,
            sna_flow_id="dash-a",
            started_at="2026-06-24T08:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.0.0.10",
            src_port=50000,
            dst_ip="198.51.100.10",
            dst_port=443,
            protocol="TCP",
            service="https",
            application="HTTPS",
            total_bytes=10_000,
            total_packets=100,
        )
        self.flow_b = Flow.objects.create(
            network=self.network,
            sna_flow_id="dash-b",
            started_at="2026-06-24T09:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.0.0.10",
            src_port=50001,
            dst_ip="203.0.113.20",
            dst_port=22,
            protocol="TCP",
            service="ssh",
            application="SSH",
            total_bytes=30_000,
            total_packets=300,
        )
        Bulletin.objects.create(
            structure=self.structure,
            severity=BulletinSeverity.HIGH,
            created_by=self.user,
            updated_by=self.user,
        )

    def test_top_talkers_conversations_and_ports(self):
        params = {"structure_id": str(self.structure.id), "limit": "5"}

        talkers = top_talkers(params)
        conversations = top_conversations(params)
        ports_protocols = top_ports_protocols(params)

        self.assertEqual(talkers["results"][0]["ip"], "10.0.0.10")
        self.assertEqual(talkers["results"][0]["total_bytes"], 40_000)
        self.assertEqual(conversations["results"][0]["total_bytes"], 30_000)
        self.assertEqual(ports_protocols["ports"][0]["dst_port"], 22)
        self.assertEqual(ports_protocols["protocols"][0]["protocol"], "TCP")

    def test_dashboard_overview(self):
        overview = build_dashboard_overview({"structure_id": str(self.structure.id), "limit": "3"})

        self.assertEqual(overview["totals"]["flows"], 2)
        self.assertEqual(overview["totals"]["total_bytes"], 40_000)
        self.assertEqual(overview["totals"]["bulletins"], 1)
        self.assertEqual(overview["flows_by_direction"][FlowDirection.OUTBOUND], 2)
        self.assertEqual(overview["bulletins_by_severity"][BulletinSeverity.HIGH], 1)
        self.assertEqual(overview["top_talkers"][0]["ip"], "10.0.0.10")


class IPReputationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="reputation@example.com",
            password="a-long-test-password",
            role=UserRole.ANALYST,
        )
        self.structure = Structure.objects.create(name="Structure reputation", code="REP")
        self.network = Network.objects.create(structure=self.structure, name="Réseau reputation")
        NetworkCIDR.objects.create(network=self.network, cidr="10.0.0.0/8")
        self.flow_a = Flow.objects.create(
            network=self.network,
            sna_flow_id="rep-a",
            started_at="2026-06-24T08:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.0.0.10",
            dst_ip="203.0.113.50",
            dst_port=443,
            duration_seconds=120,
            protocol="TCP",
            service="https",
            total_bytes=10_000,
        )
        self.flow_b = Flow.objects.create(
            network=self.network,
            sna_flow_id="rep-b",
            started_at="2026-06-24T09:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.0.0.11",
            dst_ip="198.51.100.25",
            dst_port=22,
            duration_seconds=900,
            protocol="TCP",
            service="ssh",
            total_bytes=20_000,
        )

    def test_candidate_ips_prioritizes_never_analyzed_external_ips(self):
        candidates = candidate_ips(limit=10)

        self.assertEqual([item.ip_address for item in candidates], ["198.51.100.25", "203.0.113.50"])
        self.assertEqual(candidates[0].analyzed_source_count, 0)

    def test_run_reputation_analysis_uses_clients_and_aggregates_verdict(self):
        class FakeAbuse:
            def analyze(self, ip):
                return ReputationClientResult(
                    source=ReputationSource.ABUSEIPDB,
                    status=ReputationStatus.SUCCESS,
                    verdict=ReputationVerdict.MALICIOUS if ip == "198.51.100.25" else ReputationVerdict.CLEAN,
                    score=90 if ip == "198.51.100.25" else 0,
                    country="BF",
                    raw={"fake": True},
                    error_message="",
                    analyzed_at=timezone.now(),
                )

        result = run_reputation_analysis(
            tools=[ReputationSource.ABUSEIPDB],
            limit=10,
            client_classes={ReputationSource.ABUSEIPDB: FakeAbuse},
        )

        self.assertEqual(result["analyzed_count"], 2)
        malicious = next(item for item in result["records"] if item["ip_address"] == "198.51.100.25")
        self.assertEqual(malicious["verdict"], ReputationVerdict.MALICIOUS)
        self.assertEqual(malicious["score"], 90)
        self.assertEqual(result["observation_sync"]["observation_count"], 2)

        observation = PeerObservation.objects.get(peer_reputation__ip_address="198.51.100.25")
        self.assertEqual(observation.network, self.network)
        self.assertEqual(observation.host_ip, "10.0.0.11")
        self.assertEqual(observation.host_service, "ssh")
        self.assertEqual(observation.flow_count, 1)
        self.assertEqual(observation.total_bytes, 20_000)
        self.assertEqual(observation.total_duration_seconds, 900)
        self.assertEqual(observation.max_duration_seconds, 900)
        self.assertEqual(observation.avg_duration_seconds, 900)

    def test_sync_peer_observations_materializes_external_peer_to_internal_host(self):
        result = sync_peer_observations()

        self.assertEqual(result["observation_count"], 2)
        self.assertEqual(result["created_count"], 2)

        observation = PeerObservation.objects.get(peer_reputation__ip_address="203.0.113.50")
        self.assertEqual(observation.host_ip, "10.0.0.10")
        self.assertEqual(observation.host_service, "https")
        self.assertEqual(observation.host_port_category, "Web")
        self.assertEqual(observation.total_duration_seconds, 120)
        self.assertEqual(observation.peer_reputation.flow_count, 0)

    def test_top_peers_filters_recent_period_and_orders_by_duration(self):
        IPReputation.objects.create(
            ip_address="198.51.100.25",
            verdict=ReputationVerdict.MALICIOUS,
            score=90,
            country="BF",
            source_count=1,
            successful_source_count=1,
        )
        IPReputation.objects.create(
            ip_address="203.0.113.50",
            verdict=ReputationVerdict.CLEAN,
            score=0,
            country="FR",
            source_count=1,
            successful_source_count=1,
        )

        result = top_peers(
            {
                "date_from": "2026-06-24T08:30:00Z",
                "date_to": "2026-06-24T10:00:00Z",
                "verdict": ReputationVerdict.MALICIOUS,
                "min_duration": "600",
                "sort": "total_duration_seconds",
            }
        )

        self.assertEqual(len(result["results"]), 1)
        peer = result["results"][0]
        self.assertEqual(peer["peer_ip"], "198.51.100.25")
        self.assertEqual(peer["verdict"], ReputationVerdict.MALICIOUS)
        self.assertEqual(peer["country"], "BF")
        self.assertEqual(peer["total_duration_seconds"], 900)
        self.assertEqual(peer["host_ips"], ["10.0.0.11"])


class IPTimelineTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="timeline@example.com",
            password="a-long-test-password",
            role=UserRole.ANALYST,
        )
        self.structure = Structure.objects.create(name="Structure timeline", code="TIM")
        self.network = Network.objects.create(structure=self.structure, name="Réseau timeline")
        self.ip = "203.0.113.77"
        self.flow = Flow.objects.create(
            network=self.network,
            sna_flow_id="timeline-flow",
            started_at="2026-06-24T08:26:23Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.INBOUND,
            src_ip=self.ip,
            src_port=44444,
            dst_ip="10.10.1.50",
            dst_port=443,
            protocol="TCP",
            service="https",
            application="HTTPS",
            total_bytes=12_000,
            total_packets=120,
        )
        self.bulletin = Bulletin.objects.create(
            structure=self.structure,
            severity=BulletinSeverity.HIGH,
            created_by=self.user,
            updated_by=self.user,
            sent_at=timezone.now(),
        )
        BulletinIP.objects.create(
            bulletin=self.bulletin,
            ip_address=self.ip,
            role=BulletinIPRole.SOURCE,
        )
        self.response = BulletinResponse.objects.create(
            bulletin=self.bulletin,
            respondent_name="SOC Structure",
            respondent_email="soc@example.com",
            received_at=timezone.now(),
            content="IP bloquée côté firewall.",
            created_by=self.user,
        )

    def test_ip_timeline_correlates_flows_bulletins_and_responses(self):
        result = build_ip_timeline(self.ip, {"structure_id": str(self.structure.id)})

        self.assertEqual(result["ip"], self.ip)
        self.assertEqual(result["counts"]["flows"], 1)
        self.assertEqual(result["counts"]["bulletins"], 1)
        self.assertEqual(result["counts"]["responses"], 1)
        self.assertEqual(result["flows"][0]["side"], "source")
        self.assertEqual(result["bulletins"][0]["reference"], self.bulletin.reference)
        self.assertEqual(result["responses"][0]["bulletin"]["reference"], self.bulletin.reference)
        self.assertEqual(result["conversation_groups"][0]["flow_count"], 1)
        self.assertEqual({item["type"] for item in result["timeline"]}, {"flow", "bulletin", "response"})


class BulletinBusinessTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="bulletins@example.com",
            password="a-long-test-password",
            role=UserRole.ANALYST,
        )
        self.structure = Structure.objects.create(name="Structure bulletins", code="BUL")
        self.risk = RiskCatalog.objects.create(name="Exfiltration potentielle de données")
        self.other_risk = RiskCatalog.objects.create(name="Compte compromis")
        self.bulletin_type = BulletinTypeCatalog.objects.create(name="Tunnel SSH")
        self.recommendation = RecommendationCatalog.objects.create(
            name="Vérifier session SSH longue",
            description="Contrôler compte, source, destination, transferts et tunnels éventuels.",
        )
        self.payload = {
            "structure": self.structure,
            "severity": BulletinSeverity.HIGH,
            "ips": [{"ip_address": "203.0.113.77", "role": BulletinIPRole.SOURCE}],
            "risks": [self.risk],
            "bulletin_types": [self.bulletin_type],
            "recommendations": [self.recommendation],
        }

    def test_create_bulletin_with_links(self):
        bulletin, duplicates = create_bulletin_with_links(self.payload, self.user)

        self.assertEqual(duplicates, [])
        self.assertIsNotNone(bulletin)
        self.assertEqual(bulletin.ip_addresses.count(), 1)
        self.assertEqual(bulletin.risk_links.count(), 1)
        self.assertEqual(bulletin.type_links.count(), 1)
        self.assertEqual(bulletin.recommendation_links.count(), 1)
        self.assertEqual(len(bulletin.ip_signature), 64)

    def test_duplicate_is_blocked_without_force_and_allowed_with_force(self):
        first, _ = create_bulletin_with_links(self.payload, self.user)
        second, duplicates = create_bulletin_with_links(self.payload, self.user)

        self.assertIsNone(second)
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0]["reference"], first.reference)

        forced, forced_duplicates = create_bulletin_with_links(self.payload, self.user, force_duplicate=True)
        self.assertIsNotNone(forced)
        self.assertEqual(len(forced_duplicates), 1)

    def test_same_ips_with_different_risk_is_not_duplicate(self):
        create_bulletin_with_links(self.payload, self.user)

        duplicates = find_duplicate_bulletins(
            structure_id=self.structure.id,
            ips=self.payload["ips"],
            risk_ids=[self.other_risk.id],
        )

        self.assertEqual(duplicates, [])

    def test_create_bulletin_from_peer_observation_and_risk_profile(self):
        network = Network.objects.create(structure=self.structure, name="Réseau bulletin findings")
        reputation = IPReputation.objects.create(
            ip_address="198.51.100.99",
            verdict=ReputationVerdict.MALICIOUS,
            score=95,
            country="GH",
        )
        observation = PeerObservation.objects.create(
            peer_reputation=reputation,
            network=network,
            host_ip="10.20.30.40",
            host_port=22,
            host_service="ssh",
            host_port_category="Administration distante",
            flow_count=8,
            total_bytes=500_000,
            total_duration_seconds=3600,
        )
        risk_profile = RiskProfile.objects.create(
            name="Accès SSH prolongé depuis une IP malveillante",
            impact="Risque d'accès distant non autorisé ou de tunnel.",
            recommendation="Vérifier les journaux SSH et restreindre l'accès à la source.",
            default_severity=BulletinSeverity.HIGH,
        )

        bulletin, duplicates = create_bulletin_from_findings(
            {
                "structure": self.structure,
                "peer_observations": [observation],
                "risk_profiles": [risk_profile],
            },
            self.user,
        )

        self.assertEqual(duplicates, [])
        self.assertIsNotNone(bulletin)
        self.assertEqual(bulletin.structure, self.structure)
        self.assertEqual(bulletin.severity, BulletinSeverity.HIGH)
        self.assertEqual(bulletin.findings.count(), 1)
        finding = bulletin.findings.get()
        self.assertEqual(finding.peer_observation, observation)
        self.assertEqual(finding.risk_profile, risk_profile)
        self.assertEqual(finding.impact_snapshot, risk_profile.impact)
        self.assertEqual(finding.recommendation_snapshot, risk_profile.recommendation)

        duplicate, duplicate_rows = create_bulletin_from_findings(
            {
                "structure": self.structure,
                "peer_observations": [observation],
                "risk_profiles": [risk_profile],
            },
            self.user,
        )
        self.assertIsNone(duplicate)
        self.assertEqual(len(duplicate_rows), 1)
        self.assertEqual(duplicate_rows[0]["reference"], bulletin.reference)

        timeline = build_ip_timeline("198.51.100.99", {"structure_id": str(self.structure.id)})
        self.assertEqual(timeline["counts"]["bulletins"], 1)
        self.assertEqual(timeline["bulletins"][0]["findings"][0]["host_ip"], "10.20.30.40")
