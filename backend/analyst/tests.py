from pathlib import Path
from io import StringIO
import tempfile
from datetime import timedelta
from unittest.mock import patch

from django.core.management import call_command, CommandError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db.utils import OperationalError
from django.test import RequestFactory, TestCase, override_settings

from django.utils import timezone

from .models import (
    AuditEvent,
    Bulletin,
    BulletinFinding,
    BulletinIP,
    BulletinResponse,
    BulletinTypeCatalog,
    BackgroundJob,
    Flow,
    FlowImport,
    FlowImportItem,
    IPReputation,
    IPReputationResult,
    Network,
    NetworkCIDR,
    PeerObservation,
    PeerObservationRisk,
    RecommendationCatalog,
    RiskCatalog,
    RiskIndicator,
    RiskProfile,
    RiskProfileIndicator,
    RiskProfilePortService,
    Structure,
    User,
)
from .models.choices import (
    BulletinIPRole,
    BulletinSeverity,
    BackgroundJobKind,
    BackgroundJobStatus,
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
from .services.analytics import (
    build_dashboard_overview,
    malicious_communications,
    top_conversations,
    top_peers,
    top_ports_protocols,
    top_talkers,
)
from .services.security import audit_action_catalog, permission_matrix
from .controllers.audit import record_audit
from .services.ip_reputation import candidate_ips, run_reputation_analysis
from .services.ip_reputation.clients import ReputationClientResult
from .services.peer_observations import sync_peer_observations
from .services.jobs.tasks import execute_background_job
from .services.jobs.supervisor import WorkerHeartbeat, worker_status
from .services.risk_profiles import import_risk_profiles_catalog
from .serializers.bulletin.serializer import BulletinAssistantDraftInputSerializer


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
TEST_MEDIA_ROOT = WORKSPACE_ROOT / "backend" / "media_test"


class RiskProfileCatalogImportTests(TestCase):
    def test_import_is_idempotent_and_expands_abbreviated_ports(self):
        content = (
            "ACTIVITÉS;PORTS/SERVICES;RISQUES;IMPACTS;IOCS;RECOMMANDATIONS;CRITICITÉ\n"
            "DDoS;3389 (RDP), 5985/86 (WinRM);Accès distant;Compromission de poste;"
            "Connexion depuis réseau externe;Activer VPN et NLA;Élevée\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".csv", encoding="utf-8", delete=False) as handle:
            handle.write(content)
            path = Path(handle.name)
        self.addCleanup(path.unlink, missing_ok=True)

        first = import_risk_profiles_catalog(path)
        second = import_risk_profiles_catalog(path)

        self.assertEqual(first["created"], 1)
        self.assertEqual(second["updated"], 1)
        self.assertEqual(RiskProfile.objects.count(), 1)
        profile = RiskProfile.objects.get()
        self.assertEqual(profile.activity, "DDoS")
        self.assertEqual(
            list(profile.port_services.values_list("port", flat=True)),
            [3389, 5985, 5986],
        )
        self.assertEqual(profile.indicator_links.get().indicator.name, "Connexion depuis réseau externe")


class BulletinAssistantTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="assistant@example.com",
            password="a-long-test-password",
            role=UserRole.ANALYST,
        )
        self.structure = Structure.objects.create(name="Structure assistant", code="assistant")
        self.network = Network.objects.create(structure=self.structure, name="Réseau assistant")
        self.reputation = IPReputation.objects.create(
            ip_address="203.0.113.8",
            verdict=ReputationVerdict.MALICIOUS,
            score=92,
            country="CA",
        )
        self.observation = PeerObservation.objects.create(
            peer_reputation=self.reputation,
            network=self.network,
            host_ip="10.0.0.10",
            host_port=22,
            host_service="ssh",
            flow_count=4,
            total_bytes=2048,
            total_duration_seconds=300,
        )
        self.profile = RiskProfile.objects.create(
            activity="DDoS",
            name="Attaque par brute force",
            impact="Accès non autorisé",
            recommendation="Sécuriser les accès SSH",
            default_severity=BulletinSeverity.HIGH,
        )
        RiskProfilePortService.objects.create(risk_profile=self.profile, port=22, service="SSH")
        self.indicator = RiskIndicator.objects.create(name="Tentatives répétées de connexion SSH")
        RiskProfileIndicator.objects.create(risk_profile=self.profile, indicator=self.indicator)

    def test_three_field_selection_creates_snapshot_bulletin_draft(self):
        serializer = BulletinAssistantDraftInputSerializer(data={
            "peer_ip": "203.0.113.8",
            "host_port": 22,
            "indicator_id": self.indicator.id,
        })
        self.assertTrue(serializer.is_valid(), serializer.errors)
        bulletin, duplicates = create_bulletin_from_findings(serializer.validated_data, self.user)

        self.assertFalse(duplicates)
        self.assertEqual(bulletin.status, "draft")
        finding = bulletin.findings.get()
        self.assertEqual(finding.peer_ip_snapshot, "203.0.113.8")
        self.assertEqual(finding.host_port_snapshot, 22)
        self.assertEqual(finding.risk_activity_snapshot, "DDoS")
        self.assertEqual(finding.ioc_snapshot, "Tentatives répétées de connexion SSH")


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
            '"peer.ipAddress","peer.orientation","peer.portProtocol.port","peer.portProtocol.protocol","peer.hostGroups",'
            '"connection.transferBytes","connection.transferPackets","connection.transferByteRate","connection.transferPacketRate",'
            '"connection.tcpConnections","connection.tcpRetransmissions","connection.application.name"\n'
            '2246437167,"301","Wed Jul 08 22:44:40 UTC 2026","Wed Jul 08 22:44:41 UTC 2026","1000",'
            '"10.10.30.40","server","5060","UDP",'
            '"192.95.20.52","client","4040","UDP","Canada",'
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
        self.assertEqual(flow.src_location, "Canada")
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

    def test_import_keeps_cross_network_rows_and_rejects_only_unmatched_rows(self):
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
        self.assertEqual(flow_import.accepted_rows, 1)
        self.assertEqual(flow_import.rejected_rows, 1)

        cross_flow = Flow.objects.get(sna_flow_id="cross")
        self.assertEqual(cross_flow.direction, FlowDirection.INTERNAL)
        self.assertEqual(cross_flow.network, self.network)
        self.assertEqual(cross_flow.src_network, self.network)
        self.assertEqual(cross_flow.dst_network, second_network)
        self.assertEqual(
            list(apply_flow_filters(Flow.objects.all(), {"network_id": str(second_network.id)})),
            [cross_flow],
        )

        observation_sync = sync_peer_observations(scope="import", import_id=flow_import.id)
        self.assertEqual(observation_sync["observation_count"], 0)

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


class BackgroundJobTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="jobs@example.com",
            password="a-long-test-password",
            role=UserRole.ANALYST,
        )
        self.structure = Structure.objects.create(name="Structure jobs", code="JOB")
        self.network = Network.objects.create(structure=self.structure, name="Réseau jobs")
        NetworkCIDR.objects.create(network=self.network, cidr="10.30.0.0/16")

    def test_flow_import_job_completes_and_reports_progress(self):
        csv_body = (
            "Flow ID,Start,Subject IP Address,Subject Orientation,Subject Port/Protocol,"
            "Peer IP Address,Peer Orientation,Peer Port/Protocol,protocol\n"
            "job-flow,2026-07-08T10:00:00Z,10.30.1.20,Client,50000/TCP,198.51.100.1,Server,443/TCP,TCP\n"
        )
        upload = SimpleUploadedFile("job-flows.csv", csv_body.encode("utf-8"), content_type="text/csv")
        with self.settings(MEDIA_ROOT=TEST_MEDIA_ROOT):
            preview = preview_flow_import_upload(upload, self.structure, self.user)
            flow_import = FlowImport.objects.get(pk=preview["import_id"])
            job = BackgroundJob.objects.create(
                kind=BackgroundJobKind.FLOW_IMPORT,
                created_by=self.user,
                flow_import=flow_import,
                payload={"import_id": flow_import.id},
            )
            result = execute_background_job(str(job.id))

        job.refresh_from_db()
        flow_import.refresh_from_db()
        self.assertEqual(job.status, BackgroundJobStatus.COMPLETED)
        self.assertEqual(job.progress_current, 1)
        self.assertEqual(job.progress_total, 1)
        self.assertEqual(job.progress_percent, 100)
        self.assertEqual(result["accepted_rows"], 1)
        self.assertEqual(flow_import.status, ImportStatus.COMPLETED)
        self.assertTrue(AuditEvent.objects.filter(action="BACKGROUND_JOB_COMPLETED", entity_id=str(job.id)).exists())

    def test_job_failure_is_persisted_and_audited(self):
        job = BackgroundJob.objects.create(
            kind=BackgroundJobKind.FLOW_IMPORT,
            created_by=self.user,
            payload={},
        )

        with self.assertRaises(ValueError):
            execute_background_job(str(job.id))

        job.refresh_from_db()
        self.assertEqual(job.status, BackgroundJobStatus.FAILED)
        self.assertTrue(job.error_message)
        self.assertTrue(job.can_retry)
        self.assertTrue(AuditEvent.objects.filter(action="BACKGROUND_JOB_FAILED", entity_id=str(job.id)).exists())

    def test_empty_ip_reputation_job_completes(self):
        job = BackgroundJob.objects.create(
            kind=BackgroundJobKind.IP_REPUTATION,
            created_by=self.user,
            payload={"scope": "all_flows", "tools": [ReputationSource.ABUSEIPDB], "limit": 10},
        )

        result = execute_background_job(str(job.id))

        job.refresh_from_db()
        self.assertEqual(job.status, BackgroundJobStatus.COMPLETED)
        self.assertEqual(job.progress_percent, 100)
        self.assertEqual(result["candidate_count"], 0)

    def test_database_lock_is_retried_before_job_failure(self):
        job = BackgroundJob.objects.create(
            kind=BackgroundJobKind.IP_REPUTATION,
            created_by=self.user,
            payload={"scope": "all_flows"},
        )
        with override_settings(SQLITE_LOCK_RETRY_ATTEMPTS=2, SQLITE_LOCK_RETRY_BASE_SECONDS=0.01), patch(
            "analyst.services.jobs.tasks._run_recoverable",
            side_effect=[OperationalError("database is locked"), {"candidate_count": 0}],
        ) as mocked_run:
            result = execute_background_job(str(job.id))

        job.refresh_from_db()
        self.assertEqual(mocked_run.call_count, 2)
        self.assertEqual(job.status, BackgroundJobStatus.COMPLETED)
        self.assertEqual(result["candidate_count"], 0)


class BackgroundJobApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="jobs-api@example.com",
            password="a-long-test-password",
            role=UserRole.ANALYST,
        )
        self.structure = Structure.objects.create(name="Structure jobs API", code="JAPI")
        self.client.force_login(self.user)

    def test_confirm_import_returns_a_persistent_queued_job(self):
        flow_import = FlowImport.objects.create(
            structure=self.structure,
            uploaded_by=self.user,
            status=ImportStatus.PENDING,
            original_filename="queued.csv",
            stored_path="queued.csv",
            file_sha256="0" * 64,
            file_size_bytes=10,
        )

        response = self.client.post(
            "/api/v1/flow-imports/confirm/",
            {"import_id": flow_import.id},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["job"]["status"], BackgroundJobStatus.QUEUED)
        self.assertEqual(response.json()["flow_import"]["id"], flow_import.id)
        self.assertEqual(BackgroundJob.objects.filter(flow_import=flow_import).count(), 1)

    def test_ip_analysis_endpoint_returns_same_active_job_for_same_payload(self):
        payload = {
            "scope": "all_flows",
            "tools": [ReputationSource.ABUSEIPDB],
            "limit": 10,
        }

        first = self.client.post("/api/v1/ip-analysis/run/", payload, content_type="application/json")
        second = self.client.post("/api/v1/ip-analysis/run/", payload, content_type="application/json")

        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 202)
        self.assertEqual(first.json()["job"]["id"], second.json()["job"]["id"])
        self.assertTrue(second.json()["already_queued"])

    def test_ip_analysis_endpoint_rejects_shodan_as_reputation_source(self):
        response = self.client.post(
            "/api/v1/ip-analysis/run/",
            {"scope": "all_flows", "tools": [ReputationSource.SHODAN], "limit": 10},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)


class StructureAdministrationApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            email="structure-admin@example.com",
            password="a-long-test-password",
            role=UserRole.ADMIN,
        )
        self.client.force_login(self.admin)

    def test_admin_can_create_structure_network_and_cidr_then_filter_them(self):
        structure_response = self.client.post(
            "/api/v1/structures/create/",
            {"name": "Nouvelle structure", "code": "NEW", "description": "SOC"},
            content_type="application/json",
        )
        self.assertEqual(structure_response.status_code, 201)
        structure_id = structure_response.json()["id"]

        network_response = self.client.post(
            "/api/v1/networks/create/",
            {"structure": structure_id, "name": "Réseau principal"},
            content_type="application/json",
        )
        self.assertEqual(network_response.status_code, 201)
        network_id = network_response.json()["id"]

        cidr_response = self.client.post(
            "/api/v1/network-cidrs/create/",
            {"network": network_id, "cidr": "10.20.30.40/24", "label": "LAN"},
            content_type="application/json",
        )
        networks = self.client.get("/api/v1/networks/", {"structure_id": structure_id})
        cidrs = self.client.get("/api/v1/network-cidrs/", {"network_id": network_id})

        self.assertEqual(cidr_response.status_code, 201)
        self.assertEqual(cidr_response.json()["cidr"], "10.20.30.0/24")
        self.assertEqual(networks.json()["count"], 1)
        self.assertEqual(cidrs.json()["count"], 1)


class WorkerApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            email="worker-admin@example.com",
            password="a-long-test-password",
            role=UserRole.ADMIN,
        )
        self.viewer = User.objects.create_user(
            email="worker-viewer@example.com",
            password="a-long-test-password",
            role=UserRole.VIEWER,
        )
        self.status = {
            "status": "running",
            "state": "idle",
            "pid": 123,
            "hostname": "test-host",
            "started_at": "2026-07-16T10:00:00+00:00",
            "last_heartbeat_at": "2026-07-16T10:00:05+00:00",
            "heartbeat_age_seconds": 1,
            "current_job_id": None,
        }

    @patch("analyst.controllers.worker.status.worker_status")
    def test_authenticated_user_can_read_worker_status(self, mocked_status):
        mocked_status.return_value = self.status
        self.client.force_login(self.viewer)

        response = self.client.get("/api/v1/workers/status/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "running")

    @patch("analyst.controllers.worker.start.start_background_worker")
    def test_only_admin_can_start_worker(self, mocked_start):
        mocked_start.return_value = {**self.status, "status": "starting", "state": "starting", "already_running": False}
        self.client.force_login(self.viewer)
        forbidden = self.client.post("/api/v1/workers/start/", {}, content_type="application/json")
        self.client.force_login(self.admin)
        accepted = self.client.post("/api/v1/workers/start/", {}, content_type="application/json")

        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(accepted.status_code, 202)
        self.assertTrue(AuditEvent.objects.filter(action="BACKGROUND_WORKER_START_REQUESTED").exists())

    def test_heartbeat_reports_running_then_stopped_without_database_writes(self):
        TEST_MEDIA_ROOT.mkdir(parents=True, exist_ok=True)
        with override_settings(
            BASE_DIR=TEST_MEDIA_ROOT,
            WORKER_HEARTBEAT_SECONDS=1,
            WORKER_STALE_SECONDS=5,
        ):
            with WorkerHeartbeat():
                running = worker_status()
            stopped = worker_status()

        self.assertEqual(running["status"], "running")
        self.assertEqual(running["state"], "idle")
        self.assertEqual(stopped["status"], "stopped")

    @patch("analyst.controllers.worker.logs.worker_log_tail")
    def test_only_admin_can_read_worker_logs(self, mocked_logs):
        mocked_logs.return_value = {"line_limit": 100, "files": [{"name": "worker.err.log", "lines": ["test"]}]}
        self.client.force_login(self.viewer)
        forbidden = self.client.get("/api/v1/workers/logs/")
        self.client.force_login(self.admin)
        accepted = self.client.get("/api/v1/workers/logs/")

        self.assertEqual(forbidden.status_code, 403)
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.json()["files"][0]["lines"], ["test"])

    @patch("analyst.controllers.worker.start.start_background_worker")
    def test_worker_start_returns_explicit_operating_system_error(self, mocked_start):
        mocked_start.side_effect = OSError("accès refusé")
        self.client.force_login(self.admin)

        response = self.client.post("/api/v1/workers/start/", {}, content_type="application/json")

        self.assertEqual(response.status_code, 503)
        self.assertIn("accès refusé", response.json()["detail"])

    def test_missing_heartbeat_falls_back_to_worker_lock(self):
        missing_path = TEST_MEDIA_ROOT / "missing-worker-status.json"
        with patch("analyst.services.jobs.supervisor._status_path", return_value=missing_path), patch(
            "analyst.services.jobs.supervisor._worker_lock_is_held", return_value=True
        ):
            status = worker_status()

        self.assertEqual(status["status"], "running")
        self.assertEqual(status["state"], "idle")
        self.assertIn("verrou local", status["detail"])


class IPAnalysisRecordsApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="ip-records@example.com",
            password="a-long-test-password",
            role=UserRole.VIEWER,
        )
        self.structure = Structure.objects.create(name="Structure IP A", code="IPA")
        self.other_structure = Structure.objects.create(name="Structure IP B", code="IPB")
        self.network = Network.objects.create(structure=self.structure, name="Réseau IP A")
        self.other_network = Network.objects.create(structure=self.other_structure, name="Réseau IP B")
        self.reputation = IPReputation.objects.create(
            ip_address="198.51.100.10",
            verdict=ReputationVerdict.MALICIOUS,
            score=95,
        )
        self.other_reputation = IPReputation.objects.create(
            ip_address="203.0.113.10",
            verdict=ReputationVerdict.MALICIOUS,
            score=90,
        )
        PeerObservation.objects.create(
            peer_reputation=self.reputation,
            network=self.network,
            host_ip="10.0.0.10",
        )
        PeerObservation.objects.create(
            peer_reputation=self.reputation,
            network=self.network,
            host_ip="10.0.0.11",
        )
        PeerObservation.objects.create(
            peer_reputation=self.other_reputation,
            network=self.other_network,
            host_ip="10.1.0.10",
        )
        self.client.force_login(self.user)

    def test_records_can_be_filtered_by_structure_without_duplicates(self):
        response = self.client.get(
            "/api/v1/ip-analysis/records/",
            {"structure_id": self.structure.id, "verdict": ReputationVerdict.MALICIOUS},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["ip_address"], self.reputation.ip_address)

    def test_records_reject_invalid_structure_id(self):
        response = self.client.get("/api/v1/ip-analysis/records/", {"structure_id": "abc"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("structure_id", response.json())


class FlowExplorationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="viewer@example.com",
            password="a-long-test-password",
            role=UserRole.VIEWER,
        )
        self.structure = Structure.objects.create(name="Structure exploration", code="EXP")
        self.external_structure = Structure.objects.create(name="Autre structure", code="OTHER")
        self.network = Network.objects.create(structure=self.structure, name="Réseau exploration")
        self.other_network = Network.objects.create(structure=self.structure, name="Autre réseau")
        self.external_network = Network.objects.create(
            structure=self.external_structure,
            name="Réseau autre structure",
        )
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
        self.flow_c = Flow.objects.create(
            network=self.external_network,
            sna_flow_id="flow-c",
            started_at="2026-06-24T10:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.20.1.10",
            src_port=53000,
            dst_ip="192.0.2.53",
            dst_port=53,
            protocol="UDP",
            service="dns",
            application="DNS",
            total_bytes=250,
        )

    def test_apply_flow_filters_by_structure_includes_all_its_networks(self):
        queryset = apply_flow_filters(
            Flow.objects.all(),
            {"structure_id": str(self.structure.id)},
        )

        self.assertEqual(set(queryset), {self.flow_a, self.flow_b})

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
            duration_seconds=600,
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
            duration_seconds=120,
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

    def test_dashboard_ranks_malicious_ips_and_hosts_by_volume_and_duration(self):
        IPReputation.objects.create(
            ip_address="198.51.100.10",
            verdict=ReputationVerdict.MALICIOUS,
            score=95,
            country="BF",
        )
        IPReputation.objects.create(
            ip_address="203.0.113.20",
            verdict=ReputationVerdict.MALICIOUS,
            score=90,
            country="FR",
        )
        Flow.objects.create(
            network=self.network,
            sna_flow_id="dash-c",
            started_at="2026-06-24T10:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.0.0.20",
            src_port=50002,
            dst_ip="203.0.113.20",
            dst_port=22,
            protocol="TCP",
            service="ssh",
            duration_seconds=60,
            total_bytes=50_000,
            total_packets=500,
        )
        other_structure = Structure.objects.create(name="Structure dashboard externe", code="DSHX")
        other_network = Network.objects.create(structure=other_structure, name="Réseau dashboard externe")
        Flow.objects.create(
            network=other_network,
            sna_flow_id="dash-outside-scope",
            started_at="2026-06-24T11:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.99.0.10",
            dst_ip="198.51.100.10",
            duration_seconds=10_000,
            total_bytes=1_000_000,
        )

        overview = build_dashboard_overview({"structure_id": str(self.structure.id), "limit": "10"})

        self.assertEqual(overview["top_malicious_ips_by_volume"][0]["ip_address"], "203.0.113.20")
        self.assertEqual(overview["top_malicious_ips_by_volume"][0]["total_bytes"], 80_000)
        self.assertEqual(overview["top_malicious_ips_by_duration"][0]["ip_address"], "198.51.100.10")
        self.assertEqual(overview["top_malicious_ips_by_duration"][0]["total_duration_seconds"], 600)
        self.assertEqual(overview["top_hosts_with_malicious_by_volume"][0]["host_ip"], "10.0.0.20")
        self.assertEqual(overview["top_hosts_with_malicious_by_duration"][0]["host_ip"], "10.0.0.10")


class MaliciousCommunicationsAnalysisTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="correlation@example.com",
            password="a-long-test-password",
            role=UserRole.ANALYST,
        )
        self.structure = Structure.objects.create(name="Structure corrélation", code="CORR")
        self.network = Network.objects.create(structure=self.structure, name="Réseau corrélation")
        self.other_structure = Structure.objects.create(name="Structure hors périmètre", code="OUT")
        self.other_network = Network.objects.create(structure=self.other_structure, name="Réseau hors périmètre")
        IPReputation.objects.create(
            ip_address="198.51.100.10",
            verdict=ReputationVerdict.MALICIOUS,
            score=95,
            country="FR",
        )
        IPReputation.objects.create(
            ip_address="203.0.113.20",
            verdict=ReputationVerdict.MALICIOUS,
            score=80,
            country="CA",
        )
        self.flow_a = Flow.objects.create(
            network=self.network,
            sna_flow_id="corr-a",
            started_at="2026-07-01T08:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.0.0.10",
            src_port=51000,
            dst_ip="198.51.100.10",
            dst_port=443,
            service="https",
            duration_seconds=100,
            total_bytes=10_000,
        )
        self.flow_b = Flow.objects.create(
            network=self.network,
            sna_flow_id="corr-b",
            started_at="2026-07-02T08:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.INBOUND,
            src_ip="203.0.113.20",
            src_port=44444,
            dst_ip="10.0.0.10",
            dst_port=22,
            service="ssh",
            duration_seconds=200,
            total_bytes=20_000,
        )
        self.flow_c = Flow.objects.create(
            network=self.network,
            sna_flow_id="corr-c",
            started_at="2026-07-03T08:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.0.0.20",
            src_port=52000,
            dst_ip="198.51.100.10",
            dst_port=443,
            service="https",
            duration_seconds=50,
            total_bytes=5_000,
        )
        Flow.objects.create(
            network=self.other_network,
            sna_flow_id="corr-outside",
            started_at="2026-07-03T09:00:00Z",
            mapping_method=MappingMethod.ORIENTATION,
            direction=FlowDirection.OUTBOUND,
            src_ip="10.99.0.10",
            dst_ip="198.51.100.10",
            dst_port=443,
            duration_seconds=9_999,
            total_bytes=9_999_999,
        )

    def test_structure_scope_correlates_hosts_peers_ports_countries_and_totals(self):
        result = malicious_communications({
            "scope": "structure",
            "structure_id": str(self.structure.id),
            "ordering": "-total_bytes",
        })

        self.assertEqual(result["count"], 3)
        self.assertEqual(result["totals"]["hosts"], 2)
        self.assertEqual(result["totals"]["correlations"], 3)
        self.assertEqual(result["totals"]["total_bytes"], 35_000)
        first = result["results"][0]
        self.assertEqual(first["host_ip"], "10.0.0.10")
        self.assertEqual(first["host_ports"], [22])
        self.assertEqual(first["malicious_ip"], "203.0.113.20")
        self.assertEqual(first["reputation_verdict"], ReputationVerdict.MALICIOUS)
        self.assertEqual(first["reputation_score"], 80)
        self.assertEqual(first["peer_country"], "CA")
        self.assertEqual(first["total_duration_seconds"], 200)

    def test_import_and_date_scopes_and_peer_filters(self):
        flow_import = FlowImport.objects.create(
            structure=self.structure,
            uploaded_by=self.user,
            original_filename="scope.csv",
            stored_path="scope.csv",
            file_sha256="a" * 64,
            file_size_bytes=100,
        )
        FlowImportItem.objects.create(flow_import=flow_import, flow=self.flow_a, source_row_number=1)
        FlowImportItem.objects.create(flow_import=flow_import, flow=self.flow_c, source_row_number=2)

        imported = malicious_communications({"scope": "import", "import_id": str(flow_import.id)})
        dated = malicious_communications({
            "scope": "date_range",
            "date_from": "2026-07-02T00:00:00Z",
            "date_to": "2026-07-02T23:59:59Z",
            "country": "CA",
            "host_port": "22",
        })

        self.assertEqual(imported["totals"]["flows"], 2)
        self.assertEqual(imported["totals"]["malicious_peers"], 1)
        self.assertEqual(dated["count"], 1)
        self.assertEqual(dated["results"][0]["total_bytes"], 20_000)

    def test_country_falls_back_to_peer_location_from_flow(self):
        reputation = IPReputation.objects.get(ip_address="198.51.100.10")
        reputation.country = ""
        reputation.save(update_fields=("country", "updated_at"))
        self.flow_a.dst_location = "France"
        self.flow_a.save(update_fields=("dst_location",))

        result = malicious_communications({
            "scope": "structure",
            "structure_id": str(self.structure.id),
            "peer_ip": "198.51.100.10",
            "country": "France",
        })

        self.assertEqual(result["count"], 1)
        self.assertTrue(all(row["peer_country"] == "France" for row in result["results"]))


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

        second_run = run_reputation_analysis(
            tools=[ReputationSource.ABUSEIPDB],
            limit=10,
            client_classes={ReputationSource.ABUSEIPDB: FakeAbuse},
        )
        self.assertEqual(second_run["candidate_count"], 0)
        self.assertEqual(second_run["source_analysis_count"], 0)

        forced_run = run_reputation_analysis(
            tools=[ReputationSource.ABUSEIPDB],
            limit=10,
            client_classes={ReputationSource.ABUSEIPDB: FakeAbuse},
            force_refresh=True,
        )
        self.assertEqual(forced_run["candidate_count"], 2)
        self.assertEqual(forced_run["source_analysis_count"], 2)

    def test_candidate_freshness_skips_fresh_results_and_prioritizes_expired_results(self):
        fresh_reputation = IPReputation.objects.create(ip_address="203.0.113.50")
        fresh_result = IPReputationResult.objects.create(
            reputation=fresh_reputation,
            source=ReputationSource.ABUSEIPDB,
            status=ReputationStatus.SUCCESS,
            verdict=ReputationVerdict.CLEAN,
            score=0,
            analyzed_at=timezone.now(),
            expires_at=timezone.now() + timedelta(hours=24),
        )
        expired_reputation = IPReputation.objects.create(ip_address="198.51.100.25")
        expired_result = IPReputationResult.objects.create(
            reputation=expired_reputation,
            source=ReputationSource.ABUSEIPDB,
            status=ReputationStatus.SUCCESS,
            verdict=ReputationVerdict.SUSPICIOUS,
            score=40,
            analyzed_at=timezone.now() - timedelta(days=2),
            expires_at=timezone.now() - timedelta(hours=1),
        )

        candidates = candidate_ips(tools=[ReputationSource.ABUSEIPDB], limit=10)

        self.assertFalse(fresh_result.is_stale)
        self.assertTrue(expired_result.is_stale)
        self.assertEqual([item.ip_address for item in candidates], ["198.51.100.25"])
        self.assertEqual(candidates[0].priority, "expired")
        self.assertEqual(candidates[0].due_tools, (ReputationSource.ABUSEIPDB,))

        forced = candidate_ips(
            tools=[ReputationSource.ABUSEIPDB],
            limit=10,
            force_refresh=True,
        )
        self.assertEqual({item.ip_address for item in forced}, {"198.51.100.25", "203.0.113.50"})

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
        reputation_result = IPReputationResult.objects.create(
            reputation=reputation,
            source=ReputationSource.ABUSEIPDB,
            status=ReputationStatus.SUCCESS,
            verdict=ReputationVerdict.MALICIOUS,
            score=95,
            country="GH",
            analyzed_at=timezone.now(),
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
        self.assertEqual(finding.peer_ip_snapshot, "198.51.100.99")
        self.assertEqual(finding.peer_country_snapshot, "GH")
        self.assertEqual(finding.host_ip_snapshot, "10.20.30.40")
        self.assertEqual(finding.host_port_snapshot, 22)
        self.assertEqual(finding.flow_count_snapshot, 8)
        self.assertEqual(finding.total_bytes_snapshot, 500_000)
        self.assertEqual(finding.reputation_verdict_snapshot, ReputationVerdict.MALICIOUS)
        self.assertEqual(finding.reputation_score_snapshot, 95)
        self.assertEqual(finding.reputation_results_snapshot[0]["source"], ReputationSource.ABUSEIPDB)
        self.assertEqual(
            finding.reputation_results_snapshot[0]["analyzed_at"],
            reputation_result.analyzed_at.isoformat(),
        )

        reputation.country = "FR"
        reputation.verdict = ReputationVerdict.CLEAN
        reputation.score = 0
        reputation.save()
        observation.host_port = 443
        observation.flow_count = 99
        observation.total_bytes = 9_000_000
        observation.save()
        risk_profile.name = "Risque renommé"
        risk_profile.impact = "Impact modifié"
        risk_profile.recommendation = "Recommandation modifiée"
        risk_profile.save()
        finding.refresh_from_db()

        self.assertEqual(finding.peer_country_snapshot, "GH")
        self.assertEqual(finding.host_port_snapshot, 22)
        self.assertEqual(finding.flow_count_snapshot, 8)
        self.assertEqual(finding.total_bytes_snapshot, 500_000)
        self.assertEqual(finding.reputation_verdict_snapshot, ReputationVerdict.MALICIOUS)
        self.assertEqual(finding.risk_name_snapshot, "Accès SSH prolongé depuis une IP malveillante")
        self.assertEqual(finding.impact_snapshot, "Risque d'accès distant non autorisé ou de tunnel.")
        self.assertEqual(
            finding.recommendation_snapshot,
            "Vérifier les journaux SSH et restreindre l'accès à la source.",
        )

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
