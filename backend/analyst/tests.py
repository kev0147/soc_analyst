from django.test import TestCase

from .models import Bulletin, BulletinIP, Flow, Network, NetworkCIDR, Structure, User
from .models.choices import BulletinIPRole, BulletinSeverity, FlowDirection, MappingMethod, UserRole


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
            severity=BulletinSeverity.HIGH,
            created_by=self.user,
            updated_by=self.user,
        )
        BulletinIP.objects.create(
            bulletin=bulletin,
            ip_address="203.0.113.10",
            role=BulletinIPRole.SOURCE,
        )
        bulletin.refresh_from_db()
        self.assertRegex(bulletin.reference, r"^TEST-\d{4}-001$")
        self.assertEqual(len(bulletin.ip_signature), 64)

# Create your tests here.
