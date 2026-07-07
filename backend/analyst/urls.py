from django.urls import path

from analyst.controllers.user.login import LoginController
from analyst.controllers.user.logout import LogoutController
from analyst.controllers.user.me import CurrentUserController
from analyst.controllers.bulletin.restore import BulletinRestoreController
from analyst.controllers.password_reset_token.consume import PasswordResetTokenConsumeController
from analyst.controllers.user.list import UserListController
from analyst.controllers.user.retrieve import UserRetrieveController
from analyst.controllers.user.create import UserCreateController
from analyst.controllers.user.update import UserUpdateController
from analyst.controllers.user.delete import UserDeleteController
from analyst.controllers.password_reset_token.list import PasswordResetTokenListController
from analyst.controllers.password_reset_token.retrieve import PasswordResetTokenRetrieveController
from analyst.controllers.password_reset_token.create import PasswordResetTokenCreateController
from analyst.controllers.structure.list import StructureListController
from analyst.controllers.structure.retrieve import StructureRetrieveController
from analyst.controllers.structure.create import StructureCreateController
from analyst.controllers.structure.update import StructureUpdateController
from analyst.controllers.structure.delete import StructureDeleteController
from analyst.controllers.network.list import NetworkListController
from analyst.controllers.network.retrieve import NetworkRetrieveController
from analyst.controllers.network.create import NetworkCreateController
from analyst.controllers.network.update import NetworkUpdateController
from analyst.controllers.network.delete import NetworkDeleteController
from analyst.controllers.network_cidr.list import NetworkCIDRListController
from analyst.controllers.network_cidr.retrieve import NetworkCIDRRetrieveController
from analyst.controllers.network_cidr.create import NetworkCIDRCreateController
from analyst.controllers.network_cidr.update import NetworkCIDRUpdateController
from analyst.controllers.network_cidr.delete import NetworkCIDRDeleteController
from analyst.controllers.flow_import.list import FlowImportListController
from analyst.controllers.flow_import.retrieve import FlowImportRetrieveController
from analyst.controllers.flow_import.create import FlowImportCreateController
from analyst.controllers.flow_import.delete import FlowImportDeleteController
from analyst.controllers.flow.list import FlowListController
from analyst.controllers.flow.retrieve import FlowRetrieveController
from analyst.controllers.flow_import_item.list import FlowImportItemListController
from analyst.controllers.flow_import_item.retrieve import FlowImportItemRetrieveController
from analyst.controllers.bulletin.list import BulletinListController
from analyst.controllers.bulletin.retrieve import BulletinRetrieveController
from analyst.controllers.bulletin.create import BulletinCreateController
from analyst.controllers.bulletin.update import BulletinUpdateController
from analyst.controllers.bulletin.delete import BulletinDeleteController
from analyst.controllers.bulletin_ip.list import BulletinIPListController
from analyst.controllers.bulletin_ip.retrieve import BulletinIPRetrieveController
from analyst.controllers.bulletin_ip.create import BulletinIPCreateController
from analyst.controllers.bulletin_ip.update import BulletinIPUpdateController
from analyst.controllers.bulletin_ip.delete import BulletinIPDeleteController
from analyst.controllers.bulletin_type_catalog.list import BulletinTypeCatalogListController
from analyst.controllers.bulletin_type_catalog.retrieve import BulletinTypeCatalogRetrieveController
from analyst.controllers.bulletin_type_catalog.create import BulletinTypeCatalogCreateController
from analyst.controllers.bulletin_type_catalog.update import BulletinTypeCatalogUpdateController
from analyst.controllers.bulletin_type_catalog.delete import BulletinTypeCatalogDeleteController
from analyst.controllers.risk_catalog.list import RiskCatalogListController
from analyst.controllers.risk_catalog.retrieve import RiskCatalogRetrieveController
from analyst.controllers.risk_catalog.create import RiskCatalogCreateController
from analyst.controllers.risk_catalog.update import RiskCatalogUpdateController
from analyst.controllers.risk_catalog.delete import RiskCatalogDeleteController
from analyst.controllers.recommendation_catalog.list import RecommendationCatalogListController
from analyst.controllers.recommendation_catalog.retrieve import RecommendationCatalogRetrieveController
from analyst.controllers.recommendation_catalog.create import RecommendationCatalogCreateController
from analyst.controllers.recommendation_catalog.update import RecommendationCatalogUpdateController
from analyst.controllers.recommendation_catalog.delete import RecommendationCatalogDeleteController
from analyst.controllers.bulletin_type.list import BulletinTypeListController
from analyst.controllers.bulletin_type.retrieve import BulletinTypeRetrieveController
from analyst.controllers.bulletin_type.create import BulletinTypeCreateController
from analyst.controllers.bulletin_type.delete import BulletinTypeDeleteController
from analyst.controllers.bulletin_risk.list import BulletinRiskListController
from analyst.controllers.bulletin_risk.retrieve import BulletinRiskRetrieveController
from analyst.controllers.bulletin_risk.create import BulletinRiskCreateController
from analyst.controllers.bulletin_risk.delete import BulletinRiskDeleteController
from analyst.controllers.bulletin_recommendation.list import BulletinRecommendationListController
from analyst.controllers.bulletin_recommendation.retrieve import BulletinRecommendationRetrieveController
from analyst.controllers.bulletin_recommendation.create import BulletinRecommendationCreateController
from analyst.controllers.bulletin_recommendation.delete import BulletinRecommendationDeleteController
from analyst.controllers.bulletin_response.list import BulletinResponseListController
from analyst.controllers.bulletin_response.retrieve import BulletinResponseRetrieveController
from analyst.controllers.bulletin_response.create import BulletinResponseCreateController
from analyst.controllers.bulletin_response.update import BulletinResponseUpdateController
from analyst.controllers.bulletin_response.delete import BulletinResponseDeleteController
from analyst.controllers.bulletin_attachment.list import BulletinAttachmentListController
from analyst.controllers.bulletin_attachment.retrieve import BulletinAttachmentRetrieveController
from analyst.controllers.bulletin_attachment.create import BulletinAttachmentCreateController
from analyst.controllers.bulletin_attachment.delete import BulletinAttachmentDeleteController
from analyst.controllers.audit_event.list import AuditEventListController
from analyst.controllers.audit_event.retrieve import AuditEventRetrieveController

app_name = "analyst"

urlpatterns = [
    path("auth/login/", LoginController.as_view(), name="login"),
    path("auth/logout/", LogoutController.as_view(), name="logout"),
    path("auth/me/", CurrentUserController.as_view(), name="current-user"),
    path("auth/password-reset/consume/", PasswordResetTokenConsumeController.as_view(), name="password-reset-consume"),
    path("users/", UserListController.as_view(), name="user-list"),
    path("users/<int:pk>/", UserRetrieveController.as_view(), name="user-retrieve"),
    path("users/create/", UserCreateController.as_view(), name="user-create"),
    path("users/<int:pk>/update/", UserUpdateController.as_view(), name="user-update"),
    path("users/<int:pk>/delete/", UserDeleteController.as_view(), name="user-delete"),
    path("password-reset-tokens/", PasswordResetTokenListController.as_view(), name="password_reset_token-list"),
    path("password-reset-tokens/<int:pk>/", PasswordResetTokenRetrieveController.as_view(), name="password_reset_token-retrieve"),
    path("password-reset-tokens/create/", PasswordResetTokenCreateController.as_view(), name="password_reset_token-create"),
    path("structures/", StructureListController.as_view(), name="structure-list"),
    path("structures/<int:pk>/", StructureRetrieveController.as_view(), name="structure-retrieve"),
    path("structures/create/", StructureCreateController.as_view(), name="structure-create"),
    path("structures/<int:pk>/update/", StructureUpdateController.as_view(), name="structure-update"),
    path("structures/<int:pk>/delete/", StructureDeleteController.as_view(), name="structure-delete"),
    path("networks/", NetworkListController.as_view(), name="network-list"),
    path("networks/<int:pk>/", NetworkRetrieveController.as_view(), name="network-retrieve"),
    path("networks/create/", NetworkCreateController.as_view(), name="network-create"),
    path("networks/<int:pk>/update/", NetworkUpdateController.as_view(), name="network-update"),
    path("networks/<int:pk>/delete/", NetworkDeleteController.as_view(), name="network-delete"),
    path("network-cidrs/", NetworkCIDRListController.as_view(), name="network_cidr-list"),
    path("network-cidrs/<int:pk>/", NetworkCIDRRetrieveController.as_view(), name="network_cidr-retrieve"),
    path("network-cidrs/create/", NetworkCIDRCreateController.as_view(), name="network_cidr-create"),
    path("network-cidrs/<int:pk>/update/", NetworkCIDRUpdateController.as_view(), name="network_cidr-update"),
    path("network-cidrs/<int:pk>/delete/", NetworkCIDRDeleteController.as_view(), name="network_cidr-delete"),
    path("flow-imports/", FlowImportListController.as_view(), name="flow_import-list"),
    path("flow-imports/<int:pk>/", FlowImportRetrieveController.as_view(), name="flow_import-retrieve"),
    path("flow-imports/create/", FlowImportCreateController.as_view(), name="flow_import-create"),
    path("flow-imports/<int:pk>/delete/", FlowImportDeleteController.as_view(), name="flow_import-delete"),
    path("flows/", FlowListController.as_view(), name="flow-list"),
    path("flows/<int:pk>/", FlowRetrieveController.as_view(), name="flow-retrieve"),
    path("flow-import-items/", FlowImportItemListController.as_view(), name="flow_import_item-list"),
    path("flow-import-items/<int:pk>/", FlowImportItemRetrieveController.as_view(), name="flow_import_item-retrieve"),
    path("bulletins/", BulletinListController.as_view(), name="bulletin-list"),
    path("bulletins/<int:pk>/", BulletinRetrieveController.as_view(), name="bulletin-retrieve"),
    path("bulletins/create/", BulletinCreateController.as_view(), name="bulletin-create"),
    path("bulletins/<int:pk>/update/", BulletinUpdateController.as_view(), name="bulletin-update"),
    path("bulletins/<int:pk>/delete/", BulletinDeleteController.as_view(), name="bulletin-delete"),
    path("bulletins/<int:pk>/restore/", BulletinRestoreController.as_view(), name="bulletin-restore"),
    path("bulletin-ips/", BulletinIPListController.as_view(), name="bulletin_ip-list"),
    path("bulletin-ips/<int:pk>/", BulletinIPRetrieveController.as_view(), name="bulletin_ip-retrieve"),
    path("bulletin-ips/create/", BulletinIPCreateController.as_view(), name="bulletin_ip-create"),
    path("bulletin-ips/<int:pk>/update/", BulletinIPUpdateController.as_view(), name="bulletin_ip-update"),
    path("bulletin-ips/<int:pk>/delete/", BulletinIPDeleteController.as_view(), name="bulletin_ip-delete"),
    path("bulletin-types/", BulletinTypeCatalogListController.as_view(), name="bulletin_type_catalog-list"),
    path("bulletin-types/<int:pk>/", BulletinTypeCatalogRetrieveController.as_view(), name="bulletin_type_catalog-retrieve"),
    path("bulletin-types/create/", BulletinTypeCatalogCreateController.as_view(), name="bulletin_type_catalog-create"),
    path("bulletin-types/<int:pk>/update/", BulletinTypeCatalogUpdateController.as_view(), name="bulletin_type_catalog-update"),
    path("bulletin-types/<int:pk>/delete/", BulletinTypeCatalogDeleteController.as_view(), name="bulletin_type_catalog-delete"),
    path("risks/", RiskCatalogListController.as_view(), name="risk_catalog-list"),
    path("risks/<int:pk>/", RiskCatalogRetrieveController.as_view(), name="risk_catalog-retrieve"),
    path("risks/create/", RiskCatalogCreateController.as_view(), name="risk_catalog-create"),
    path("risks/<int:pk>/update/", RiskCatalogUpdateController.as_view(), name="risk_catalog-update"),
    path("risks/<int:pk>/delete/", RiskCatalogDeleteController.as_view(), name="risk_catalog-delete"),
    path("recommendations/", RecommendationCatalogListController.as_view(), name="recommendation_catalog-list"),
    path("recommendations/<int:pk>/", RecommendationCatalogRetrieveController.as_view(), name="recommendation_catalog-retrieve"),
    path("recommendations/create/", RecommendationCatalogCreateController.as_view(), name="recommendation_catalog-create"),
    path("recommendations/<int:pk>/update/", RecommendationCatalogUpdateController.as_view(), name="recommendation_catalog-update"),
    path("recommendations/<int:pk>/delete/", RecommendationCatalogDeleteController.as_view(), name="recommendation_catalog-delete"),
    path("bulletin-type-links/", BulletinTypeListController.as_view(), name="bulletin_type-list"),
    path("bulletin-type-links/<int:pk>/", BulletinTypeRetrieveController.as_view(), name="bulletin_type-retrieve"),
    path("bulletin-type-links/create/", BulletinTypeCreateController.as_view(), name="bulletin_type-create"),
    path("bulletin-type-links/<int:pk>/delete/", BulletinTypeDeleteController.as_view(), name="bulletin_type-delete"),
    path("bulletin-risk-links/", BulletinRiskListController.as_view(), name="bulletin_risk-list"),
    path("bulletin-risk-links/<int:pk>/", BulletinRiskRetrieveController.as_view(), name="bulletin_risk-retrieve"),
    path("bulletin-risk-links/create/", BulletinRiskCreateController.as_view(), name="bulletin_risk-create"),
    path("bulletin-risk-links/<int:pk>/delete/", BulletinRiskDeleteController.as_view(), name="bulletin_risk-delete"),
    path("bulletin-recommendation-links/", BulletinRecommendationListController.as_view(), name="bulletin_recommendation-list"),
    path("bulletin-recommendation-links/<int:pk>/", BulletinRecommendationRetrieveController.as_view(), name="bulletin_recommendation-retrieve"),
    path("bulletin-recommendation-links/create/", BulletinRecommendationCreateController.as_view(), name="bulletin_recommendation-create"),
    path("bulletin-recommendation-links/<int:pk>/delete/", BulletinRecommendationDeleteController.as_view(), name="bulletin_recommendation-delete"),
    path("bulletin-responses/", BulletinResponseListController.as_view(), name="bulletin_response-list"),
    path("bulletin-responses/<int:pk>/", BulletinResponseRetrieveController.as_view(), name="bulletin_response-retrieve"),
    path("bulletin-responses/create/", BulletinResponseCreateController.as_view(), name="bulletin_response-create"),
    path("bulletin-responses/<int:pk>/update/", BulletinResponseUpdateController.as_view(), name="bulletin_response-update"),
    path("bulletin-responses/<int:pk>/delete/", BulletinResponseDeleteController.as_view(), name="bulletin_response-delete"),
    path("bulletin-attachments/", BulletinAttachmentListController.as_view(), name="bulletin_attachment-list"),
    path("bulletin-attachments/<int:pk>/", BulletinAttachmentRetrieveController.as_view(), name="bulletin_attachment-retrieve"),
    path("bulletin-attachments/create/", BulletinAttachmentCreateController.as_view(), name="bulletin_attachment-create"),
    path("bulletin-attachments/<int:pk>/delete/", BulletinAttachmentDeleteController.as_view(), name="bulletin_attachment-delete"),
    path("audit-events/", AuditEventListController.as_view(), name="audit_event-list"),
    path("audit-events/<int:pk>/", AuditEventRetrieveController.as_view(), name="audit_event-retrieve"),
]
