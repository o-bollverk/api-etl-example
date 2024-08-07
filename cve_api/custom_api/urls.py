from django.urls import path
from .views import CVEList, CVEBySeverity, CveSeverityAggregation, CveImpactAggregation, CveExplAggregation, CveAttackVecAggregation

urlpatterns = [
    path('cves/', CVEList.as_view(), name='cve-list'),
    #path('cves/<str:cve_id>/', CVEDetail.as_view(), name='cve-detail'),
    # path('cves/<str:severity>/cves/', CVEBySeverity.as_view(), name='cve-by-severity'),
    path('cves/<str:severity_aggregation>/cves/', CveSeverityAggregation.as_view(), name='cve-severity-aggregation'),
    path('cves/<str:impact_aggregation>/cves/', CveImpactAggregation.as_view(), name='cve-impact-aggregation'),
    path('cves/<str:expl_aggregation>/cves/', CveExplAggregation.as_view(), name='cve-expl-aggregation'),
    path('cves/<str:attack_vector_aggregation>/cves/', CveAttackVecAggregation.as_view(), name='cve-attackvec-aggregation'),
]

