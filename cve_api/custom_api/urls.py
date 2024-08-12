from django.urls import path
from .views import CVEList, CveSeverityAggregation, CveImpactAggregation, CveExplAggregation, CveAttackVecAggregation

urlpatterns = [
    path('cves/', CVEList.as_view(), name='cve-list'),
    path('cves/<str:severity_aggregation>/', CveSeverityAggregation.as_view(), name='cve-severity-aggregation'),
    path('cves/<str:impact_aggregation>/', CveImpactAggregation.as_view(), name='cve-impact-aggregation'),
    path('cves/<str:expl_aggregation>/', CveExplAggregation.as_view(), name='cve-expl-aggregation'),
    path('cves/<str:attack_vector_aggregation>/', CveAttackVecAggregation.as_view(), name='cve-attackvec-aggregation'),
]

