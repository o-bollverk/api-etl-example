from django.urls import path
from .views import CVEList, CveSeverityAggregation, CveImpactAggregation, CveExplAggregation, CveAttackVecAggregation

urlpatterns = [
    path('cves/', CVEList.as_view(), name='cve-list'),
    path('cves/severity/', CveSeverityAggregation.as_view(), name='cve-severity-aggregation'),
    path('cves/impact/', CveImpactAggregation.as_view(), name='cve-impact-aggregation'),
    path('cves/expl/', CveExplAggregation.as_view(), name='cve-expl-aggregation'),
    path('cves/attackvec/', CveAttackVecAggregation.as_view(), name='cve-attackvec-aggregation'),
]

