from django.shortcuts import render

# Create your views here.

from rest_framework import generics
from .models import CveFact
from .serializers import FactTableSerializer

from rest_framework.views import APIView
from rest_framework.response import Response
from django.db.models import Count, Sum
from .models import CveFact
from .serializers import FactTableSerializer


class CveSeverityAggregation(APIView):
    def get(self, request, *args, **kwargs):
        # Perform join and aggregation
        results = CveFact.objects.using('cve_db')\
            .values('cves_severity__severity')\
                .annotate(count=Count('severity_types'))\
                    .order_by('-count')
        print(str(results)) 
        
        return Response(results)
    
class CveImpactAggregation(APIView):
    def get(self, request, *args, **kwargs):
        # Perform join and aggregation
        results = CveFact.objects.using('cve_db').values('cves_scores__impact_score').annotate(count=Sum('impact_score')).order_by('impact_score').order_by('-sum')[:10]
        
        return Response(results)

class CveExplAggregation(APIView):
    def get(self, request, *args, **kwargs):
        # Perform join and aggregation
        results = CveFact.objects.using('cve_db').values('cves_scores__exploitability_score').annotate(count=Sum('exploitability_score')).order_by('exploitability_score').order_by('-sum')[:10]
        
        return Response(results)

class CveAttackVecAggregation(APIView):
    def get(self, request, *args, **kwargs):
        # Perform join and aggregation
        results = CveFact.objects.using('cve_db').values('cves_attack_vectors__attack_vector').annotate(count=Count('attack_vectors')).order_by('attack_vectors').order_by('-count')[:10]
        
        return Response(results)
    
class CVEList(generics.ListAPIView):
    queryset = CveFact.objects.using('cve_db').all()
    serializer_class = FactTableSerializer

class CVEBySeverity(generics.ListAPIView):
    serializer_class = FactTableSerializer

    def get_queryset(self):
        severity = self.kwargs['severity']
        return CveFact.objects.using('cve_db').filter(severity=severity)


# class CVEDetail(generics.RetrieveAPIView):
#     queryset = CVE.objects.using('cve_db').all()
#     serializer_class = CVESerializer
#     lookup_field = 'cve_id'