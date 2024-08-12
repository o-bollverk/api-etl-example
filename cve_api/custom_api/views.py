from django.shortcuts import render

# Create your views here.

from rest_framework import generics
from .models import CveFact

from rest_framework.views import APIView
from rest_framework.response import Response
from django.db.models import Count, Sum
from rest_framework import status
from .models import CveFact
import datetime

class CveImpactAggregation(APIView):
    def get(self, request, *args, **kwargs):
        min_date_str = request.query_params.get('min_date', None)
        min_date = None
        
        if min_date_str:
            try:
                # Parse the date string to a datetime object
                min_date = datetime.datetime.strptime(min_date_str, '%Y-%m-%d')
            except ValueError:
                return Response({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Build the queryset with optional date filter
        queryset = CveFact.objects.using('cve_db')
        
        if min_date:
            queryset = queryset.filter(cvescores__last_modified__gte=min_date)
            
        results = CveFact.objects.using('cve_db')\
            .values('cvescores__impact_score')\
            .values('cve_id_str','cvescores__last_modified' )\
            .annotate(impact_score_sum=Sum('cvescores__impact_score'))\
            .order_by('-impact_score_sum', 'cvescores__last_modified')[:10]
        
        return Response(results)

class CveExplAggregation(APIView):
    def get(self, request, *args, **kwargs):
        # Retrieve the minimum date from query parameters
        min_date_str = request.query_params.get('min_date', None)
        min_date = None
        
        if min_date_str:
            try:
                # Parse the date string to a datetime object
                min_date = datetime.datetime.strptime(min_date_str, '%Y-%m-%d')
            except ValueError:
                return Response({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Build the queryset with optional date filter
        queryset = CveFact.objects.using('cve_db')
        
        if min_date:
            queryset = queryset.filter(cvescores__last_modified__gte=min_date)
        
        results = queryset\
            .values('cvescores__exploitability_score')\
            .values('cve_id_str', 'cvescores__last_modified')\
            .annotate(exploitability_score_sum=Sum('cvescores__exploitability_score'))\
            .order_by('-exploitability_score_sum', 'cvescores__last_modified')[:10]
        
        return Response(results)
    
class CveAttackVecAggregation(APIView):
    def get(self, request, *args, **kwargs):
        min_date_str = request.query_params.get('min_date', None)
        min_date = None
        
        if min_date_str:
            try:
                # Parse the date string to a datetime object
                min_date = datetime.datetime.strptime(min_date_str, '%Y-%m-%d')
            except ValueError:
                return Response({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Build the queryset with optional date filter
        queryset = CveFact.objects.using('cve_db')
        
        if min_date:
            queryset = queryset.filter(cveattackvec__last_modified__gte=min_date)
        
        results = queryset\
            .values('cveattackvec__last_modified', "cveattackvec__attack_vector")\
            .annotate(attackvec_count=Count('cveattackvec__attack_vector'))\
            .order_by('-attackvec_count', 'cveattackvec__last_modified')[:10]
        
        return Response(results)

class CveSeverityAggregation(APIView):
    def get(self, request, *args, **kwargs):
        min_date_str = request.query_params.get('min_date', None)
        min_date = None
        
        if min_date_str:
            try:
                # Parse the date string to a datetime object
                min_date = datetime.datetime.strptime(min_date_str, '%Y-%m-%d')
            except ValueError:
                return Response({'error': 'Invalid date format. Use YYYY-MM-DD.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Build the queryset with optional date filter
        queryset = CveFact.objects.using('cve_db')
        
        if min_date:
            queryset = queryset.filter(cveseverity__last_modified__gte=min_date)
        
        results = queryset\
            .values('cveseverity__last_modified', "cveseverity__severity")\
            .annotate(severity_count=Count('cveseverity__severity'))\
            .order_by('-severity_count','cveseverity__last_modified')
        
        return Response(results)
    
    
class CVEList(generics.ListAPIView):

    def get(self, request, *args, **kwargs):
        cve_id_str = request.query_params.get('cve_id', None)
        cve_id_integer_part = None
        
        if cve_id_str:
            try:
                # TODO improve parsing and chechking of CVE_ID format
                cve_id_integer_part = int("".join(cve_id_str.split("-")[1:])) 
            except ValueError:
                return Response({'error': 'Invalid cve_id format.'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Build the queryset with optional cve_id filter
        queryset = CveFact.objects.using('cve_db')
        
        if cve_id_integer_part:
            queryset = queryset.filter(cveseverity__cve_id__gte=cve_id_integer_part)
        
        results = queryset\
            .values('cve_id', "cve_id_str", "description")\
            .order_by('-cve_id')
        
        return Response(results)
    
