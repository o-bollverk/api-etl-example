from rest_framework import serializers
from .models import CveFact

class FactTableSerializer(serializers.ModelSerializer):
    class Meta:
        model = CveFact
        fields = '__all__'