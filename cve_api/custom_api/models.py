from django.db import models


# Create your models here.
class CveSeverity(models.Model):
    id = models.IntegerField(primary_key = True, unique=True)
    cve_id = models.IntegerField()
    severity = models.CharField(max_length=60)
    
    class Meta:
        db_table = 'cves_severity'
    
    def __str__(self):
        return self.cve_id

    
class CveScores(models.Model):
    id = models.IntegerField(primary_key = True, unique=True)
    cve_id = models.IntegerField()
    impact_score = models.FloatField()
    exploitability_score = models.FloatField()
    
    class Meta:
        db_table = 'cves_scores'
    
    def __str__(self):
        return self.cve_id
    
        
class CveAttackVec(models.Model):
    id = models.IntegerField(primary_key = True, unique=True)
    cve_id = models.IntegerField()
    attack_vector = models.CharField(max_length=500)
    
    class Meta:
        db_table = 'cves_attack_vectors'
    
    def __str__(self):
        return self.cve_id
    
    
    
# Create your models here.
class CveFact(models.Model):
    cve_id_str = models.CharField( max_length=90, unique=True)
    cve_id = models.IntegerField(primary_key = True, unique=True)
    description = models.CharField(max_length=500)
    
    severity_types = models.ForeignKey(CveSeverity, on_delete=models.CASCADE) 
    scores = models.ForeignKey(CveScores, on_delete=models.CASCADE) 
    attack_vectors = models.ForeignKey(CveAttackVec, on_delete=models.CASCADE) 
    
    class Meta:
        db_table = 'cves_fact'
    
    def __str__(self):
        return self.cve_id
    
    