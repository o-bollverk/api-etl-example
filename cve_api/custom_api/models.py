from django.db import models


class CveFact(models.Model):
    cve_id_str = models.CharField( max_length=90, unique=True)
    cve_id = models.IntegerField(primary_key = True, unique=True) 
    description = models.CharField(max_length=500)
    
    class Meta:
        db_table = 'cves_fact'
    
    def __str__(self):
        return self.cve_id
    

class CveSeverity(models.Model):
    id = models.IntegerField(primary_key = True, unique=True)
    cve =  models.ForeignKey(CveFact, on_delete=models.CASCADE) 
    severity = models.CharField(max_length=60)
    last_modified = models.DateField(default='2021-01-01')
    
    class Meta:
        db_table = 'cves_severity'
    
    def __str__(self):
        return self.cve_id


class CveAttackVec(models.Model):
    id = models.IntegerField(primary_key = True, unique=True)
    cve =  models.ForeignKey(CveFact, on_delete=models.CASCADE) 
    attack_vector = models.CharField(max_length=500)
    last_modified = models.DateField(default='2021-01-01')
    
    class Meta:
        db_table = 'cves_attack_vectors'
    
    def __str__(self):
        return self.cve_id
    
    
class CveScores(models.Model):
    main_id = models.IntegerField(primary_key = True, unique=True)
    cve = models.ForeignKey(CveFact, on_delete=models.CASCADE) 
    impact_score = models.FloatField()
    exploitability_score = models.FloatField()
    last_modified = models.DateField(default='2021-01-01')

    
    class Meta:
        db_table = 'cves_scores'
    
    def __str__(self):
        return self.cve_id
    

