from django.urls import path
from .views import ml_scorer

urlpatterns = [
    path('', ml_scorer, name='ml_scorer'),
]
