from django.http import JsonResponse
from django.views.decorators.http import require_GET
import random

@require_GET
def ml_scorer(request):
    """
    Return a JSON response with a random integer.
    Format: {"ml_score": <int>}
    """
    # To Pick a random integer between 0 and 100
    value = random.randint(0, 100)
    return JsonResponse({"ml_score": value})
