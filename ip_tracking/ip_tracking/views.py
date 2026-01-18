from django.http import JsonResponse
from ratelimit.decorators import ratelimit
from django.contrib.auth import authenticate, login

# Example: login view
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@ratelimit(key='user', rate='10/m', method='POST', block=True)
def login_view(request):
    """
    Example login view with rate limiting:
    - Anonymous users: 5 requests/minute
    - Authenticated users: 10 requests/minute
    """
    if request.method != 'POST':
        return JsonResponse({"error": "POST request required"}, status=400)

    username = request.POST.get('username')
    password = request.POST.get('password')

    user = authenticate(request, username=username, password=password)
    if user:
        login(request, user)
        return JsonResponse({"message": "Login successful"})
    else:
        return JsonResponse({"error": "Invalid credentials"}, status=401)
