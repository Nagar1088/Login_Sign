from django.urls import path
from .views import*

urlpatterns = [
    path('', Authentication.login, name='login'),
    path('signup/', Authentication.signup, name='signup'),
    path('forget/', Authentication.forgot_password, name='forget'),
    path('logout/', Authentication.logout_user, name='logout_user'),
    path('change-password/', Authentication.change_password, name='change_password'),
    path('Dashboar/', Authentication.Dashboard, name='Dashboard'),
]