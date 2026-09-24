from django.urls import path, include
from django.contrib.auth import views as auth_views
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'tests', views.TestViewSet, basename='test')

app_name = 'frontend'

urlpatterns = [
    path('', views.home_view, name='home'),
    path('api/submit-test/', views.SubmitTest.as_view(), name='submit-test'),
    path('api/', include(router.urls)),
]