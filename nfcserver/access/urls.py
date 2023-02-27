from django.urls import path

from . import views

urlpatterns = [
    path('', views.receive_message, name='access'),
    path('records', views.generate_report, name='records')
]
