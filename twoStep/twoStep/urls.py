"""twoStep URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from Auth import views as authViews
from django.contrib import admin
from django.urls import include, path
from django.urls import path
from django.conf.urls import url, include as inc
from Auth.views import ( refresh_jwt_token )
from rest_framework import routers, serializers, viewsets
# , 
# obtain_jwt_token 
# )
# from rest_framework_jwt.views import (
    # obtain_jwt_token,
    # refresh_jwt_token
# )
router = routers.DefaultRouter()
router.register(r'auth', authViews.AuthView)
urlpatterns = [
    path('api/', include(router.urls)),
    # url(r'^api/login/', obtain_jwt_token),
    # url(r'^api/otp/(P<pk>\D+)/', authViews.AuthView.as_view({'get': 'getTwoToken'})),
    url(r'^api/login/', authViews.AuthView.as_view({'post': 'login'})),
    path('admin/', admin.site.urls),
    url(r'^api/register/', authViews.RegisterView.as_view({'post': 'create'} )),
]
