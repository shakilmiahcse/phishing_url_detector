
from django.contrib import admin
from django.urls import path
from phishing_detector import views

urlpatterns = [
    path('admin/', admin.site.urls),

    path('', views.index), 
    path('index', views.index),
    path('about', views.about),
    path('blog-details', views.blogDetails),
    path('blog-grid', views.blogGrid),
    path('blog-list-with-sidebar', views.blogListWithSidebar),
    path('business-with-ecommerce', views.businessWithEcommerce),
    path('consulting', views.consulting),
    path('contact', views.contact),
    path('corporate', views.corporate),
    path('finance', views.finance),
    path('insurance', views.insurance),
    path('portfolio', views.portfolio),
    path('pricing', views.pricing),
    path('project-details', views.projectDetails),
    path('service', views.service),
    path('services-details', views.servicesDetails),
    path('shop-cart', views.shopCart),
    path('shop-checkout', views.shopCheckout),
    path('shop-order-recived', views.shopOrderRecived),
    path('shop-product-details', views.shopProductDetails),
    path('shop', views.shop),
    path('team-details', views.teamDetails),
    path('team', views.team),
    path('feature', views.feature),
]
