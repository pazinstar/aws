from django.urls import path
from . import views
  
urlpatterns = [
    path('', views.index, name ='index'), 
    path('dashboard/', views.home, name ='home'),
    path('market_place/', views.market_place, name ='market_place'),
    path('myactivity/', views.myactivity, name ='myactivity'),
    path('myaccount/', views.account, name ='myaccount'),
    path('signup/', views.signup, name ='signup'),
    path('signin/', views.signin, name ='signin'),
    path('signout/', views.signout, name ='signout'), 
    path('reset_password/', views.reset_password, name ='reset_password'),
    path('update_item/', views.updateItems, name ='update_item'),
    path('cart/', views.cart, name ='cart'),
    path('checkout/', views.checkout, name ='checkout'),
    path('process_order/', views.processOrder, name ='process_order'),
    path('deposit/', views.deposit, name ='first_time_payment'),

    path('deposit_test/', views.index_deposit, name ='deposit_test'),

    path('process_payment/', views.process_payment, name ='process_payment'),
    path('get_items/', views.search, name ='search'),
]  