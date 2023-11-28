from django.conf import settings
from django.shortcuts import render, redirect
from .models import *
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib import messages
from django.http import JsonResponse
import json
import datetime  
from .my_captcha import FormWithCaptcha 

import stripe
from coinbase_commerce.client import Client
from coinbase_commerce.error import SignatureVerificationError, WebhookInvalidPayload
from coinbase_commerce.webhook import Webhook

from django.urls import reverse

from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
#admin charts
import json
import datetime 
from django.db.models import Q
from django.core.serializers import serialize
from django.http import JsonResponse
from django.db.models.query import QuerySet
from django.db.models import Model
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class DjangoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (Model, QuerySet)):
            return serialize('json', [obj])
        elif isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        return super(DjangoJSONEncoder, self).default(obj)
    
from datetime import datetime
from django.views.generic import View
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .tokens import generate_token
from django.core.mail import EmailMessage, send_mail





def index(request):

    prod = product.objects.all()
    flashcards = Flash_Sales.objects.all()

    context = {'products':prod, 'Flash_cards': flashcards, 'company_name': "SHC" , 'current_year':2023}
    return render(request, 'website/mainPage.html', context)

def home(request):
    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        items = order.orderitem_set.all()
        cartItems = order.get_cart_items
    else:
        items = []
        order = {'get_cart_items':0, 'get_cart_total':0}
        cartItems = order['get_cart_total']


    prod = product.objects.all() 
    flashcards = Flash_Sales.objects.all()

    context = {'products':prod, 'Flash_cards': flashcards, 'company_name': "SHC" , 'current_year':2023, 'CartItems':cartItems}
    return render(request, 'store/dashboard.html', context)

def search(request):
    search = request.GET.get('search')
    payload = []
    if search:
        objs = product.objects.filter(name__startswith = search)

        for obj in objs:
            payload.append({
                'name': obj.name
            })

    return JsonResponse({
        'status':True,
        'payload': payload
    })
  
def market_place(request):
    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        items = order.orderitem_set.all()
        cartItems = order.get_cart_items
    else:
        items = []
        order = {'get_cart_items':0, 'get_cart_total':0}
        cartItems = order['get_cart_total']

    prod = product.objects.all()
    flashcards = Flash_Sales.objects.all()

    context = {'products':prod, 'Flash_cards': flashcards, 'company_name': "SHC" , 'current_year':2023, 'CartItems':cartItems}
    # context = {}
    return render(request, 'store/market_place.html', context)

def cart(request):
    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        items = order.orderitem_set.all()
        cartItems = order.get_cart_items
    else:
        items = []
        order = {'get_cart_items':0, 'get_cart_total':0}
        cartItems = order['get_cart_total']

    context = {'items': items, 'order': order,'company_name': "SHC" , 'CartItems':cartItems}
    return render(request, 'store/cart.html', context)

def checkout(request):
    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        items = order.orderitem_set.all()
        cartItems = order.get_cart_items
    else:
        items = []
        order = {'get_cart_items':0, 'get_cart_total':0}
        cartItems = order['get_cart_total']

    context = {'items': items,'company_name': "SHC" , 'order': order, 'CartItems':cartItems}
    return render(request, 'store/checkout.html', context)

def processOrder(request):
    data = json.loads(request.body)
    transaction_id= datetime.datetime.now().timestamp()
    print(transaction_id)
    form_data = data['form']
    print(form_data)
    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        total = float(data['form']['total'])
        order.transaction_id = transaction_id
        order.order_amount = total

        if total == order.get_cart_total:
            order.complete = True
            ac = Customer.objects.get(name=customer)
            ac.balance = (ac.balance-total)
            print(ac.balance)
            ac.save()
        order.save()
        
    return JsonResponse('payment Submitted..', safe=False)

def myactivity(request):
     #transactions = Transactions.objects.all()
    

    if request.user.is_authenticated:
        customer = request.user.customer
        # transact = transactions.get(customer=customer)
        transactions = Order.objects.filter(customer=customer, complete = True)
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        cartItems = order.get_cart_items
    else:
        cartItems = 0
    context = {'transactions':transactions,'company_name': "SHC" , 'CartItems':cartItems}
    return render(request, 'store/myactivity.html', context)

def account(request):
    if not request.user.is_authenticated:
        return redirect('signin')

    if request.user.is_authenticated:
        customer = request.user.customer
        order, created = Order.objects.get_or_create(customer=customer, complete = False)
        cartItems = order.get_cart_items
    else:
        customer=''
        cartItems = 0
    
    context = {'customer': customer,'company_name': "SHC" , 'CartItems':cartItems}
    return render(request, 'store/myaccount.html', context)

def updateItems(request):
    data = json.loads(request.body)
    productId = data['productId']
    action = data['action']

    print('action: ', action)
    print('productId: ', productId)

    customer = request.user.customer
    prod = product.objects.get(id = productId)
    order, created = Order.objects.get_or_create(customer=customer, complete = False)
    orderItem, created = OrderItem.objects.get_or_create(order=order, product=prod)

    if action == 'add':
        orderItem.quantity = (orderItem.quantity + 1)
    elif action == 'remove':
        orderItem.quantity = (orderItem.quantity - 1)
    orderItem.save()

    if orderItem.quantity <=0:
        orderItem.delete()

    # print(prod.name)
    # print(prod.price)
    # print(prod.offer)

    return JsonResponse('Item was added', safe=False)


def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if User.objects.filter(username = username):
            messages.error(request, "Username already exists. Try another one")
            return redirect("signup")
        if User.objects.filter(email = email):
            messages.error(request, "email already exists")
            return redirect("signup")
        if len(username)>10:
            messages.error(request, "Username should not exceed 10 characters")
            return redirect("signup")
        
        if pass1 != pass2:
            messages.error(request, "Passwords didn't match")
            return redirect("signup")
        

        myuser = User.objects.create_user(username, email, pass1)
        myuser.is_active = False
        myuser.save()
        messages.success(request, "Your account has been successfully created. Confirm your email to activate account.")
        customer = Customer(
                            user = myuser,
                            name=myuser,
                            email= email,
                            balance = 0
        )
        customer.save()
            
        sender = settings.EMAIL_HOST_USER
        recipient = email
        current_site = get_current_site(request)
        # name = username
        # domain = current_site.domain
        # uid = urlsafe_base64_encode(force_bytes(myuser.pk))
        # token = generate_token.make_token(myuser)

        subject = "Welcome to Secret Hackers CLub Ecommerce"
        msgtext = f"""
            Hello {username}, 
            Welcome to Darksales Secret Hackers Club Ecommerce platform

            Regards,
            Darksales SHC Team

        """
        msg2 = render_to_string('store/email_confirmation.html', {
            'name': username,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser),
        })
        # email = EmailMessage(
        #     subject,
        #     msg2,
        #     sender,
        #     [email],

        # )
        # # email.attach_alternative(msg2, "text/html")
        # email.send(fail_silently = True)

        # msg = MIMEText(msgtext)
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient

        text_part = MIMEText('Plain text version of the message', 'plain')
        html_part = MIMEText(msg2, 'html')

        msg.attach(text_part)
        msg.attach(html_part)

        server = smtplib.SMTP_SSL(settings.EMAIL_HOST, 465)

        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        server.sendmail(sender, [recipient], msg.as_string())
        
        # server.sendmail(sender, [recipient], email)
        # server.send_message(email)
        server.quit()


        user = authenticate(request, email=email, password = pass2)
        # login(request, user)
        if customer.balance == 0:
            return redirect('first_time_payment')
        return redirect("signin")

    context = {'captcha':FormWithCaptcha,}
    return render(request, 'store/signup.html', context)

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None
    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        return redirect('first_time_payment')
    else:
        return render(request, 'store/activation_failed.html')

def deposit(request): 
    if not request.user.is_authenticated:
        return redirect('signin')
    if request.method == 'POST':
        amount = request.POST['amount']
        print(amount)
    client = Client(api_key=settings.COINBASE_COMMERCE_API_KEY)
    domain_url = 'http://localhost:8000/'
    product = {
            'metadata': {
            'customer_id': request.user.id if request.user.is_authenticated else None,
            'customer_username': request.user.username if request.user.is_authenticated else None,
            },
            'name': 'Deposit',
            
            'local_price': {
                            'amount': '50.00',
                            'currency': 'USD'
                            },
            'pricing_type': 'fixed_price',
            'redirect_url': domain_url + 'dashboard/',
            'cancel_url': domain_url + 'deposit/',
    }
    charge = client.charge.create(**product)

    stripe.api_key = settings.STRIPE_SECRET_KEY

    session = stripe.checkout.Session.create( 
        payment_method_types = ['card'],
        line_items = [{
            'price': 'price_1OASYGA3uxThpfeVyZ9Iq440',
            'quantity': 1,
        }],
        mode = 'payment',
        success_url = request.build_absolute_uri(reverse('home')) + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url = request.build_absolute_uri(reverse('first_time_payment')),
    )


    context = {
        'charge':charge, 
        'session_id': session.id,
        'stripe_public_key': settings.STRIPE_PUBLIC_KEY
    }
    logout(request)
    return render(request, 'store/deposit.html', context)


def index_deposit(request):
    stripe.api_key = settings.STRIPE_SECRET_KEY

    session = stripe.checkout.Session.create( 
        payment_method_types = ['card'],
        line_items = [{
            'price': 'price_1OASYGA3uxThpfeVyZ9Iq440',
            'quantity': 1,
        }],
        mode = 'payment',
        success_url = request.build_absolute_uri(reverse('home')) + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url = request.build_absolute_uri(reverse('first_time_payment')),
    )

    context = {
        'session_id': session.id,
       
        'stripe_public_key': settings.STRIPE_PUBLIC_KEY
    }
    return render(request, 'store/deposit_test.html', context)

def process_payment(request):
    return redirect('myaccount')
def signin(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            username = request.POST['username']
            pass1 = request.POST['pass']

            if "@" in username:
                user = authenticate(request, email=username, password = pass1)
                print(user)
                print(type(username))
            else:
                user = authenticate(username=username, password = pass1)
            if user is not None:
                login(request, user)
                fname = user.first_name
                u_name = user.get_username()
                email = user.email
                pass1 = user.password
                return redirect("home")
            else:
                messages.error(request, "Invalid Login Credentials")
                return redirect("signin")
        context = {'captcha':FormWithCaptcha,}
        return render(request, 'store/signin.html', context)
    else:
        return redirect("home")

def signout(request):
    logout(request)
    messages.success(request, "Logged out successfully")
    return redirect("index")

def reset_password(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']
        myuser = User.objects.get(username = username)
        # user = User.objects.get(username='username')
        if pass1 != pass2:
            messages.error(request, "Passwords didn't match")
            return redirect("reset_password")
        
        if myuser or User.objects.get(username = email):
            # myuser.password = pass1
            myuser.set_password(pass1)
            print(myuser.password)
            myuser.save()
            return redirect("signin")
        else:
            messages.error(request, "Invalid Username or Email")
            return redirect("reset_password")
        # Update the session authentication hash to keep the user logged in
        update_session_auth_hash(request, myuser)
    return render(request, 'store/reset_password.html')




#Admin charts

def chart_template_view(request):
    
    #line chart
    line_data = line_chart.objects.all()
    labels = [item.label for item in line_data]
    values = [item.value for item in line_data]
    
    
    line_data = {
        'labels': labels,
        'values': values,
         
    }

    Line_data = json.dumps(line_data, cls=DjangoJSONEncoder)

  #pie chart
    pie_data = pie_chart.objects.all()
    labels = [item.brand for item in pie_data]
    values = [item.value for item in pie_data]
    
    
    pie_data = {
        'labels': labels,
        'values': values,
         
    }

    Pie_data = json.dumps(pie_data, cls=DjangoJSONEncoder)
      #sales_chart
    sales_data = sales_chart.objects.all()
    labels = [item.month for item in sales_data]
    values = [item.value for item in sales_data]
    
    
    data_sales = {
        'labels': labels,
        'values': values,
         
    }

    Sales_data = json.dumps(data_sales, cls=DjangoJSONEncoder)
    


    users=User.objects.count()
    #rendering context
    context = {
      
        'Sales_data': Sales_data,
        'Pie_data':Pie_data,
        'users':users,
        'Line_data': Line_data,
       
    }
    

    return render(request, 'store/custom_template.html',context)
