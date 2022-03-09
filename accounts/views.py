from email.message import EmailMessage
from django.shortcuts import redirect, render
from accounts.forms import RegistrationForm
from .models import Account
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.core.mail import EmailMessage
from carts.views import _cart_id
from carts.models import Cart, CartItem
import requests




# Create your views here.

def register(request):
    form = RegistrationForm()
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
           
            # extrae caracteres antes del email para convertirlo en nombre de usuario.
            username= email.split("@")[0]
            user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
            user.phone_number = phone_number
            user.save()
            
            #envio de email
            current_site= get_current_site(request)
            mail_subject = 'por favor activa tu cuenta en Fenomeno Clik'
            body = render_to_string('accounts/account_verificaction_email.html', {
                'user' : user,
                'domain' : current_site,
                'uid' : urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, body, to=[to_email])
            send_email.send()
            
            
            #messages.success(request, 'Se registró el usuario exitosamente')
            return redirect('/accounts/login?command=verification&email='+email)
            
    
    context = {
        'form':form
    }
    return render(request, 'accounts/register.html', context)


def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        
        
        user = auth.authenticate(email=email, password=password)
        
        if user is not None:
            
            try:
                cart = Cart.objects.get(cart_id=_cart_id(request))
                is_cart_item_exists = CartItem.objects.filter(cart=cart).exists()
                if is_cart_item_exists:
                    cart_item = CartItem.objects.filter(cart=cart)
                    
                    product_variation = []
                    for item in cart_item:
                        variation = item.variations.all()
                        product_variation.append(list(variation))
                    cart_item = CartItem.objects.filters(user=user)
                    ex_var_list = []
                    id = []
                    for item in cart_item:
                        existing_variation = item.variations.all()
                        ex_var_list.append(list(existing_variation))
                        id.append(item.id)
                        
                    for pr in product_variation:
                        if pr in ex_var_list:
                            index = ex_var_list.index(pr)
                            item_id = id[index]
                            item = CartItem.objects.get(id=item_id)
                            item.quantity += 1
                            item.user = user
                            item.save()
                        else:
                            cart_item = CartItem.objects.filter(cart=cart)
                            for item in cart_item:
                                item.user = user
                                item.save() 
                    
 
            except:
                pass
            
            #http://localhost:8000/accounts/login/?next=/cart/checkout
            auth.login(request, user)
            messages.success(request, 'Has iniciado sesion exitosamente')
            
            url = request.META.get('HTTP_REFERER')
            try:
                query = requests.utils.urlparse(url).query
                #next=/cart/checkout
                params = dict(x.split('=') for x in query.split('&'))
                if 'next' in params:
                    nextPage = params['next']
                    return redirect(nextPage)
            except:
                return redirect('dashboard')
            
        else:
            messages.error(request, 'Las credenciales son incorrectas')
            return redirect('login')
    
    return render(request, 'accounts/login.html')

@login_required(login_url = 'login')
def logout(request):
    
    auth.logout(request)
    messages.success(request, 'Has Salido de sesion')
    
    
    return redirect('login')



def activate(request, uidb64, token):
    try:
        uid =urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Felicidades, tu cuenta está activa')
        return redirect('login')
    else:
        messages.error(request, 'La activacion a sido inválida')
        return redirect('register')
    
@login_required(login_url = 'login')    
def dashboard(request):
    return render(request, 'accounts/dashboard.html')
        
        
def forgotpassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)

            current_site = get_current_site(request)
            mail_subject = 'Resetear Password'
            body = render_to_string('accounts/reset_password_email.html',{
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, body , to=[to_email])
            send_email.send()

            messages.success(request, 'Un email fue enviado a tu bandeja de entrada para resetear tu password')
            return redirect('login')
        else:
            messages.error(request, 'La cuenta de usuario no existe')
            return redirect('forgotpassword')

    return render(request, 'accounts/forgotpassword.html')


def resetpassword_validate(request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = Account._default_manager.get(pk=uid)
        except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
            user=None

        if user is not None and default_token_generator.check_token(user, token):
            request.session['uid'] = uid
            messages.success(request, 'Por favor resetea tu password')
            return redirect('resetpassword')
        else:
            messages.error(request, 'El link ha expirado')
            return redirect('login')
    
def resetpassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'El password se reseteo correctamente')
            return redirect('login')
        else:
            messages.error(request, 'El password de confirmacion no concuerda')
            return redirect('resetpassword')
    else:
        return render(request, 'accounts/resetpassword.html')