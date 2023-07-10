# Create your views here.

from django.contrib import messages
from django.shortcuts import render,redirect
from .models import *
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
import uuid
from django.contrib.auth.models import User
from django.conf import settings
from django.core.mail import send_mail



def Login(request):
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')

            user_obj = User.objects.filter(username=username).first()
            if user_obj is None:
                messages.error(request, 'user not found')
                return redirect('/login')
            
            profile_obj = Profile.objects.filter(user = user_obj).first()

            if not profile_obj.is_verified:
                messages.error(request, 'Profile is not verified, Please check your mail.')
            
            user = authenticate(username=username, password=password)

            if user is None:
                messages.error(request, "Invalid username or password.")
                return redirect('/login/')
        
            login(request, user)
            return redirect("/")
        

        return render(request, 'login.html')



def Register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username is taken.")
            return redirect('/register/')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is taken.")
            return redirect('/register/')
        
        user_obj = User.objects.create_user(username=username, email=email)
        user_obj.set_password(password)
        user_obj.save()

        auth_token = str(uuid.uuid4())

        profile_obj = Profile.objects.create(user=user_obj, auth_token=auth_token)
        profile_obj.save()
        
        send_mail_after_verification(email, auth_token)
        messages.success(request, 'We sent a verification email to the registered email id')
        
        return redirect('/login/')

    return render(request, 'register.html')


def verify(request, auth_token):
    try:
        profile_obj = Profile.objects.filter(auth_token = auth_token).first()

        if profile_obj.is_verified:
            messages.success(request, 'your account is already verified')
            return redirect('/login/')
        
        
        if profile_obj:
            profile_obj.is_verified = True
            profile_obj.save()
            messages.success(request, 'Your account has been verified')
            return redirect('/login/')
        
    except Exception as e:
        print(e)


def Logout(request):
    logout(request)
    return redirect('/')


@login_required(login_url='login/')
def Home(request):
    return render(request, 'home.html')

def ChangePassword(request, token):
    context = {}
    try:
        profile_obj = Profile.objects.filter(forget_password_token = token).first()
        context = {"user_id" : profile_obj.user.id}

        if request.method == "POST":
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('reconfirm_password')
            user_id = request.POST.get('user_id')

            if user_id is None:
                messages.success(request, 'No user id found')
                return redirect(f'/change-password{token}/')
            
            if new_password != confirm_password:
                messages.success(request, 'both should be equal')
                return redirect(f'/change-password{token}/')
            
            user_obj = User.objects.get(id = user_id)
            user_obj.set_password(new_password)
            user_obj.save()
            return redirect('/login/')
        

    except Exception as e:
        print(e)
    
    return render(request, 'change-password.html', context)

def ForgetPassword(request):
    try:
        if request.method == "POST":
            username = request.POST.get("username")

            if not User.objects.get(username=username):
                messages.success(request, "Not user found with this username")
                return redirect("/register/")
            
            user_obj = User.objects.get(username=username)
            token =str(uuid.uuid4())
            profile_obj = Profile.objects.get(user = user_obj)
            profile_obj.forget_password_token = token
            profile_obj.save()
            send_forget_password_mail(user_obj, token)
            messages.success(request, 'An email is sent')
            return redirect('/forget-password/')




    except Exception as e:
        print(e)
    return render(request, 'forget-password.html')

def send_forget_password_mail(user, token):
    subject = 'Your forget password link'
    message = f'Hi, click on the link to reset your password: http://127.0.0.1:8000/change-password/{token}/'
    email_from = settings.EMAIL_HOST_USER
    recipeint_list = [user.email]
    send_mail(subject, message, email_from, recipeint_list)
    return True     


def send_mail_after_verification(email, token):
    subject = 'Your account needs to be verified'
    message = f'Hi, please click the following link to verify your account: http://127.0.0.1:8000/verify/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)


