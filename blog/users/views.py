from django.contrib.auth import login
from django.shortcuts import render

# Create your views here.
from django.views import View

from django.shortcuts import redirect
from django.urls import reverse

import re
from users.models import User
from django.db import DatabaseError

class RegisterView(View):
    """用户注册"""
    def get(self, request):
        """
        提供注册界面
        :param request: 请求对象
        :return: 注册界面
        """
        return render(request, 'register.html')

    def post(self,request):
        # 1、接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode=request.POST.get('sms_code')

        # 2、验证数据
        # 2.1、判断参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必传参数')

        # 2.2、判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号码')

        # 2.3、判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位的密码')

        # 2.4、判断两次密码是否一致
        if password != password2:
            return HttpResponseBadRequest('两次输入的密码不一致')

        # 2.5、验证短信验证码
        redis_conn = get_redis_connection('default')
        sms_code_server = redis_conn.get('sms:%s' % mobile)

        if sms_code_server is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if smscode != sms_code_server.decode():
            return HttpResponseBadRequest('短信验证码错误')

        # 3、保存注册数据
        try:
            # create_user可以使用系统的方法对密码进行加密
            user=User.objects.create_user(username=mobile,mobile=mobile, password=password)
        except DatabaseError as e:
            logger.error(e)
            return HttpResponseBadRequest('注册失败')

        # 4、响应注册结果
        # 先返回一个注册成功，后期再跳转到具体的页面上
        # return HttpResponse('注册成功，重定向到首页')
        #
        # 响应注册结果
        # 实现状态保持
        login(request, user)
        # return redirect(reverse('home:index'))

        # 跳转到首页
        response = redirect(reverse('home:index'))
        # 设置cookie
        # 登录状态，会话结束后自动过期
        response.set_cookie('is_login', True)
        # 设置用户名有效期一个月
        response.set_cookie('username', user.username, max_age=30 * 24 * 3600)

        return response


from django.http import HttpResponseBadRequest, HttpResponse
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection

class ImageCodeView(View):
    def get(self,request):
        #1. 获取前端传递过来的uuid参数
        uuid=request.GET.get('uuid')

        #2. 判断uuid参数是否为None
        if uuid is None:
            return HttpResponseBadRequest('请求参数错误')

        # 3. 通过catcha来生成图片验证码（图片和图片内容）
        # 获取验证码内容和验证码图片二进制数据
        text, image = captcha.generate_captcha()

        # 4. 将图片验内容保存到redis中
        # 设置过期时间
        # uuid作为key，图片内容为一个value
        redis_conn = get_redis_connection('default')

        # key设置为uuid
        # seconds，过期秒数，300秒，5分钟后过期
        # value，text
        redis_conn.setex('img:%s' % uuid, 300, text)

        # 5. 返回响应，将生成的图片以content_type为image/jpeg的形式返回给请求
        return HttpResponse(image, content_type='image/jpeg')




from django.http import JsonResponse
from utils.response_code import RETCODE
from random import randint
from libs.yuntongxun.sms import CCP
import logging
logger=logging.getLogger('django')

class SmsCodeView(View):

    def get(self, request):
        pass
        # 1、接收参数
        image_code_client = request.GET.get('image_code')
        uuid = request.GET.get('uuid')
        mobile = request.GET.get('mobile')

        logging.info(image_code_client,uuid,mobile)

        # 2、校验参数
        # 2.1验证参数是否齐全
        if not all([image_code_client, uuid,mobile]):
            return JsonResponse({'code': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少必传参数'})

        # 2.2图片验证码的验证
        # 创建连接到redis的对象，连接redis，获取redis中的图片验证码
        redis_conn = get_redis_connection('default')
        # 提取图形验证码
        image_code_server = redis_conn.get('img:%s' % uuid)

        # 判断图片验证码是否存在
        if image_code_server is None:
            # 图形验证码过期或者不存在
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图形验证码失效'})

        # 如果图片验证码未过期，我们获取到之后，就可以删除图片验证码了
        # 删除图形验证码，避免恶意测试图形验证码
        try:
            redis_conn.delete('img:%s' % uuid)
        except Exception as e:
            logger.error(e)

        # 对比图形验证码，注意大小写的问题，redis的数据是bytes类型
        image_code_server = image_code_server.decode()  # bytes转字符串
        if image_code_client.lower() != image_code_server.lower():  # 转小写后比较
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '输入图形验证码有误'})

        # 3、生成短信验证码：生成6位数验证码
        sms_code = '%06d' % randint(0, 999999)
        #将验证码输出在控制台，以方便调试
        logger.info("短信验证码是： " + sms_code)

        # 4、保存短信验证码到redis中，并设置有效期
        redis_conn.setex('sms:%s' % mobile, 300, sms_code)

        # 5、发送短信验证码
        CCP().send_template_sms(mobile, [sms_code, 5],1)

        # 6、响应结果
        # 没有注册短信发送的这个，直接返回true
        return JsonResponse({'code': RETCODE.OK, 'errmsg': '发送短信成功'})

#-----------------------------------------------------

from django.views import View
from django.contrib.auth import login
from django.contrib.auth import authenticate

class LoginView(View):
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        """
        1、接收参数
        2、参数验证
            2.1 验证手机号是否符合规则
            2.2 验证密码是否符合规则
        3.用户认证登录
        4.状态保持
        5.根据用户选择，是否记住登录状态来进行判断
        6、为了首页显示我们需要设置一些cookie信息
        7、返回响应
        :param request:
        :return:
        """
        # 1、接受参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')

        # 2、校验参数
        # 判断参数是否齐全
        if not all([mobile, password]):
            return HttpResponseBadRequest('缺少必传参数')

        # 判断手机号是否正确
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号')

        # 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码最少8位，最长20位')

        # 3、认证登录用户
        # 采用系统自带的认证方法进行认证
        # 如果我们的用户名和密码正确，会返回user
        # 如果我们的用户名或密码不正确，会返回None
        #
        # 默认的认证方法是针对于username字段进行用户名的判断
        # 当前的判断信息是手机号，所以我们需要修改认证字段
        # 需要到User模型中进行修改，等测试出现问题的时候，再修改
        # 认证字段已经在User模型中的USERNAME_FIELD = 'mobile'修改
        user=authenticate(mobile=mobile, password=password)
        if user is None:
            return HttpResponseBadRequest('用户名或密码错误')

        # 4、实现状态保持
        login(request, user)

        # 响应登录结果
        next = request.GET.get('next')
        if next:
            response = redirect(next)
        else:
            response = redirect(reverse('home:index'))

        # response = redirect(reverse('home:index'))

        # 5、根据用户选择的是否记住登录状态进行判断
        # 6、为了首页显示，我们需要设置一些cookie信息
        # 设置状态保持的周期
        if remember != 'on':
            # 没有记住用户：浏览器会话结束就过期
            request.session.set_expiry(0)
            # 设置cookie
            response.set_cookie('is_login', True)
            response.set_cookie('username', user.username, max_age=30 * 24 * 3600)
        else:
            # 记住用户：None表示两周后过期
            request.session.set_expiry(None)
            # 设置cookie
            response.set_cookie('is_login', True, max_age=14*24 * 3600)
            response.set_cookie('username', user.username, max_age=30 * 24 * 3600)

        #7、返回响应
        return response


from django.contrib.auth import logout


class LogoutView(View):
    def get(self,request):
        # 1、清理session
        logout(request)
        # 2、退出登录，重定向到登录页
        response = redirect(reverse('home:index'))
        # 3、退出登录时清除cookie中的登录状态
        response.delete_cookie('is_login')
        return response





# ------------------------忘记密码


from django.views import View

class ForgetPasswordView(View):
    def get(self, request):
        return render(request, 'forget_password.html')


    def post(self, request):

        """
        1、接收数据
        2、验证数据
            2.1 参数是否齐全
            2.2 手机号是否符合规则
            2.3 密码是否符合规则
            2.4 确认密码和密码是否一致
            2.5 短信验证码是否正确

        3、根据手机号进行用户信息的查询
        4、如果手机号查询出用户信息，则进行用户信息的修改
        5、如果手机号没有查询出用户信息，则进行新用户的创建
        6、进行页面跳转，跳转到登录页面
        :param request:
        :return:
        """

        # 1、接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')

        # 2
        # 2.1 判断参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必传参数')

        # 2.2 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号码')

        # 2.3 判断密码是否是8-20个数字
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位的密码')

        # 2.4 判断两次密码是否一致
        if password != password2:
            return HttpResponseBadRequest('两次输入的密码不一致')

        # 2.5 验证短信验证码
        redis_conn = get_redis_connection('default')
        sms_code_server = redis_conn.get('sms:%s' % mobile)
        if sms_code_server is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if smscode != sms_code_server.decode():
            return HttpResponseBadRequest('短信验证码错误')

        # 3 根据手机号查询数据
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 5 如果该手机号不存在，则注册个新用户
            try:
                User.objects.create_user(username=mobile, mobile=mobile, password=password)
            except Exception:
                return HttpResponseBadRequest('修改失败，请稍后再试')
        else:
            # 4 如果手机号查询出用户信息，则进行用户信息的修改
            user.set_password(password)
            user.save()

        # 6 跳转到登录页面
        response = redirect(reverse('users:login'))

        return response


# -------------------------用户中心
#
# 如果用户未登陆，会进行默认的跳转
# 默认的跳转链接是：http://127.0.0.1:8000/accounts/login/?next=/center/
# account/login/?nex={跳转路由}
#
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin

class UserCenterView(LoginRequiredMixin,View):
    def get(self,request):
        # 获取用户信息
        user = request.user

        #组织模板渲染数据
        context = {
            'username': user.username,
            'mobile': user.mobile,
            'avatar': user.avatar.url if user.avatar else None,
            'user_desc': user.user_desc
        }
        return render(request,'center.html',context=context)

    def post(self,request):
        """
        1、接收参数
        2、将参数保存起来
        3、更新cookie中的username信息
        4、刷新当前页面（重定向操作）
        5、返回响应
        :param request:
        :return:
        """
        # 接收数据
        user = request.user
        avatar = request.FILES.get('avatar')
        username = request.POST.get('username',user.username)
        user_desc = request.POST.get('desc',user.user_desc)

        # 修改数据库数据
        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                # 在模型中定义的 avatar ，字段为ImageField，会自动的将图片信息，保存，并保存图片的路径
                #     # upload_to为保存到响应的子目录中
                #     avatar = models.ImageField(upload_to='avatar/%Y%m%d/', blank=True)
                #
                # 需要设置保存的路径，如果不设置，默认会保存到工程目录中，不利于维护
                user.avatar = avatar

            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('更新失败，请稍后再试')

        # 返回响应，刷新页面
        response = redirect(reverse('users:center'))

        #更新cookie信息
        response.set_cookie('username', user.username, max_age=30*24*3600)
        return response

# ---------------------- 写博客页面
# 登录的用户，才能写博客，所以继承了 LoginRequiredMixin
from django.views import View
# 查询模型分类信息
from home.models import ArticleCategory,Article
class WriteBlogView(LoginRequiredMixin,View):
    def get(self, request):
        # 查询所有分类模型
        # 获取博客分类信息
        categories = ArticleCategory.objects.all()

        context = {
            'categories': categories
        }
        return render(request, 'write_blog.html', context)
    def post(self,request):
        #接收数据
        avatar=request.FILES.get('avatar')
        title=request.POST.get('title')
        category_id=request.POST.get('category')
        tags=request.POST.get('tags')
        sumary=request.POST.get('sumary')
        content=request.POST.get('content')
        user=request.user

        #验证数据是否齐全
        if not all([avatar,title,category_id,sumary,content]):
            return HttpResponseBadRequest('参数不全')

        #判断文章分类id数据是否正确
        try:
            article_category=ArticleCategory.objects.get(id=category_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseBadRequest('没有此分类信息')

        #保存到数据库
        try:
            article=Article.objects.create(
                author=user,
                avatar=avatar,
                category=article_category,
                tags=tags,
                title=title,
                sumary=sumary,
                content=content
            )
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('发布失败，请稍后再试')

        #返回响应，跳转到文章详情页面
        #暂时先跳转到首页
        return redirect(reverse('home:index'))