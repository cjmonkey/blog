from django.contrib import admin
from django.urls import path, include



# # 1、导入系统的logging
# import logging
#
# # 2、创建日志记录器
# # 这个名字，是在setting中设置的日志器
# logger = logging.getLogger('django')
#
# from django.http import HttpResponse
# def log(request):
#     # 3、使用日志器记录信息
#     # 输出日志
#     #
#     logger.debug('测试logging模块debug')
#     logger.info('测试logging模块info')
#     logger.error('测试logging模块error')
#     return HttpResponse('test')

urlpatterns = [
    path('admin/', admin.site.urls),
    # include
    # 首先要设置为元组（urlconf_module, app_name）
    # urlconf_module，设置子应用的路由
    # app_name，子应用的名字
    #
    # namespace 设置命名空间，能够很好的防止不同子应用之间因为路由的名字，而导致的冲突
    # namespace，名字和子应用一样，就能很好的区分了
    path('', include(('users.urls', 'users'), namespace='users')),

    # path('', log),

    path('', include(('home.urls','home'),namespace='home')),
]

# 图片访问路由
#以下代码为设置图片访问路由规则
from django.conf import settings
from django.conf.urls.static import static
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)