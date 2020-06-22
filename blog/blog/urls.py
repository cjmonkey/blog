from django.contrib import admin
from django.urls import path

# 1、导入系统的logging
import logging

# 2、创建日志记录器
# 这个名字，是在setting中设置的日志器
logger = logging.getLogger('django')

from django.http import HttpResponse
def log(request):
    # 3、使用日志器记录信息
    # 输出日志
    #
    logger.debug('测试logging模块debug')
    logger.info('测试logging模块info')
    logger.error('测试logging模块error')
    return HttpResponse('test')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', log),
]