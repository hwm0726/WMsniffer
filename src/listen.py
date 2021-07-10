import sys
import pcapy
from PyQt5.QtCore import pyqtSignal,QThread
from resolve import Resolve

class Listen(QThread):
    __getDataSignal = pyqtSignal()#发送获取解析数据的信号量
    __showErrorSignal = pyqtSignal()#发送过滤规则有误的信号量
    def __init__(self, device, filter, fun_getData, fun_showError, parent=None):#监听类的构造函数
        super().__init__(parent)
        self.__device = device
        self.__filter = filter
        self.__runTag = True
        self.__resList = []
        self.__getDataSignal.connect(fun_getData)#将信号与主线程的取解析数据函数连接
        self.__showErrorSignal.connect(fun_showError)#将信号与主线程的提示错误函数连接

    def run(self):#执行监听
        capture = pcapy.open_live(self.__device, 65536, 1, 0)#将网卡设置为混杂模式
        if len(self.__filter) != 0:#有过滤条件
            try:#设置过滤规则，并检测输入的过滤规则是否有误
                capture.setfilter(self.__filter)
            except:
                self.__showErrorSignal.emit()#向主线程发送过滤规则有误信号
                return
        while self.__runTag:#循环直至runTag为0
            (head,data) = capture.next()#捕获数据包
            if head != None:
                resolveObj = Resolve()
                res = resolveObj.resolve(head,data)#交由解析对象解析数据包
                if res != None:
                    res["originalHex"] = data.hex()
                    self.__resList.append(res)
                    self.__getDataSignal.emit()#通知主界面此时可以获取数据

    def stopListen(self):#停止监听
        self.__runTag = False

    def getData(self):#给主线程获取数据包提供接口
        if len(self.__resList) == 0:
            return None
        return self.__resList.pop(0)
