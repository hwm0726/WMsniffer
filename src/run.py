import sys
import pcapy
import re
from UI_home import *
from listen import Listen
from PyQt5.QtWidgets import QApplication, QMainWindow,QTableWidgetItem,QTreeWidgetItem,QTreeWidget
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox,QWidget

class HomeForm(QMainWindow,Ui_Form):
    protocolMap = {"1":"ICMP", "6":"TCP", "17":"UDP"}#协议字典
    def __init__(self, parent=None):#主界面初始化
        super().__init__(parent)
        self.setupUi(self)
        self.showNetcard(self.netcard_cb)
        self.listen_bt.clicked.connect(self.connectListen)

    def showNetcard(self, netcard_cb):#显示所有网卡
        netcards = pcapy.findalldevs()#查找
        netcard_cb.addItems(netcards)#显示

    def preInit(self):#监听前的初始化函数
        self.__resList = []
        self.__cnt = {"TCP":0, "UDP":0, "ICMP":0}
        self.overview_tb.setRowCount(0)#清空总览表
        self.protocol_tree.clear()
        self.code_txt.clear()
        self.statistic_txt.clear()

    def showError(self):#提示过滤规则有误
        QMessageBox.information(QWidget(),"提示", "输入的过滤规则格式有误！")

    def connectListen(self):#连接监听线程
        self.__listen = Listen(self.netcard_cb.currentText(), self.filter_line.text(), self.getData, self.showError)#生成监听线程
        self.stop_bt.clicked.connect(self.__listen.stopListen)#连接相关接口
        self.overview_tb.clicked.connect(self.showTreeAndHex)
        self.preInit()#初始化
        self.__listen.start()#开启监听线程

    def getData(self):#获取数据包
        res = self.__listen.getData()
        if res != None:#解析结果不为空，显示到主界面
            targetRow = self.overview_tb.rowCount()
            self.overview_tb.insertRow(targetRow)
            targetData = [res["time"], res["ipSource"], res["ipTarget"], self.protocolMap[res["ipProtocol"]], res["dataLength"], res["information"]]
            for column in range(self.overview_tb.columnCount()):
                item = QTableWidgetItem(targetData[column])
                item.setTextAlignment(Qt.AlignHCenter | Qt.AlignVCenter)#文本居中显示
                self.overview_tb.setItem(targetRow, column, item)
            self.__resList.append(res)
            upperProtocol = self.protocolMap[res["ipProtocol"]]
            self.__cnt[upperProtocol] = self.__cnt[upperProtocol] + 1#更新统计数据
            self.showStatistic()
    
    def getSelectedRow(self):#获取选中行号
        items = self.overview_tb.selectedItems()
        return items[0].row()

    def showTreeAndHex(self):#显示协议树和16进制码
        self.showTree()
        self.showHex()

    def showTree(self):#显示协议树
        selectedRow = self.getSelectedRow()
        res = self.__resList[selectedRow]
        self.protocol_tree.clear()#清空

        rootFrame = QTreeWidgetItem(self.protocol_tree)#显示数据包的相关信息
        rootFrame.setText(0, "Frame %s: capture %s bytes totally" % (str(selectedRow + 1),res["dataLength"]))
        childFrame = QTreeWidgetItem(rootFrame)
        childFrame.setText(0, "Capture time: " + res["time"])

        rootEther = QTreeWidgetItem(self.protocol_tree)#显示以太网头部信息
        rootEther.setText(0, "Ethernet II, Source: (%s), Target: (%s)" % (res["macSource"],res["macTarget"]))
        childEther = QTreeWidgetItem(rootEther)
        childEther.setText(0, "Target MAC: (%s)\nSource MAC: (%s)\nType: IP(0x%04x)" % (res["macTarget"],res["macSource"],int(res["etherProtocol"])))

        rootInter = QTreeWidgetItem(self.protocol_tree)#显示IP数据包头部信息
        rootInter.setText(0, "Internet protocol, Source: (%s), Target: (%s)" % (res["ipSource"], res["ipTarget"]))
        childInter1 = QTreeWidgetItem(rootInter)
        childInter1.setText(0, "IP version: %s\nIP head length: %s bytes\nIP service type: 0x%02x\nIP total length: %s\nIP identification: %s\nIP flags: 0x%02x" % (res["ipVersion"],res["ipHeadLen"],int(res["ipServiceType"]),res["ipTotalLen"],res["ipIdenti"],int(res["ipFlag"])))
        childInter2 = QTreeWidgetItem(rootInter)
        childInter2.setText(0, "IP fragment offset: %s\nIP TTL: %s\nProtocol: %s(0x%02x)\nIP head checksum: %s\nIP source: (%s)\nIP target: (%s)" % (res["ipOffset"],res["ipTTL"],self.protocolMap[res["ipProtocol"]],int(res["ipProtocol"]),res["ipCheckSum"],res["ipSource"],res["ipTarget"]))
        
        if res["ipProtocol"] == "6":#显示TCP头部信息
            rootTrans = QTreeWidgetItem(self.protocol_tree)
            rootTrans.setText(0, "Transmission control protocol, Source port: (%s), Target port: (%s)" % (res["tcpSourcePort"],res["tcpTargetPort"]))
            childTrans1 = QTreeWidgetItem(rootTrans)
            childTrans1.setText(0, "TCP source port: %s\nTCP target port: %s\nTCP sequence number: %s\nTCP acknowledge number: %s" % (res["tcpSourcePort"],res["tcpTargetPort"],res["tcpSequence"],res["tcpAck"]))
            childTrans2 = QTreeWidgetItem(rootTrans)
            childTrans2.setText(0, "TCP head length: %s bytes\nTCP flags: 0x%02x\nTCP window size: %s\nTCP checksum: %s\nTCP urgent pointer: %s" % (res["tcpHeadLen"],int(res["tcpFlags"]),res["tcpWindowSize"],res["tcpCheckSum"],res["tcpUrgent"]))
        
        elif res["ipProtocol"] == "17":#显示UDP头部信息
            rootTrans = QTreeWidgetItem(self.protocol_tree)
            rootTrans.setText(0, "User datagram protocol, Source port: (%s), Target port: (%s)" % (res["udpSourcePort"],res["udpTargetPort"]))
            childTrans = QTreeWidgetItem(rootTrans)
            childTrans.setText(0, "UDP source port: %s\nUDP target port: %s\nUDP data length: %s bytes\nUDP checksum: %s" % (res["udpSourcePort"],res["udpTargetPort"],res["udpDataLen"],res["udpCheckSum"]))

        elif res["ipProtocol"] == "1":#显示ICMP头部信息
            rootTrans = QTreeWidgetItem(self.protocol_tree)
            rootTrans.setText(0, "Internet control management protocol, Type: (%s), Code: (%s)" % (res["icmpType"],res["icmpCode"]))
            childTrans = QTreeWidgetItem(rootTrans)
            childTrans.setText(0, "ICMP type: %s\nICMP code: %s\nICMP checksum: %s\nICMP identification: %s\nICMP sequence number: %s" % (res["icmpType"],res["icmpCode"],res["icmpCheckSum"],res["icmpIdenti"],res["icmpSequence"]))

    def showHex(self):#显示16进制码
        selectedRow = self.getSelectedRow()
        hex = self.__resList[selectedRow]["originalHex"]
        hexString = re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", hex)
        hexUnicode = ' '.join([chr(int(i,16)) for i in [hex[j:j + 2] for j in range(0,len(hex),2)]])

        self.code_txt.clear()#清空
        self.code_txt.appendPlainText("Data hex string:\n" + hexString + "\n")
        self.code_txt.appendPlainText("Data unicode:\n" + hexUnicode + "\n")

    def showStatistic(self): #显示统计数据
        self.statistic_txt.clear()#清空
        tmp = ["TCP", "UDP", "ICMP"]
        for i in range(3):
            self.statistic_txt.appendPlainText(tmp[i] + " total packets: " + str(self.__cnt[tmp[i]]))
            
if __name__ == '__main__':#运行主界面
    app = QApplication(sys.argv)
    home_form = HomeForm()
    home_form.setAttribute(QtCore.Qt.WA_DeleteOnClose,  True)
    home_form.show()
    sys.exit(app.exec_())
