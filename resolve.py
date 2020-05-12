from datetime import datetime
import struct
import socket

class Resolve(object):
    def stringToMac(self,str):#将字符串转化为MAC地址
        return ":".join("%02x" % int(i) for i in str)

    def resolve(self,head,data):
        res = {}#利用字典存放解析结果
        res["time"] = str(datetime.now())
        res["dataLength"] = str(head.getlen())
        
        etherHeadLen = 14#解析以太网帧的头部
        etherHead = data[:etherHeadLen] 
        etherData = struct.unpack("!6s6sH",etherHead)#将帧头部字符串按照网络字节顺序解析出主机顺序的数据
        res["macTarget"] = self.stringToMac(etherData[0])
        res["macSource"] = self.stringToMac(etherData[1])
        etherProtocol = etherData[2]
        res["etherProtocol"] = str(etherProtocol)
        
        if etherProtocol == 0x0800:#解析IP包
            ipHeadLen = 20
            ipData = data[etherHeadLen:etherHeadLen + ipHeadLen]#取IP首部字段
            ipData = struct.unpack("!BBHHHBBH4s4s",ipData)
            res["ipVersion"] = str(ipData[0] >> 4)#解析IP首部各个字段
            res["ipHeadLen"] = str((ipData[0] & 0xF) * 4)
            res["ipServiceType"] = str(ipData[1])
            res["ipTotalLen"] = str(ipData[2])
            res["ipIdenti"] = str(ipData[3])
            res["ipFlag"] = str(ipData[4] >> 13)
            res["ipOffset"] = str(ipData[4] & 0x1F)
            res["ipTTL"] = str(ipData[5])
            ipProtocol = ipData[6]
            res["ipProtocol"] = str(ipProtocol)
            res["ipCheckSum"] = str(ipData[7])
            res["ipSource"] = socket.inet_ntoa(ipData[8])
            res["ipTarget"] = socket.inet_ntoa(ipData[9])

            tmpLen = etherHeadLen + ipHeadLen
            if ipProtocol == 6:#TCP
                tcpHeadLen = 20
                tcpHead = data[tmpLen:tmpLen + tcpHeadLen]#取TCP首部字段
                tcpData = struct.unpack("!HHLLBBHHH",tcpHead)
                res["tcpSourcePort"] = str(tcpData[0])#解析TCP首部各个字段
                res["tcpTargetPort"] = str(tcpData[1])
                res["tcpSequence"] = str(tcpData[2])
                res["tcpAck"] = str(tcpData[3])
                res["tcpHeadLen"] = str((tcpData[4] >> 4) * 4)
                res["tcpFlags"] = str(tcpData[5] & 0x3F)
                res["tcpWindowSize"] = str(tcpData[6])
                res["tcpCheckSum"] = str(tcpData[7])
                res["tcpUrgent"] = str(tcpData[8])
                res["information"] = "TCP source port:" + res["tcpSourcePort"] + " TCP target port:" + res["tcpTargetPort"]
                return res

            elif ipProtocol == 1:#ICMP
                icmpHeadLen = 8
                icmpHead = data[tmpLen:tmpLen + icmpHeadLen]#取ICMP首部字段
                icmpData = struct.unpack("!BBHHH",icmpHead)
                res["icmpType"] = str(icmpData[0])#解析ICMP首部各个字段
                res["icmpCode"] = str(icmpData[1])
                res["icmpCheckSum"] = str(icmpData[2])
                res["icmpIdenti"] = str(icmpData[3])
                res["icmpSequence"] = str(icmpData[4])
                res["information"] = "ICMP type:" + res["icmpType"] + " ICMP code:" + res["icmpCode"]
                return res

            elif ipProtocol == 17:#UDP
                udpHeadLen = 8
                udpHead = data[tmpLen:tmpLen + udpHeadLen]#取UDP首部字段
                udpData = struct.unpack("!HHHH",udpHead)
                res["udpSourcePort"] = str(udpData[0])#解析UDP首部各个字段
                res["udpTargetPort"] = str(udpData[1])
                res["udpDataLen"] = str(udpData[2])
                res["udpCheckSum"] = str(udpData[3])
                res["information"] = "UDP source port:" + res["udpSourcePort"] + " UDP target port:" + res["udpTargetPort"]
                return res

        return None