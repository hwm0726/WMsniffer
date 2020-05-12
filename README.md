### Aim
A concisely multi-thread sniffer
### Dependency
Python3  
winpcap(if you are using Linux, please install libpcap)  
pcapy  
PyQt5  
### Introduction
listen.py: listen thread  
resolve.py: resolve packets from listen thread  
run.py: listen and show resolve information into home interface  
UI_home: home interface
### Usage
Firstly install the depedencies mentioned above, then    
in Windows, use cmd with administrator mode:  
python run.py    
in Linux:  
sudo ./run.py
