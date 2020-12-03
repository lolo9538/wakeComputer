#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
Small module for use with the wake on lan protocol.

"""
from __future__ import absolute_import
from __future__ import unicode_literals

import argparse
import socket
import struct

import os
import time

from datetime import date
from datetime import datetime


BROADCAST_IP = '192.168.1.255' #it depends on your network
DEFAULT_PORT = 9

#raspberry ip
host = "put ip here"
port = 15555 #you can choose another
password_box = "the password of your SFR box"


def create_magic_packet(macaddress):
    """
    Create a magic packet.

    A magic packet is a packet that can be used with the for wake on lan
    protocol to wake up a computer. The packet is constructed from the
    mac address given as a parameter.

    Args:
        macaddress (str): the mac address that should be parsed into a
            magic packet.

    """
    if len(macaddress) == 12:
        pass
    elif len(macaddress) == 17:
        sep = macaddress[2]
        macaddress = macaddress.replace(sep, '')
    else:
        raise ValueError('Incorrect MAC address format')

    # Pad the synchronization stream
    data = b'FFFFFFFFFFFF' + (macaddress * 16).encode()
    send_data = b''

    # Split up the hex values in pack
    for i in range(0, len(data), 2):
        send_data += struct.pack(b'B', int(data[i: i + 2], 16))
    return send_data


def send_magic_packet(*macs, **kwargs):
    """
    Wake up computers having any of the given mac addresses.

    Wake on lan must be enabled on the host device.

    Args:
        macs (str): One or more macaddresses of machines to wake.

    Keyword Args:
        ip_address (str): the ip address of the host to send the magic packet
                     to (default "255.255.255.255")
        port (int): the port of the host to send the magic packet to
               (default 9)

    """
    packets = []
    ip = kwargs.pop('ip_address', BROADCAST_IP)
    port = kwargs.pop('port', DEFAULT_PORT)
    for k in kwargs:
        raise TypeError('send_magic_packet() got an unexpected keyword '
                        'argument {!r}'.format(k))

    for mac in macs:
        packet = create_magic_packet(mac)
        packets.append(packet)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.connect((ip, port))
    for packet in packets:
        sock.send(packet)
    sock.close()



from selenium import webdriver
from time import sleep
from selenium.webdriver.chrome.options import Options

#from secrets import username, password

##Bot class to turn wifi On and off
class wifiBot():
    def __init__(self):

        options = Options()
        options.add_argument("--disable-dev-shm-usage") # overcome limited resource problems
        options.add_argument("--no-sandbox") # Bypass OS security model
        options.add_argument("--remote-debugging-port=9222")  # this
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')  # Last I checked this was necessary.
        self.driver = webdriver.Chrome('/usr/lib/chromium-browser/chromedriver', chrome_options=options)

    def login(self):
        self.driver.get('http://192.168.1.1')

        sleep(0.5)

        password_field = self.driver.find_element_by_xpath('//*[@id="Authenticate.Password"]')
        password_field.send_keys(password_box)

        connexion_btn = self.driver.find_element_by_xpath('// *[ @ id = "bt_authenticate"]')
        connexion_btn.click()


    def switchToWifiTab(self):
        wifi_tab = self.driver.find_element_by_xpath(
            '/ html / body / div[11] / div / div / div / div[1] / div[3] / ul / li[2] / a / span')
        wifi_tab.click()

    #Turn wifi on
    def wifiOn(self):
        try:
            self.switchToWifiTab()
        except Exception:
            print("Already on wifi tab")

        # enabling wifi
        try:
            enable_btn = self.driver.find_element_by_xpath('//*[@id="bt_enable2"]')
            sleep(0.5)
            enable_btn.click()
        except Exception:
            print("Wifi is already on")

    #Turn wifi off
    def wifiOff(self):

        try:
            self.switchToWifiTab()
        except Exception:
            print("Already on wifi tab")

        try:
            disable_btn = self.driver.find_element_by_xpath('//*[@id="bt_disable2"]')
            sleep(0.5)
            disable_btn.click()
        except Exception:
            print("Wifi is already off")

    def close(self):
        self.driver.close()


def main(argv=None):
    """
    Run wake on lan as a CLI application.

    """   
    soc = socket.socket()
    soc.bind((host, port))
    soc.listen(5)
    print("Script WAkeOnLan.py has started")
    
    while True:
        conn, addr = soc.accept()

        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        today = date.today()
        # dd/mm/YY
        d1 = today.strftime("%d/%m/%Y")
        
        print(d1 + " " + current_time + "Got connection from",addr)
        length_of_message = int.from_bytes(conn.recv(2), byteorder='big')
        msg = conn.recv(length_of_message).decode("UTF-8")
        print(msg)
        #print(length_of_message)
    
        # Note the corrected indentation below
        if "WakeUp"in msg:
            message_to_send = "Démarrage...".encode("UTF-8")
            conn.send(len(message_to_send).to_bytes(2, byteorder='big'))
            conn.send(message_to_send)
            
            print ("Waking Laurent's computer")
            send_magic_packet('88-88-88-88-87-88', ip_address=BROADCAST_IP, port=DEFAULT_PORT)
            
    
        elif "ShutDown"in msg:
            message_to_send = "Arrêt...".encode("UTF-8")
            conn.send(len(message_to_send).to_bytes(2, byteorder='big'))
            conn.send(message_to_send)
            
            response = os.system('net rpc shutdown -f -I 192.168.1.21 -U "lolo%tennis9538"')
            print(response)
            if response == 0:
                pingstatus = "Network Active"
            else:
                pingstatus = "Network Error"
            print(pingstatus)

        elif "WifiOn" in msg:
            message_to_send = "Allumage du wifi...".encode("UTF-8")
            conn.send(len(message_to_send).to_bytes(2, byteorder='big'))
            conn.send(message_to_send)

            bot = wifiBot()
            bot.login()
            bot.wifiOn()
            bot.close()

            message_to_send = "Wifi Allumé...".encode("UTF-8")
            conn.send(len(message_to_send).to_bytes(2, byteorder='big'))
            conn.send(message_to_send)


        elif "WifiOff" in msg:
            message_to_send = "Exctinction du wifi...".encode("UTF-8")
            conn.send(len(message_to_send).to_bytes(2, byteorder='big'))
            conn.send(message_to_send)

            bot = wifiBot()
            bot.login()
            bot.wifiOff()
            bot.close()

            message_to_send = "Wifi Éteint...".encode("UTF-8")
            conn.send(len(message_to_send).to_bytes(2, byteorder='big'))
            conn.send(message_to_send)

    
        else:
            print("no message")
        
    print ("I should never print this")    
     


if __name__ == '__main__':  # pragma: nocover
    main()

