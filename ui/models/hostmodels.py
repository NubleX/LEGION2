#!/usr/bin/env python3

"""
LEGION2 - A free and open-source penetration testing tool.
Copyright (c) 2025 NubleX / Igor Dunaev

Forked from an earlier version of LEGION, which was originally created by Gotham Security.
It was archived in 2024 and Kali Linux users were left with a broken program.

LEGION (https://gotham-security.com)
Copyright (c) 2023 Gotham Security

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
    version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
    details.

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <http://www.gnu.org/licenses/>.

"""

import re
from PyQt6 import QtWidgets, QtGui, QtCore
from PyQt6.QtGui import QFont
from PyQt6.QtCore import pyqtSignal, QObject

from app.ModelHelpers import resolveHeaders, itemSelectable
from app.auxiliary import *                                                 # for bubble sort


class HostsTableModel(QtCore.QAbstractTableModel):
    
    def __init__(self, hosts = [[]], headers = [], parent = None):
        QtCore.QAbstractTableModel.__init__(self, parent)
        self.__headers = headers
        self._hosts = hosts  # Renamed to avoid conflict
        
    def setHosts(self, hosts):
        self._hosts = hosts

    def getSafeHostField(self, row, key_or_index):
        if row < 0 or row >= len(self._hosts):
            return None
        host = self._hosts[row]
        if isinstance(host, dict):
            return host.get(key_or_index)
        elif isinstance(host, tuple):
            if key_or_index == 'ip':
                return host[0]
            elif key_or_index == 'id':
                return host[1]
        return None

    def rowCount(self, parent):
        return len(self._hosts)

    def columnCount(self, parent):
        if len(self._hosts) != 0:
            return len(self._hosts[0])
        return 0
        
    def headerData(self, section, orientation, role):
        return resolveHeaders(role, orientation, section, self.__headers)

    def data(self, index, role):                # this method takes care of how the information is displayed
        if role == QtCore.Qt.ItemDataRole.DecorationRole:    # to show the operating system icon instead of text
            if index.column() == 1:                                     # if trying to display the operating system
                os_string = self.getSafeHostField(index.row(), 'osMatch')
                if not os_string:  # handles None and empty string
                    return QtGui.QIcon("./images/question-icon.png")
                    
                elif re.search('[lL]inux', os_string, re.I):
                    return QtGui.QIcon("./images/linux-icon.png")
                
                elif re.search('[wW]indows', os_string, re.I):
                    return QtGui.QIcon("./images/windows-icon.png")
                    
                elif re.search('[cC]isco', os_string, re.I):
                    return QtGui.QIcon("./images/cisco-big.jpg")
                    
                elif re.search('HP ', os_string, re.I):
                    return QtGui.QIcon("./images/hp-icon.png")

                elif re.search('[vV]x[wW]orks', os_string, re.I):
                    return QtGui.QIcon("./images/hp-icon.png")
                    
                elif re.search('[vV]m[wW]are', os_string, re.I):
                    return QtGui.QIcon("./images/vmware-big.jpg")
                
                else:  # if it's an unknown OS also use the question mark icon
                    return QtGui.QIcon("./images/question-icon.png")

        if role == QtCore.Qt.ItemDataRole.DisplayRole:                               # how to display each cell
            value = ''
            row = index.row()
            column = index.column()
            if column == 0:
                value = self.getSafeHostField(row, 'id')
            elif column == 2:
                value = self.getSafeHostField(row, 'osAccuracy')
            elif column == 3:
                hostname = self.getSafeHostField(row, 'hostname')
                ip = self.getSafeHostField(row, 'ip')
                ip = ip if ip is not None else ''
                hostname = hostname if hostname is not None else ''
                if hostname != '':
                    value = ip + ' (' + hostname + ')'
                else:
                    value = ip
            elif column == 4:
                value = self.getSafeHostField(row, 'ipv4')
            elif column == 5:
                value = self.getSafeHostField(row, 'ipv6')
            elif column == 6:
                value = self.getSafeHostField(row, 'macaddr')
            elif column == 7:
                value = self.getSafeHostField(row, 'status')
            elif column == 8:
                value = self.getSafeHostField(row, 'hostname')
            elif column == 9:
                value = self.getSafeHostField(row, 'vendor')
            elif column == 10:
                value = self.getSafeHostField(row, 'uptime')
            elif column == 11:
                value = self.getSafeHostField(row, 'lastboot')
            elif column == 12:
                value = self.getSafeHostField(row, 'distance')
            elif column == 13:
                value = self.getSafeHostField(row, 'checked')
            elif column == 14:
                value = self.getSafeHostField(row, 'state')
            elif column == 15:
                value = self.getSafeHostField(row, 'count')
            else:
                value = 'Not set in view model'
            return value
            
        if role == QtCore.Qt.ItemDataRole.FontRole:
            # if a host is checked strike it out and make it italic
            if index.column() == 3 and self.getSafeHostField(index.row(), 'checked') == 'True':
                checkedFont=QFont()
                checkedFont.setStrikeOut(True)
                checkedFont.setItalic(True)
                return checkedFont

    # method that allows views to know how to treat each item, eg: if it should be enabled, editable, selectable etc
    def flags(self, index):
        return itemSelectable()

    # sort function called when the user clicks on a header
    def sort(self, Ncol, order):
        self.layoutAboutToBeChanged.emit()
        if Ncol == 0 or Ncol == 3:  # Sort by IP address
            def ip_key(host):
                ip = host.get('ip') if isinstance(host, dict) else host[0]
                try:
                    result = IP2Int(ip)
                    if result is None:
                        return 0
                    return result
                except Exception as e:
                    log.error(f"Error converting IP for host {host}: {e}")
                    return 0
            self._hosts.sort(key=ip_key, reverse=(order == QtCore.Qt.SortOrder.DescendingOrder))
            self.layoutChanged.emit()
            return

        elif Ncol == 1:  # Sort by OS
            self.sortByOS(order)
            return

        # Add other column sorts as needed

        self.layoutChanged.emit()

    def sortByOS(self, order):
        array = [self.getSafeHostField(i, 'osMatch') or '' for i in range(len(self._hosts))]
        zipped = list(zip(array, self._hosts))
        zipped.sort(key=lambda x: x[0], reverse=(order == QtCore.Qt.SortOrder.DescendingOrder))
        self._hosts = [host for _, host in zipped]
        self.layoutChanged.emit()

    ### getter functions ###

    def getHostIPForRow(self, row):
        return self.getSafeHostField(row, 'ip')

    def getHostIdForRow(self, row):
        return self.getSafeHostField(row, 'id')
        
    def getHostCheckStatusForRow(self, row):
        return self.getSafeHostField(row, 'checked')

    def getHostCheckStatusForIp(self, ip):
        for i in range(len(self._hosts)):
            if str(self.getSafeHostField(i, 'ip')) == str(ip):
                return self.getSafeHostField(i, 'checked')
            
    def getRowForIp(self, ip):
        for i in range(len(self._hosts)):
            if self.getSafeHostField(i, 'ip') == ip:
                return i
        return None
