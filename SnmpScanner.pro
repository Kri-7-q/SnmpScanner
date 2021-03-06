#-------------------------------------------------
#
# Project created by QtCreator 2015-04-29T09:33:44
#
#-------------------------------------------------

QT       += core network

QT       -= gui

TARGET = SnmpScanner
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    snmpscanner.cpp \
    resultcreator.cpp \
    devicemap.cpp \
    snmppacket.cpp

HEADERS += \
    snmpscanner.h \
    resultcreator.h \
    devicemap.h \
    snmppacket.h


macx: LIBS += -L$$PWD/net-snmp-api/lib-mac/ -lnetsnmp.30
unix:!macx: LIBS += -L$$PWD/net-snmp-api/lib-linux/ -lnetsnmp

INCLUDEPATH += $$PWD/net-snmp-api/include
DEPENDPATH += $$PWD/net-snmp-api/include
macx: INCLUDEPATH += $$PWD/net-snmp-api/config-mac/
unix:!macx: INCLUDEPATH += $$PWD/net-snmp-api/config-linux/
