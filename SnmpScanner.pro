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
    snmppaket.cpp \
    snmpscanner.cpp \
    resultcreator.cpp \
    devicemap.cpp

HEADERS += \
    snmppaket.h \
    snmpscanner.h \
    resultcreator.h \
    devicemap.h


macx: LIBS += -L$$PWD/net-snmp-api/lib-mac/lib/ -lnetsnmp.30
unix:!macx: LIBS += -L$$PWD/net-snmp-api/lib-linux/ -lnetsnmp

INCLUDEPATH += $$PWD/net-snmp-api/include
DEPENDPATH += $$PWD/net-snmp-api/include
unix:!macx: INCLUDEPATH += $$PWD/net-snmp-api/config-linux/
