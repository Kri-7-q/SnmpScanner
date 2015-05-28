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
    udpsocket.cpp \
    scanresult.cpp \
    analyser.cpp

HEADERS += \
    snmppaket.h \
    snmpscanner.h \
    udpsocket.h \
    scanresult.h \
    analyser.h

macx: LIBS += -L$$PWD/../../net-snmp-lib/lib/ -lnetsnmp

INCLUDEPATH += $$PWD/../../net-snmp-lib/include
DEPENDPATH += $$PWD/../../net-snmp-lib/include
