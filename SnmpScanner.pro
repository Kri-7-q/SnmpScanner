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
    snmpscanner.cpp

HEADERS += \
    snmppaket.h \
    snmpscanner.h

macx: LIBS += -L$$PWD/../../net-snmp-lib/lib/ -lnetsnmp

INCLUDEPATH += $$PWD/../../net-snmp-lib/include
DEPENDPATH += $$PWD/../../net-snmp-lib/include
