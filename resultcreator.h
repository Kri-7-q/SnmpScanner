#ifndef RESULTCREATOR_H
#define RESULTCREATOR_H

#include "scanresult.h"
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

class ResultCreator : public QObject
{
    Q_OBJECT
public:
    explicit ResultCreator(QObject *parent = 0);

signals:

public slots:
    void createResult(const ScanResult *scanResult);

private:
    enum ImplicitNull { noSuchObject = 128, noSuchInstance, endOfMibView };
    QStringList m_objectIdList;

    // Methods
    bool isDevicePrinter(const snmp_pdu *responsePDU) const;
    bool isDeviceRouter(const snmp_pdu *responsePDU) const;
    bool isDeviceSwitch(const snmp_pdu *responsePDU) const;
    snmp_pdu* snmpRequest(const QHostAddress &host, const QString &community, const QStringList &oidList) const;

    // Debug methods
    void printResultMap(const QVariantMap &resultMap) const;
};

#endif // RESULTCREATOR_H
