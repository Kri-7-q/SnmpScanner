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
    bool isPrinter(const SnmpDevice &device) const;
    bool isRouter(const SnmpDevice &device) const;
    snmp_pdu* snmpRequest(const QHostAddress &host, const QString &community, const QString &value) const;
};

#endif // RESULTCREATOR_H
