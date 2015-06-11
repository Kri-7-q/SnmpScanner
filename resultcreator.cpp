#include "resultcreator.h"

// Constructor
ResultCreator::ResultCreator(QObject *parent) : QObject(parent)
{
    m_objectIdList << "ipForwarding.0"
                   << "ifNumber.0"
                   << ".1.3.6.1.2.1.43.5.1.1.1.1";      // First value in Printer-MIB.
}

// SLOT
// Takes a pointer to the scan result and creates the probes result.
void ResultCreator::createResult(const ScanResult *scanResult)
{
    qDebug() << "Scanner found " << scanResult->count() << " devices.";
    QString mapKeyType("type");
    QVariantMap resultMap;
    foreach (SnmpDevice snmpDevice, scanResult->deviceList()) {
        QVariantMap device;
        device.insert(QString("host"), snmpDevice.host().toString());
        device.insert(QString("community"), snmpDevice.community());
        device.insert(QString("description"), snmpDevice.description());
        snmp_pdu *responsePDU = snmpRequest(snmpDevice.host(), snmpDevice.community()[0], m_objectIdList);
        if (responsePDU == 0)
        {
            // Error handling ! ! ! ! ! ! ! ! ! ! ! ! ! !
            qDebug() << "Got no information about this device.";
            continue;
        }
        if (isDeviceRouter(responsePDU))
        {
            device.insert(mapKeyType, QString("Router"));
        }
        else if (isDeviceSwitch(responsePDU))
        {
            device.insert(mapKeyType, QString("Switch"));
        }
        else if (isDevicePrinter(responsePDU))
        {
            device.insert(mapKeyType, QString("Printer"));
        }
        else
        {
            device.insert(mapKeyType, QString("unknown"));
        }
        snmp_free_pdu(responsePDU);

        resultMap.insert(snmpDevice.host().toString(), device);
    }
    qDebug() << "Found " << resultMap.size() << " devices.";
    printResultMap(resultMap);
}

// Its a printer if the third value in response is present.
bool ResultCreator::isDevicePrinter(const snmp_pdu *responsePDU) const
{
    variable_list *valueList = responsePDU->variables->next_variable->next_variable;
    if (valueList->type == noSuchObject || valueList->type == noSuchInstance)
    {
        return false;
    }

    return true;
}

// Send a request to the device. Query a value in the IP-MIB.
// Its a router if 'ipForwarding.0' is set to 1.
bool ResultCreator::isDeviceRouter(const snmp_pdu *responsePDU) const
{
    variable_list *valueList = responsePDU->variables;
    if (valueList->type != ASN_INTEGER)
    {
        return false;
    }
    int ipForwarding = *(int*)(valueList->buf);
    valueList = valueList->next_variable;
    if (valueList->type != ASN_INTEGER)
    {
        return false;
    }
    int numInterfaces = *(int*)(valueList->buf);

    return ipForwarding == 1 && numInterfaces >= 4;
}

// Takes the response of a request (ipForwarding and ifNumber).
// Tests if device is a switch. No forwarding but many interfaces.
bool ResultCreator::isDeviceSwitch(const snmp_pdu *responsePDU) const
{
    variable_list *valueList = responsePDU->variables;
    if (valueList->type != ASN_INTEGER)
    {
        return false;
    }
    int ipForwarding = *(int*)(valueList->buf);
    valueList = valueList->next_variable;
    if (valueList->type != ASN_INTEGER)
    {
        return false;
    }
    int numInterfaces = *(int*)(valueList->buf);

    return ipForwarding != 1 && numInterfaces >= 4;
}

// Send one or more SNMP requests to a devices.
snmp_pdu *ResultCreator::snmpRequest(const QHostAddress &host, const QString &community, const QStringList &oidList) const
{
    QByteArray peername = host.toString().toLocal8Bit();
    QByteArray communityStr = community.toLocal8Bit();
    struct snmp_session session;
    snmp_sess_init(&session);
    session.community = (u_char*)communityStr.data();
    session.community_len = communityStr.length();
    session.peername = peername.data();
    session.version = SNMP_VERSION_2c;
    struct snmp_session *ss = snmp_open(&session);
    if (ss == NULL)
    {
        // Horrible error.
        qDebug() << "Could not open session.";
        return NULL;
    }

    struct snmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET);
    oid objectId[MAX_OID_LEN];
    foreach (QString value, oidList)
    {
        size_t oidLength = MAX_OID_LEN;
        // Get ObjectID of MIB-Object name.
        int result = get_node(value.toLocal8Bit().data(), objectId, &oidLength);
        if (!result)
        {
            // Get ObjectID of string like ".1.3.6.2.1.1".
            if (! read_objid(value.toLocal8Bit().data(), objectId, &oidLength))
            {
                // Error didn't get object ID.
                qDebug() << "ObjectID corrupt.";
                free(pdu);
                return NULL;
            }
        }
        snmp_add_null_var(pdu, objectId, oidLength);
    }

    struct snmp_pdu *response = NULL;
    int result = snmp_synch_response(ss, pdu, &response);
    snmp_close(ss);
    if (result != STAT_SUCCESS)
    {
        // Error could not read MIB of agent.
        qDebug() << "Can't read agent MIB.";
        return NULL;
    }

    return response;
}

// DEBUG
// Print scann result.
void ResultCreator::printResultMap(const QVariantMap &resultMap) const
{
    QTextStream outStream(stdout);
    foreach ( QVariant value, resultMap.values()) {
        QVariantMap map = value.value<QVariantMap>();
        outStream << "----------------------------------------------------" << endl;
        foreach (QString key, map.keys()) {
            outStream << key << " : " << map.value(key).toString() << endl;
        }
    }
    outStream << "----------------------------------------------------" << endl;
}

