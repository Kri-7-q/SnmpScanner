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
void ResultCreator::createResult(const DeviceMap *scanResult)
{
    qDebug() << "Scanner found " << scanResult->count() << " devices.";
    QVariantMap resultMap;
    foreach (SnmpDevice device, scanResult->deviceList()) {
        QVariantMap deviceMap;
        deviceMap.insert(QString("host"), device.host.toString());
        deviceMap.insert(QString("communityList"), device.m_communityList);
        deviceMap.insert(QString("description"), device.description);
        SnmpPaket packet = snmpRequest(device.host, device.communityName(), m_objectIdList);
        if (packet.isEmpty())
        {
            // Error handling ! ! ! ! ! ! ! ! ! ! ! ! ! !
            qDebug() << "Got no information about this device.";
            continue;
        }
        if (isDeviceRouter(packet))
        {
            deviceMap.insert(QString("type"), QString("Router"));
        }
        else if (isDeviceSwitch(packet))
        {
            deviceMap.insert(QString("type"), QString("Switch"));
        }
        else if (isDevicePrinter(packet))
        {
            deviceMap.insert(QString("type"), QString("Printer"));
        }
        else
        {
            deviceMap.insert(QString("type"), QString("unknown"));
        }

        resultMap.insert(device.host.toString(), deviceMap);
    }
    qDebug() << "Found " << resultMap.size() << " devices.";
    printResultMap(resultMap);
}

// Its a printer if the third value in response is present.
bool ResultCreator::isDevicePrinter(const SnmpPaket &packet) const
{
    quint8 dataType = packet.valueTypeAt(2);
    if (dataType == noSuchObject || dataType == noSuchInstance)
    {
        return false;
    }

    return true;
}

// Send a request to the device. Query a value in the IP-MIB.
// Its a router if 'ipForwarding.0' is set to 1.
bool ResultCreator::isDeviceRouter(const SnmpPaket &packet) const
{
    quint8 dataType = packet.valueTypeAt(0);
    if (dataType != ASN_INTEGER)
    {
        return false;
    }
    int ipForwarding = packet.intValueAt(0);
    dataType = packet.valueTypeAt(1);
    if (dataType != ASN_INTEGER)
    {
        return false;
    }
    int numInterfaces = packet.intValueAt(1);

    return ipForwarding == 1 && numInterfaces >= 4;
}

// Takes the response of a request (ipForwarding and ifNumber).
// Tests if device is a switch. No forwarding but many interfaces.
bool ResultCreator::isDeviceSwitch(const SnmpPaket &packet) const
{
    quint8 dataType = packet.valueTypeAt(0);
    if (dataType != ASN_INTEGER)
    {
        return false;
    }
    int ipForwarding = packet.intValueAt(0);
    dataType = packet.valueTypeAt(1);
    if (dataType != ASN_INTEGER)
    {
        return false;
    }
    int numInterfaces = packet.intValueAt(1);

    return ipForwarding != 1 && numInterfaces >= 4;
}

// Send one or more SNMP requests to a devices.
SnmpPaket ResultCreator::snmpRequest(const QHostAddress &host, const QString &community, const QStringList &oidList) const
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
        return SnmpPaket();
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
                snmp_free_pdu(pdu);
                snmp_close(ss);
                return SnmpPaket();
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
        snmp_close(ss);
        snmp_free_pdu(pdu);
        return SnmpPaket();
    }

    return SnmpPaket::fromPduStruct(response);
}

// DEBUG
// Print scann result.
void ResultCreator::printResultMap(const QVariantMap &resultMap) const
{
    QTextStream outStream(stdout);
    foreach ( QVariant value, resultMap.values()) {
        QVariantMap map = value.value<QVariantMap>();
        outStream << "----------------------------------------------------" << endl;
        outStream << "Host              : " << map.value("host").toString() << endl;
        outStream << "Community list    : ";
        foreach (QString communityName, map.value("communityList").toStringList()) {
            outStream << communityName << " ";
        }
        outStream << endl;
        outStream << "Description       : " << map.value("description").toString() << endl;
        outStream << "Type              : " << map.value("type").toString() << endl;
    }
    outStream << "----------------------------------------------------" << endl;
}

