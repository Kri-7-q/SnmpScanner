#include "resultcreator.h"

// Constructor
ResultCreator::ResultCreator(QObject *parent) : QObject(parent)
{

}

// SLOT
// Takes a pointer to the scan result and creates the probes result.
void ResultCreator::createResult(const ScanResult *scanResult)
{
    foreach (SnmpDevice device, scanResult->deviceList()) {

    }
}

// Send a request to the device. Query a value in the Printer MIB.
// Its a printer if device responses without an error.
bool ResultCreator::isPrinter(const SnmpDevice &device) const
{
    snmp_pdu *pdu = snmpRequest(device.host(), device.community()[0], "1.3.6.1.2.1.43.5.1.1.1.1");

    if (pdu == 0 || pdu->errstat != SNMP_ERR_NOERROR) {
        free(pdu);
        return false;
    }
    free(pdu);

    return true;
}

// Send a request to the device. Query a value in the IP-MIB.
// Its a router if 'ipForwarding.0' is set to 1.
bool ResultCreator::isRouter(const SnmpDevice &device) const
{
    snmp_pdu *pdu = snmpRequest(device.host(), device.community()[0], "ipForwarding.0");
    if (pdu == 0 || pdu->errstat != SNMP_ERR_NOERROR)
    {
        free(pdu);
        return false;
    }
    long ipForwarding = *pdu->variables->val.integer;
    free(pdu);
    pdu = NULL;
    pdu = snmpRequest(device.host(), device.community()[0], ".1.3.6.1.2.1.2.1");
    if (pdu == 0 || pdu->errstat != SNMP_ERR_NOERROR)
    {
        free(pdu);
        return false;
    }
    bool manyInterfaces = (pdu->variables->type == ASN_INTEGER && *pdu->variables->val.integer >= 2);
    free(pdu);

    return ipForwarding == 1 && manyInterfaces;
}

// Send a SNMP request to a devices.
snmp_pdu *ResultCreator::snmpRequest(const QHostAddress &host, const QString &community, const QString &value) const
{
    snmp_session session;
    snmp_sess_init(&session);
    session.community = (u_char*)community.toUtf8().data();
    session.community_len = community.length();
    session.peername = host.toString().toUtf8().data();
    session.version = SNMP_VERSION_2c;
    snmp_session *ss = snmp_open(&session);

    snmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET);
    oid objectId[MAX_OID_LEN];
    size_t oidLength = MAX_OID_LEN;
    int result = get_node(value.toUtf8().data(), objectId, &oidLength);
    snmp_add_null_var(pdu, objectId, oidLength);

    snmp_pdu *response;
    result = snmp_synch_response(ss, pdu, &response);
    if (!result)
    {
        return 0;
    }
    snmp_close(ss);

    return response;
}

