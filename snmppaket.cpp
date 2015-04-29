#include "snmppaket.h"

// Constructs a Simple Network Management Protocol
SnmpPaket::SnmpPaket()
{

}

// Destructor
SnmpPaket::~SnmpPaket()
{

}

// Setter and getter
long SnmpPaket::version() const
{
    return m_version.value();
}

void SnmpPaket::setVersion(const long version)
{
    m_version.setType(ASN_INTEGER);
    m_version.setLength(1);
    m_version.setValue(version);
}

QString SnmpPaket::community() const
{
    return QString(m_community.value());
}

void SnmpPaket::setCommunity(const QString &community)
{
    m_community.setType(ASN_OCTET_STR);
    m_community.setLength(community.length());
    m_community.setValue(community.toUtf8());
}



// Initialize net-snmp PDU structure.
void SnmpPaket::setCommand(const int command)
{
    memset(&pdu, 0, sizeof(snmp_pdu));
    pdu.version = SNMP_DEFAULT_VERSION;
    pdu.command = command;
    pdu.errstat = SNMP_DEFAULT_ERRSTAT;
    pdu.errindex = SNMP_DEFAULT_ERRINDEX;
    pdu.securityModel = SNMP_DEFAULT_SECMODEL;
    pdu.transport_data = NULL;
    pdu.transport_data_length = 0;
    pdu.securityNameLen = 0;
    pdu.contextNameLen = 0;
    pdu.time = 0;
    pdu.reqid = snmp_get_next_reqid();
    pdu.msgid = snmp_get_next_msgid();
}

// Get the SNMP datagram.
QByteArray SnmpPaket::getDatagram() const
{
    size_t bufferLength = 1024, outLength = 1024;
    u_char *buffer = (u_char*)malloc(bufferLength);
    u_char* result = snmp_pdu_build(&pdu, buffer, &outLength);
    size_t pduLength = bufferLength - outLength;
    QByteArray version = m_version.getAsByteArray();
    QByteArray community = m_community.getAsByteArray();
    m_messageSequence.setLength(version.size() + community.size() + pduLength);
    QByteArray sequence = m_messageSequence.getAsByteArray();
    QByteArray datagram(sequence);
    datagram.append(version).append(community).append((char*)buffer, pduLength);

    return datagram;
}

// Factory function. Creates a SNMP paket for a get request.
SnmpPaket SnmpPaket::protocolGetRequest(const int command, const long version, const QString &community, const QString &objectId)
{
    SnmpPaket paket;
    paket.setCommand(command);
    paket.setVersion(version);
    paket.setCommunity(community);
    struct oid objectIdentifier[MAX_OID_LEN];
    size_t identifierLength = MAX_OID_LEN;
    get_node(objectId.toUtf8().data(), objectIdentifier, &identifierLength);
    snmp_add_null_var(&pdu, objectIdentifier, identifierLength);

    return paket;
}


// Getter and setter
unsigned short Sequence::length() const
{
    return m_length;
}

void Sequence::setLength(const unsigned short length)
{
    m_length = length;
}

// Get the Sequnce as a byte array to build the protocol header.
QByteArray Sequence::getAsByteArray() const
{
    QByteArray array;
    array.append(128 + 2);  // Set the highest bit and define the following 2 bytes as length value.
    array.append(m_length / 255);   // Set heigh byte
    array.append(m_length % 255);   // Set low byte

    return array;
}

// Getter and setter
quint8 Triple::length() const
{
    return m_length;
}

void Triple::setLength(const quint8 length)
{
    m_length = length;
}

QByteArray Triple::value() const
{
    return m_value;
}

void Triple::setValue(const QByteArray &value)
{
    m_value = value;
}

quint8 Triple::type() const
{
    return m_type;
}

void Triple::setType(const quint8 type)
{
    m_type = type;
}

// Get a TLV triple as byte array. (Type, Length, Value)
QByteArray Triple::getAsByteArray() const
{
    QByteArray array;
    array.append(m_length);
    array.append(m_type);
    array.append(m_value);

    return array;
}
