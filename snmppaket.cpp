#include "snmppaket.h"

// Constructs a Simple Network Management Protocol
SnmpPaket::SnmpPaket()
{

}

// Destructor
SnmpPaket::~SnmpPaket()
{

}

// Get version from QByteArray as long value.
long SnmpPaket::version() const
{
    long version = m_version.value().at(0);
    for (int i=1; i<m_version.value().size(); ++i)
    {
        version << 8;
        version += m_version.value().at(i);
    }

    return version;
}

// Set Snmp version
void SnmpPaket::setVersion(const long version, const int length)
{
    m_version.setType(ASN_INTEGER);
    m_version.setValue(version, length);
}

QString SnmpPaket::community() const
{
    return QString(m_community.value());
}

void SnmpPaket::setCommunity(const QString &community)
{
    m_community.setType(ASN_OCTET_STR);
    m_community.setValue(community);
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
QByteArray SnmpPaket::getDatagram()
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
    paket.setVersion(version, sizeof(long));
    paket.setCommunity(community);
    oid objectIdentifier[MAX_OID_LEN];
    size_t identifierLength = MAX_OID_LEN;
    get_node(objectId.toUtf8().data(), objectIdentifier, &identifierLength);
    snmp_add_null_var(&paket.pdu, objectIdentifier, identifierLength);

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
    array.append((char)48);         // Protocols sequence mark.
    array.append((char)(128 + 2));  // Set the highest bit and define the following 2 bytes as length value.
    array.append(m_length / 255);   // Set heigh byte
    array.append(m_length % 255);   // Set low byte

    return array;
}

// Getter and setter
quint8 Triple::length() const
{
    return m_value.size();
}

QByteArray Triple::value() const
{
    return m_value;
}

// Set a string value. (community string)
void Triple::setValue(const QString &value)
{
    m_value = QByteArray(value.toUtf8());
}

// Set a long value. (snmp version)
void Triple::setValue(const long value, int length)
{
    int startPosition = sizeof(long) - length;
    char *currentPosition = ((char*)value) + startPosition;
    while (length >= 0)
    {
        m_value.append(*currentPosition);
        ++currentPosition;
        --length;
    }
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
    array.append((char)m_value.size());
    array.append(m_type);
    array.append(m_value);

    return array;
}
