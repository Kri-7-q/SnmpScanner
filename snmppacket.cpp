#include "snmppaket.h"

// Constructs a Simple Network Management Protocol
SnmpPaket::SnmpPaket() :
    m_pdu(NULL)
{

}

// Destructor
SnmpPaket::~SnmpPaket()
{
    if (m_pdu != NULL)
    {
        snmp_free_pdu(m_pdu);
    }
}

// Get version from QByteArray as long value.
long SnmpPaket::version() const
{
    long version = m_version.value().at(0);
    for (int i=1; i<m_version.value().size(); ++i)
    {
        version = version << 8;
        version += m_version.value().at(i);
    }

    return version;
}

// Set Snmp version
void SnmpPaket::setVersion(const long version)
{
    m_version.setType(ASN_INTEGER);
    m_version.setValue(version);
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
    if (m_pdu != NULL)
    {
        snmp_free_pdu(m_pdu);
    }
    m_pdu = snmp_pdu_create(command);
}

// Get the SNMP datagram.
QByteArray SnmpPaket::getDatagram()
{
    size_t bufferLength = approximatePduSize();
    size_t outLength = bufferLength;
    u_char *buffer = (u_char*)malloc(bufferLength);
    memset(buffer, 0, bufferLength);
    snmp_pdu_build(m_pdu, buffer, &outLength);
    size_t pduLength = bufferLength - outLength;
    QByteArray version = m_version.getAsByteArray();
    QByteArray community = m_community.getAsByteArray();
    m_messageSequence.setLength(version.size() + community.size() + pduLength);
    QByteArray sequence = m_messageSequence.getAsByteArray();
    QByteArray datagram(sequence);
    datagram.append(version).append(community).append((char*)buffer, pduLength);
    free(buffer);

    return datagram;
}

// Get a value of PDU at index.
// Return a string which reads 'data type: value'.
QString SnmpPaket::pduValueAt(const quint8 index) const
{
    variable_list *variable = variableAtIndex(index);
    if (variable == NULL)
        return QString();
    size_t bufferLen = variable->val_len + 10;
    char *buffer = (char*)malloc(bufferLen);
    memset(buffer, 0, bufferLen);
    snprint_value(buffer, bufferLen, variable->name, variable->name_length, variable);
    QString value(buffer);
    free(buffer);

    return value;
}

// Gets a integer value from PDU at a given index.
// Behaviour is undefined if pdu value is not a int.
int SnmpPaket::intValueAt(const quint8 index) const
{
    variable_list *variable = variableAtIndex(index);
    if (variable == NULL)
        return 0;
    int *value = (int *)variable->buf;

    return *value;
}

// Get a string value from PDU at a given index.
// Behaviour is undefined if pdu value is not a string.
QString SnmpPaket::stringValueAt(const quint8 index) const
{
    variable_list *variable = variableAtIndex(index);
    if (variable == NULL)
        return QString();

    return QString::fromUtf8((char*)variable->val.string, variable->val_len);
}

// Get the data type of a value at a given position.
// Return the ASN.1 number of data type or 0 if an error occures.
quint8 SnmpPaket::valueTypeAt(const quint8 index) const
{
    variable_list *variable = variableAtIndex(index);
    if (variable == NULL)
        return 0;

    return variable->type;
}

// Factory function. Creates a SNMP paket for a get request.
SnmpPaket SnmpPaket::snmpGetRequest(const long version, const QString &community, const QString &objectId)
{
    SnmpPaket paket;
    paket.setCommand(SNMP_MSG_GET);
    paket.setVersion(version);
    paket.setCommunity(community);
    oid objectIdentifier[MAX_OID_LEN];
    size_t identifierLength = MAX_OID_LEN;
    get_node(objectId.toUtf8().data(), objectIdentifier, &identifierLength);
    snmp_add_null_var(paket.m_pdu, objectIdentifier, identifierLength);

    return paket;
}

// Parse a received datagram.
SnmpPaket SnmpPaket::fromDatagram(const QByteArray &datagram)
{
    SnmpPaket paket;
    // Get protocoll head
    quint16 position = paket.m_messageSequence.fromByteArray(datagram, 0);
    if (position == 0)
    {
        // Is not a SNMP datagram it starts not with a sequence.
        return paket;
    }
    position = paket.m_version.fromByteArray(datagram, position);
    position = paket.m_community.fromByteArray(datagram, position);
    // Get Protocoll Data Unit.
    QByteArray pdu = datagram.mid(position);
    size_t pduLength = pdu.size();
    paket.m_pdu = snmp_pdu_create(SNMP_MSG_RESPONSE);
    snmp_pdu_parse(paket.m_pdu, (u_char*)pdu.data(), &pduLength);

    return paket;
}

// Get the length value of a byte array. Value is distributed over some bytes.
quint16 SnmpPaket::lengthValueFromByteArray(const QByteArray &array, quint16 &position)
{
    quint8 higestBit = 128;
    if (array[position] < higestBit)
    {
        // Byte at position is length value.
        return array[position++];
    }
    // Length value needs more than one byte.
    quint16 length = 0;
    quint8 numFields = array[position++] - higestBit;
    for (quint8 index=0; index<numFields; ++index)
    {
        length = (length << 8) + array[position++];
    }

    return length;
}

// Get a length value as a byte array. A value higher then 127 must take more then one byte.
QByteArray SnmpPaket::lengthValueToByteArray(const int length)
{
    QByteArray array;
    if (length < 128)
    {
        // Length is less than 128 bytes. It needs just one byte.
        array.append((char)length);
        return array;
    }
    // Length value is higher or equal than 128 bytes.
    array.append((char)128 + 2);                // Set highest bit and define two fields for length value.
    array.append((char)length / 255);           // Set high byte.
    array.append((char)length % 255);           // Set low byte.

    return array;
}

// Get a SnmpPacket object from a PDU structure pointer.
SnmpPaket SnmpPaket::fromPduStruct(snmp_pdu *pdu)
{
    SnmpPaket packet;
    packet.setVersion(pdu->version);
    if (pdu->version == SNMP_VERSION_1 || pdu->version == SNMP_VERSION_2c)
    {
        packet.setCommunity(QString::fromUtf8((char*)pdu->community, pdu->community_len));
    }
    packet.m_pdu = pdu;

    return packet;
}

// Get approximate size of PDU.
size_t SnmpPaket::approximatePduSize()
{
    size_t pduSize = 4 + 3 + 3 + 3; // Fields :    Type + RequestId + Error + ErrIndex
    variable_list *list = m_pdu->variables;
    while (list)
    {
        pduSize += 2 + list->name_length;   // Type and Length field + value
        pduSize += 2 + list->val_len;       // Type and Length field + value
        list = list->next_variable;
    }
    pduSize += 20;                  // Add bytes as ensurense

    return pduSize;
}

// Return a variable_list pointer of a variable at given index or null.
variable_list *SnmpPaket::variableAtIndex(const quint8 index) const
{
    variable_list *list = m_pdu->variables;
    quint8 pos = 0;
    while (pos < index) {
        if (list == NULL)
            break;
        list = list->next_variable;
        ++pos;
    }

    return list;
}


// Getter and setter
quint16 Sequence::length() const
{
    return m_length;
}

void Sequence::setLength(const quint16 length)
{
    m_length = length;
}

// Get the Sequnce as a byte array to build the protocol header.
QByteArray Sequence::getAsByteArray() const
{
    QByteArray array;
    array.append((char)TypeSequence);       // Protocols sequence mark.
    array.append( SnmpPaket::lengthValueToByteArray(m_length) );

    return array;
}

// Get the paket length and return the position of next value in datagram.
quint16 Sequence::fromByteArray(const QByteArray &datagram, quint16 position)
{
    if (datagram[position++] != TypeSequence)
    {
        return 0;
    }
    m_length = SnmpPaket::lengthValueFromByteArray(datagram, position);

    return position;
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
void Triple::setValue(const long value)
{
    m_value.clear();
    int state = 0;
    const int LeadingNull = 0, Value = 1;
    char *currentPosition = (char*)&value;
    int length = sizeof(long);
    while (length > 0)
    {
        if (*currentPosition != 0)
            state = Value;
        switch (state)
        {
        case LeadingNull:
            break;
        case Value:
            m_value.append(*currentPosition);
            break;
        }
        ++currentPosition;
        --length;
    }
    if (m_value.isEmpty())
        m_value.append((char)0);
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
    array.append(m_type);
    array.append( SnmpPaket::lengthValueToByteArray(m_value.size()) );
    array.append(m_value);

    return array;
}

// Parses the SNMP version or the community string from datagram.
quint16 Triple::fromByteArray(const QByteArray &datagram, quint16 position)
{
    m_type = datagram[position++];
    quint16 length = SnmpPaket::lengthValueFromByteArray(datagram, position);
    m_value = datagram.mid(position, length);

    return position + length;
}
