#ifndef SNMPROTOCOL_H
#define SNMPROTOCOL_H

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <QByteArray>
#include <QString>

// Protocol type 'Sequence'.
class Sequence
{
    unsigned short m_length;

public:
    unsigned short length() const;
    void setLength(const unsigned short length);
    QByteArray getAsByteArray() const;
};

// TLV (Type, Length, Value) triple.
// For the values 'version' and 'community'.
class Triple
{
    quint8 m_type;
    // length is part of QByteArray.
    QByteArray m_value;

public:
    quint8 type() const;
    void setType(const quint8 type);
    quint8 length() const;
    void setLength(const quint8 length);
    QByteArray value() const;
    void setValue(const QString &value);
    void setValue(const long value, int length);
    QByteArray getAsByteArray() const;
};

// SNMP paket
class SnmpPaket
{
public:
    SnmpPaket();
    ~SnmpPaket();

public:
    long version() const;
    void setVersion(const long version, const int length);
    QString community() const;
    void setCommunity(const QString &community);
    void setCommand(const int command);
    QByteArray getDatagram();

    // Static functions
    static SnmpPaket protocolGetRequest(const int command, const long version, const QString &community, const QString &objectId);

private:
    Sequence m_messageSequence;
    Triple m_version;
    Triple m_community;
    struct snmp_pdu pdu;
};

#endif // SNMPROTOCOL_H
