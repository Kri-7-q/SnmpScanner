#ifndef SCANRESULT_H
#define SCANRESULT_H

#include <QHash>
#include <QHostAddress>



class SnmpDevice
{
public:
    SnmpDevice(const QString community, const QString description);

    QString community() const       { return m_community; }
    QString description() const     { return m_description; }

private:
    QString m_community;
    QString m_description;
};



class ScanResult : public QHash<QHostAddress,SnmpDevice>
{
public:
    ScanResult();
};

#endif // SCANRESULT_H
