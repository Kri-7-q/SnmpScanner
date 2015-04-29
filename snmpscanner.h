#ifndef SNMPSCANNER_H
#define SNMPSCANNER_H

#include <QUdpSocket>
#include <QNetworkAddressEntry>

class SnmpScanner : public QUdpSocket
{
    Q_OBJECT
public:
    explicit SnmpScanner(QObject *parent = 0);
    ~SnmpScanner();

    bool startScan(const QByteArray &datagram);

signals:

public slots:
    void sendPaketToNextIP();

private:
    QList<QNetworkInterface> m_interfaceList;
    quint32 m_currentIp;
    quint32 m_lastIp;
    QByteArray m_datagram;

    // Methods
    QList<QNetworkInterface> getCurrentlyOnlineInterfacesIPv4() const;
    bool hasInterfaceIPv4Entry(const QNetworkInterface &interface) const;
    QNetworkAddressEntry getInterfacesIPv4Entry(const QNetworkInterface &interface);
    quint32 getInterfacesLowestIPv4(const QNetworkInterface &interface);
    quint32 getInterfacesHighestIPv4(const QNetworkInterface &interface);
};

#endif // SNMPSCANNER_H
