#ifndef UDPSOCKET_H
#define UDPSOCKET_H

#include "snmppaket.h"
#include <QUdpSocket>
#include <QDebug>

class UdpSocket : public QUdpSocket
{
    Q_OBJECT
public:
    explicit UdpSocket(QObject *parent = 0);
    ~UdpSocket();

signals:

public slots:
    void readResponse();
};

#endif // UDPSOCKET_H
