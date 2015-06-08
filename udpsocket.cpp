#include "udpsocket.h"

UdpSocket::UdpSocket(QObject *parent) : QUdpSocket(parent)
{
    connect(this, SIGNAL(readyRead()), this, SLOT(readResponse()));
}

UdpSocket::~UdpSocket()
{

}

// Get response
void UdpSocket::readResponse()
{
    while (hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(pendingDatagramSize());
        QHostAddress host;
        readDatagram(datagram.data(), datagram.size(), &host);
        SnmpPaket paket = SnmpPaket::fromDatagram(datagram);
        qDebug() << "--------------------------------------------------" << endl << "Response";
        qDebug() << "Version : " << paket.version() << endl << "Community : " << paket.community();
        qDebug() << "Value : " << paket.pduValue(0);
        qDebug() << "--------------------------------------------------";
    }
}

