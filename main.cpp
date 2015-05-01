#include <QCoreApplication>
#include "udpsocket.h"
#include <QTimer>


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    init_snmp("app");

    SnmpPaket paket = SnmpPaket::snmpGetRequest(SNMP_VERSION_1, QString("demopublic"), QString("sysDescr.0"));
    QByteArray dgram = paket.getDatagram();
    for (int i=0; i<dgram.size(); ++i) {
        printf("%i, ", (u_char)dgram.at(i));
    }

    UdpSocket socket;
    socket.writeDatagram(paket.getDatagram(), QHostAddress("157.185.82.8"), 161);

    QTimer::singleShot(6000, &a, SLOT(quit()));

    return a.exec();
}
