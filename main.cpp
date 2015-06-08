#include <QCoreApplication>
#include "snmpscanner.h"
#include "analyser.h"
#include <QTimer>


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    init_snmp("app");

    QString mibValue("sysDescr.0");
    QStringList communityList = QStringList() << "public" << "private" << "demopublic";
    QHostAddress start(QString("192.168.0.1"));
    QHostAddress end(QString("192.168.0.254"));
    SnmpScanner scanner;
    Analyser analyser(&a);
    QObject::connect(&scanner, SIGNAL(scanFinished(ScanResult*)), &analyser, SLOT(analyseScanResult(ScanResult*)));

    scanner.scanRange(SNMP_VERSION_1, communityList, mibValue, 2, start, end);

    return a.exec();
}
