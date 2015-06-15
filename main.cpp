#include <QCoreApplication>
#include "snmpscanner.h"
#include "resultcreator.h"
#include <QTimer>


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    init_snmp("app");

    QString mibValue("sysDescr.0");
    QStringList communityList = QStringList() << "public" << "private" << "demopublic";
    QHostAddress start(QString("141.82.52.1"));
    QHostAddress end(QString("141.82.52.254"));
    SnmpScanner scanner;
    ResultCreator analyser;
    QObject::connect(&scanner, SIGNAL(scanFinished(const DeviceMap*)), &analyser, SLOT(createResult(const DeviceMap*)));

    scanner.scanRange(SNMP_VERSION_1, communityList, mibValue, 2, start, end);

    return a.exec();
}
