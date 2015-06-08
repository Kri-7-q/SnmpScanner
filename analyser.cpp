#include "analyser.h"

// Constructor
Analyser::Analyser(QObject *parent) : QObject(parent)
{

}

// Anlyses the devices which are found while scan.
void Analyser::analyseScanResult(ScanResult *resultTable)
{
    qDebug() << "Finished scan.";
    qDebug() << "Found " << resultTable->count() << " devices.";
    QList<SnmpDevice> list = resultTable->deviceList();
    for (int i=0; i<list.size(); ++i) {
        SnmpDevice device = list[i];
        qDebug() << "Host           : " << device.host().toString();
        qDebug() << "Communities    : " << device.community();
        qDebug() << "Description    : " << device.description();
        qDebug() << "-----------------------------------------------------------";
    }
    delete resultTable;
    ((QCoreApplication*)parent())->quit();
}

