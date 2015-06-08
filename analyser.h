#ifndef ANALYSER_H
#define ANALYSER_H

#include "scanresult.h"
#include <QCoreApplication>

class Analyser : public QObject
{
    Q_OBJECT
public:
    explicit Analyser(QObject *parent = 0);

signals:

public slots:
    void analyseScanResult(ScanResult *resultTable);
};

#endif // ANALYSER_H
