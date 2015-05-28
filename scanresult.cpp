#include "scanresult.h"

ScanResult::ScanResult()
{

}


// SnmpDevice
// Constructor
SnmpDevice::SnmpDevice(const QString community, const QString description) :
    m_community(community),
    m_description(description)
{

}
