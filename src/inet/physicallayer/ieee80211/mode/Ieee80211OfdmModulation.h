//
// Copyright (C) 2015 OpenSim Ltd.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __INET_IEEE80211OFDMMODULATION_H
#define __INET_IEEE80211OFDMMODULATION_H

#include "inet/physicallayer/base/packetlevel/ApskModulationBase.h"

namespace inet {
namespace physicallayer {

class INET_API Ieee80211OfdmModulation : public IModulation
{
  protected:
    int numSubcarriers;
    const ApskModulationBase *subcarrierModulation;

  public:
    Ieee80211OfdmModulation(int numSubcarriers, const ApskModulationBase *subcarrierModulation);

    virtual int getNumSubcarriers() const { return numSubcarriers; }
    virtual const ApskModulationBase *getSubcarrierModulation() const { return subcarrierModulation; }

    // TODO: is it correct to calculate this with the same bandwidth and bitrate when there are subcarriers?
    virtual double calculateBER(double snir, Hz bandwidth, bps bitrate) const override { return subcarrierModulation->calculateBER(snir, bandwidth, bitrate); }
    virtual double calculateSER(double snir, Hz bandwidth, bps bitrate) const override { return subcarrierModulation->calculateSER(snir, bandwidth, bitrate); }

    virtual std::ostream& printToStream(std::ostream& stream, int level) const override;
};

class INET_API Ieee80211OfdmCompliantModulations
{
  // Modulations supported by the OFDM PHY: Table 18-12—Major parameters of the OFDM PHY
  public:
    static const Ieee80211OfdmModulation subcarriers52QbpskModulation;
    static const Ieee80211OfdmModulation subcarriers52BpskModulation;
    static const Ieee80211OfdmModulation subcarriers52QpskModulation;
    static const Ieee80211OfdmModulation subcarriers52Qam16Modulation;
    static const Ieee80211OfdmModulation subcarriers52Qam64Modulation;
    static const Ieee80211OfdmModulation subcarriers52Qam256Modulation;
};

} /* namespace physicallayer */
} /* namespace inet */

#endif /* __INET_IEEE80211OFDMMODULATION_H */