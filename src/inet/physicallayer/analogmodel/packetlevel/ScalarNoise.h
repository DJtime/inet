//
// Copyright (C) 2013 OpenSim Ltd.
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

#ifndef __INET_SCALARNOISE_H
#define __INET_SCALARNOISE_H

#include "inet/common/math/IFunction.h"
#include "inet/physicallayer/base/packetlevel/NarrowbandNoiseBase.h"

namespace inet {

namespace physicallayer {

class INET_API ScalarNoise : public NarrowbandNoiseBase
{
  protected:
    Ptr<const math::IFunction<W, math::Domain<simtime_t>>> powerFunction;

  public:
    ScalarNoise(simtime_t startTime, simtime_t endTime, Hz centerFrequency, Hz bandwidth, Ptr<const math::IFunction<W, math::Domain<simtime_t>>> powerFunction);

    virtual std::ostream& printToStream(std::ostream& stream, int level) const override;
    virtual Ptr<const math::IFunction<W, math::Domain<simtime_t>>> getPower() const { return powerFunction; }

    virtual W computeMinPower(simtime_t startTime, simtime_t endTime) const override;
    virtual W computeMaxPower(simtime_t startTime, simtime_t endTime) const override;
};

} // namespace physicallayer

} // namespace inet

#endif // ifndef __INET_SCALARNOISE_H
