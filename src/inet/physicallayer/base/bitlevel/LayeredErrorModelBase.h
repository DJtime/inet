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

#ifndef __INET_LAYEREDERRORMODELBASE_H
#define __INET_LAYEREDERRORMODELBASE_H

#include "inet/physicallayer/base/packetlevel/ApskModulationBase.h"
#include "inet/physicallayer/contract/bitlevel/ILayeredErrorModel.h"

namespace inet {

namespace physicallayer {

class INET_API LayeredErrorModelBase : public cModule, public ILayeredErrorModel
{
  protected:
    const char *symbolCorruptionMode = nullptr;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;

    virtual const IReceptionPacketModel *computePacketModel(const LayeredTransmission *transmission, double packetErrorRate) const;
    virtual const IReceptionBitModel *computeBitModel(const LayeredTransmission *transmission, double bitErrorRate) const;
    virtual const IReceptionSymbolModel *computeSymbolModel(const LayeredTransmission *transmission, double symbolErrorRate) const;

    virtual const ISymbol *computeCorruptSymbol(const ApskModulationBase *modulation, const ApskSymbol *transmittedSymbol) const;
};

} // namespace physicallayer

} // namespace inet

#endif // ifndef __INET_LAYEREDERRORMODELBASE_H
