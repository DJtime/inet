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

#ifndef __INET_ISIGNALSAMPLEMODEL_H
#define __INET_ISIGNALSAMPLEMODEL_H

#include "inet/physicallayer/contract/packetlevel/IPrintableObject.h"

namespace inet {

namespace physicallayer {

/**
 * This purely virtual interface provides an abstraction for different radio
 * signal models in the waveform or sample domain.
 */
class INET_API ISignalSampleModel : public IPrintableObject
{
  public:
    virtual int getHeaderSampleLength() const = 0;

    virtual double getHeaderSampleRate() const = 0;

    virtual int getDataSampleLength() const = 0;

    virtual double getDataSampleRate() const = 0;

    virtual const std::vector<W> *getSamples() const = 0;
};

class INET_API ITransmissionSampleModel : public virtual ISignalSampleModel
{
};

class INET_API IReceptionSampleModel : public virtual ISignalSampleModel
{
};

} // namespace physicallayer

} // namespace inet

#endif // ifndef __INET_ISIGNALSAMPLEMODEL_H
