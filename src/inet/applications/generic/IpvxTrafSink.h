//
// Copyright (C) 2004 OpenSim Ltd.
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 3
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//

#ifndef __INET_IPVXTRAFSINK_H
#define __INET_IPVXTRAFSINK_H

#include <vector>

#include "inet/applications/base/ApplicationBase.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3Address.h"

namespace inet {

/**
 * Consumes and prints packets received from the IP module. See NED for more info.
 */
class INET_API IpvxTrafSink : public ApplicationBase
{
  protected:
    int numReceived;

  protected:
    virtual void printPacket(Packet *msg);
    virtual void processPacket(Packet *msg);

    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void refreshDisplay() const override;

    virtual void handleStartOperation(LifecycleOperation *operation) override {}
    virtual void handleStopOperation(LifecycleOperation *operation) override {}
    virtual void handleCrashOperation(LifecycleOperation *operation) override {}
};

} // namespace inet

#endif

