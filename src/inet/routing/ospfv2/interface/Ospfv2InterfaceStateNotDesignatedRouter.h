//
// Copyright (C) 2006 Andras Babos and Andras Varga
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

#ifndef __INET_OSPFV2INTERFACESTATENOTDESIGNATEDROUTER_H
#define __INET_OSPFV2INTERFACESTATENOTDESIGNATEDROUTER_H

#include "inet/routing/ospfv2/interface/Ospfv2InterfaceState.h"

namespace inet {

namespace ospfv2 {

class INET_API InterfaceStateNotDesignatedRouter : public Ospfv2InterfaceState
{
  public:
    virtual void processEvent(Ospfv2Interface *intf, Ospfv2Interface::Ospfv2InterfaceEventType event) override;
    virtual Ospfv2Interface::Ospfv2InterfaceStateType getState() const override { return Ospfv2Interface::NOT_DESIGNATED_ROUTER_STATE; }
};

} // namespace ospfv2

} // namespace inet

#endif

