//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
/***************************************************************************
                          RtpSenderInfo.h  -  description
                             -------------------
    begin                : Wed Dec 5 2001
    copyright            : (C) 2001 by Matthias Oppitz
    email                : Matthias.Oppitz@gmx.de
***************************************************************************/

#ifndef __INET_RTPSENDERINFO_H
#define __INET_RTPSENDERINFO_H

#include "inet/transportlayer/rtp/RtpParticipantInfo.h"

namespace inet {
namespace rtp {

/**
 * The class RtpSenderInfo is used by an Rtp end system for storing information
 * about itself. With the stored information it can create a SenderReport.
 */
class INET_API RtpSenderInfo : public RtpParticipantInfo
{
  public:
    /**
     * Default constructor.
     */
    RtpSenderInfo(uint32_t ssrc = 0);

    /**
     * Copy constructor.
     */
    RtpSenderInfo(const RtpSenderInfo& senderInfo);

    /**
     * Destructor.
     */
    virtual ~RtpSenderInfo();

    /**
     * Assignment operator.
     */
    RtpSenderInfo& operator=(const RtpSenderInfo& senderInfo);

    /**
     * Duplicates this RtpSenderInfo by calling the copy constructor.
     */
    virtual RtpSenderInfo *dup() const override;

    /**
     * Stores information about this outgoing RtpPacket.
     */
    virtual void processRTPPacket(Packet *packet, int id, simtime_t arrivalTime) override;

    /**
     * Processes an incoming ReceptionReport for this sender.
     */
    virtual void processReceptionReport(const ReceptionReport *report, simtime_t arrivalTime);

    /**
     * Returns a SenderReport for this rtp endsystem.
     * If it hasn't sent rtp data packets during the
     * last 2 rtcp intervals, it returns nullptr.
     */
    virtual SenderReport *senderReport(simtime_t now) override;

    /**
     * Sets the time (simTime) when this endsystem has
     * started sending rtp packets.
     */
    virtual void setStartTime(simtime_t startTime);

    /**
     * Sets the clock rate (in ticks per second) this sender
     * increases the rtp time stamp.
     */
    virtual void setClockRate(int clockRate);

    /**
     * Sets the initial rtp time stamp.
     */
    virtual void setTimeStampBase(uint32_t timeStampBase);

    /**
     * Sets the initial sequence number.
     */
    virtual void setSequenceNumberBase(uint16_t sequenceNumberBase);

  private:
    void copy(const RtpSenderInfo& other);

  protected:
    /**
     * The time when the transmission was started.
     */
    simtime_t _startTime;

    /**
     * The clock rate this sender increases the rtp time stamp.
     */
    int _clockRate;

    /**
     * The initial rtp time stamp.
     */
    uint32_t _timeStampBase;

    /**
     * The initial sequence number.
     */
    uint16_t _sequenceNumberBase;

    /**
     * The number of rtp data packets this sender has sent.
     */
    uint32_t _packetsSent;

    /**
     * The number of data bytes this sender has sent.
     */
    uint32_t _bytesSent;
};

} // namespace rtp
} // namespace inet

#endif

