//
// Copyright (C) 2009-2010 Thomas Reschka
// Copyright (C) 2011 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#include "inet/transportlayer/tcp/TcpSackRexmitQueue.h"

#include "inet/transportlayer/tcp/TcpSendQueue.h"

namespace inet {

namespace tcp {

TcpSackRexmitQueue::TcpSackRexmitQueue()
{
    conn = nullptr;
    begin = end = 0;
}

TcpSackRexmitQueue::~TcpSackRexmitQueue()
{
    while (!rexmitQueue.empty())
        rexmitQueue.pop_front();
}

void TcpSackRexmitQueue::init(uint32_t seqNum)
{
    begin = seqNum;
    end = seqNum;
}

std::string TcpSackRexmitQueue::str() const
{
    std::stringstream out;

    out << "[" << begin << ".." << end << ")";
    return out.str();
}

std::string TcpSackRexmitQueue::detailedInfo() const
{
    std::stringstream out;
    out << str() << endl;

    uint j = 1;

    for (const auto& elem : rexmitQueue) {
        out << j << ". region: [" << elem.beginSeqNum << ".." << elem.endSeqNum
            << ") \t sacked=" << elem.sacked << "\t rexmitted=" << elem.rexmitted
            << endl;
        j++;
    }
    return out.str();
}

void TcpSackRexmitQueue::discardUpTo(uint32_t seqNum)
{
    ASSERT(seqLE(begin, seqNum) && seqLE(seqNum, end));

    if (!rexmitQueue.empty()) {
        auto i = rexmitQueue.begin();

        while ((i != rexmitQueue.end()) && seqLE(i->endSeqNum, seqNum)) // discard/delete regions from rexmit queue, which have been acked
        {
            if (i->sacked) {
                auto sendQueue = conn->getSendQueueForUpdate();
                sendQueue->sackedOut -= i->endSeqNum - i->beginSeqNum;
            }
            i = rexmitQueue.erase(i);
        }

        if (i != rexmitQueue.end()) {
            ASSERT(seqLE(i->beginSeqNum, seqNum) && seqLess(seqNum, i->endSeqNum));
            i->beginSeqNum = seqNum;
        }
    }

    if (!rexmitQueue.empty())
    {
        auto& head = rexmitQueue.front();
        if (head.sacked)
        {
            // It is not possible to have the UNA sacked; otherwise, it would
            // have been ACKed. This is, most likely, our wrong guessing
            // when adding Reno dupacks in the count.
            head.sacked = false;
            auto sendQueue = conn->getSendQueueForUpdate();
            sendQueue->sackedOut -= head.endSeqNum - head.beginSeqNum;
            addInferredSack();
        }
    }

    begin = seqNum;

    // TESTING queue:
    ASSERT(checkQueue());
}

void TcpSackRexmitQueue::enqueueSentData(uint32_t fromSeqNum, uint32_t toSeqNum)
{
    ASSERT(seqLE(begin, fromSeqNum) && seqLE(fromSeqNum, end));

    bool found = false;
    Region region;

    EV_INFO << "rexmitQ: " << str() << " enqueueSentData [" << fromSeqNum << ".." << toSeqNum << ")\n";

    ASSERT(seqLess(fromSeqNum, toSeqNum));

    if (rexmitQueue.empty() || (end == fromSeqNum)) {
        region.beginSeqNum = fromSeqNum;
        region.endSeqNum = toSeqNum;
        region.sacked = false;
        region.rexmitted = false;
        rexmitQueue.push_back(region);
        found = true;
        fromSeqNum = toSeqNum;
    }
    else {
        auto i = rexmitQueue.begin();

        while (i != rexmitQueue.end() && seqLE(i->endSeqNum, fromSeqNum))
            i++;

        ASSERT(i != rexmitQueue.end());
        ASSERT(seqLE(i->beginSeqNum, fromSeqNum) && seqLess(fromSeqNum, i->endSeqNum));

        if (i->beginSeqNum != fromSeqNum) {
            // chunk item
            region = *i;
            region.endSeqNum = fromSeqNum;
            rexmitQueue.insert(i, region);
            i->beginSeqNum = fromSeqNum;
        }

        while (i != rexmitQueue.end() && seqLE(i->endSeqNum, toSeqNum)) {
            i->rexmitted = true;
            fromSeqNum = i->endSeqNum;
            found = true;
            i++;
        }

        if (fromSeqNum != toSeqNum) {
            bool beforeEnd = (i != rexmitQueue.end());

            ASSERT(i == rexmitQueue.end() || seqLess(i->beginSeqNum, toSeqNum));

            region.beginSeqNum = fromSeqNum;
            region.endSeqNum = toSeqNum;
            region.sacked = beforeEnd ? i->sacked : false;
            region.rexmitted = beforeEnd;
            rexmitQueue.insert(i, region);
            found = true;
            fromSeqNum = toSeqNum;

            if (beforeEnd)
                i->beginSeqNum = toSeqNum;
        }
    }

    ASSERT(fromSeqNum == toSeqNum);

    if (!found) {
        EV_DEBUG << "Not found enqueueSentData(" << fromSeqNum << ", " << toSeqNum << ")\nThe Queue is:\n" << detailedInfo();
    }

    ASSERT(found);

    begin = rexmitQueue.front().beginSeqNum;
    end = rexmitQueue.back().endSeqNum;

    // TESTING queue:
    ASSERT(checkQueue());

//    tcpEV << "rexmitQ: rexmitQLength=" << getQueueLength() << "\n";
}

bool TcpSackRexmitQueue::checkQueue() const
{
    uint32_t b = begin;
    bool f = true;

    for (const auto& elem : rexmitQueue) {
        f = f && (b == elem.beginSeqNum);
        f = f && seqLess(elem.beginSeqNum, elem.endSeqNum);
        b = elem.endSeqNum;
    }

    f = f && (b == end);

    if (!f) {
        EV_DEBUG << "Invalid Queue\nThe Queue is:\n" << detailedInfo();
    }

    return f;
}

void TcpSackRexmitQueue::addInferredSack()
{
    // skip the head which is assumed to be lost
    auto i = ++rexmitQueue.begin();
    while (i != rexmitQueue.end() && i->sacked)
        i++;
    if (i != rexmitQueue.end()) {
        i->sacked = true;
        auto sendQueue = conn->getSendQueueForUpdate();
        sendQueue->sackedOut += i->endSeqNum - i->beginSeqNum;
    }
}

void TcpSackRexmitQueue::setSackedBit(uint32_t fromSeqNum, uint32_t toSeqNum)
{
    if (seqLess(fromSeqNum, begin))
        fromSeqNum = begin;

    ASSERT(seqLess(fromSeqNum, end));
    ASSERT(seqLess(begin, toSeqNum) && seqLE(toSeqNum, end));
    ASSERT(seqLess(fromSeqNum, toSeqNum));

    bool found = false;

    if (!rexmitQueue.empty()) {
        auto i = rexmitQueue.begin();

        while (i != rexmitQueue.end() && seqLE(i->endSeqNum, fromSeqNum))
            i++;

        ASSERT(i != rexmitQueue.end() && seqLE(i->beginSeqNum, fromSeqNum) && seqLess(fromSeqNum, i->endSeqNum));

        if (i->beginSeqNum != fromSeqNum) {
            Region region = *i;

            region.endSeqNum = fromSeqNum;
            rexmitQueue.insert(i, region);
            i->beginSeqNum = fromSeqNum;
        }

        while (i != rexmitQueue.end() && seqLE(i->endSeqNum, toSeqNum)) {
            if (seqGE(i->beginSeqNum, fromSeqNum)) { // Search region in queue!
                found = true;
                i->sacked = true; // set sacked bit
                auto sendQueue = conn->getSendQueueForUpdate();
                sendQueue->sackedOut += i->endSeqNum - i->beginSeqNum;
            }

            i++;
        }

        if (i != rexmitQueue.end() && seqLess(i->beginSeqNum, toSeqNum) && seqLess(toSeqNum, i->endSeqNum)) {
            Region region = *i;

            region.endSeqNum = toSeqNum;
            region.sacked = true;
            auto sendQueue = conn->getSendQueueForUpdate();
            sendQueue->sackedOut += region.endSeqNum - region.beginSeqNum;
            rexmitQueue.insert(i, region);
            i->beginSeqNum = toSeqNum;
        }
    }

    if (!found)
        EV_DETAIL << "FAILED to set sacked bit for region: [" << fromSeqNum << ".." << toSeqNum << "). Not found in retransmission queue.\n";

    ASSERT(checkQueue());
}

bool TcpSackRexmitQueue::getSackedBit(uint32_t seqNum) const
{
    ASSERT(seqLE(begin, seqNum) && seqLE(seqNum, end));

    RexmitQueue::const_iterator i = rexmitQueue.begin();

    if (end == seqNum)
        return false;

    while (i != rexmitQueue.end() && seqLE(i->endSeqNum, seqNum))
        i++;

    ASSERT((i != rexmitQueue.end()) && seqLE(i->beginSeqNum, seqNum) && seqLess(seqNum, i->endSeqNum));

    return i->sacked;
}

uint32_t TcpSackRexmitQueue::getHighestSackedSeqNum() const
{
    for (RexmitQueue::const_reverse_iterator i = rexmitQueue.rbegin(); i != rexmitQueue.rend(); i++) {
        if (i->sacked)
            return i->endSeqNum;
    }

    return begin;
}

uint32_t TcpSackRexmitQueue::getHighestRexmittedSeqNum() const
{
    for (RexmitQueue::const_reverse_iterator i = rexmitQueue.rbegin(); i != rexmitQueue.rend(); i++) {
        if (i->rexmitted)
            return i->endSeqNum;
    }

    return begin;
}

uint32_t TcpSackRexmitQueue::checkRexmitQueueForSackedOrRexmittedSegments(uint32_t fromSeqNum) const
{
    ASSERT(seqLE(begin, fromSeqNum) && seqLE(fromSeqNum, end));

    if (rexmitQueue.empty() || (end == fromSeqNum))
        return 0;

    RexmitQueue::const_iterator i = rexmitQueue.begin();
    uint32_t bytes = 0;

    while (i != rexmitQueue.end() && seqLE(i->endSeqNum, fromSeqNum))
        i++;

    while (i != rexmitQueue.end() && ((i->sacked || i->rexmitted))) {
        ASSERT(seqLE(i->beginSeqNum, fromSeqNum) && seqLess(fromSeqNum, i->endSeqNum));

        bytes += (i->endSeqNum - fromSeqNum);
        fromSeqNum = i->endSeqNum;
        i++;
    }

    return bytes;
}

void TcpSackRexmitQueue::resetSackedBit()
{
    for (auto& elem : rexmitQueue)
        elem.sacked = false; // reset sacked bit
}

void TcpSackRexmitQueue::resetRexmittedBit()
{
    for (auto& elem : rexmitQueue)
        elem.rexmitted = false; // reset rexmitted bit
}

uint32_t TcpSackRexmitQueue::getTotalAmountOfSackedBytes() const
{
    uint32_t bytes = 0;

    for (const auto& elem : rexmitQueue) {
        if (elem.sacked)
            bytes += (elem.endSeqNum - elem.beginSeqNum);
    }

    return bytes;
}

uint32_t TcpSackRexmitQueue::getAmountOfSackedBytes(uint32_t fromSeqNum) const
{
    ASSERT(seqLE(begin, fromSeqNum) && seqLE(fromSeqNum, end));

    uint32_t bytes = 0;
    RexmitQueue::const_reverse_iterator i = rexmitQueue.rbegin();

    for (; i != rexmitQueue.rend() && seqLE(fromSeqNum, i->beginSeqNum); i++) {
        if (i->sacked)
            bytes += (i->endSeqNum - i->beginSeqNum);
    }

    if (i != rexmitQueue.rend()
        && seqLess(i->beginSeqNum, fromSeqNum) && seqLess(fromSeqNum, i->endSeqNum) && i->sacked)
    {
        bytes += (i->endSeqNum - fromSeqNum);
    }

    return bytes;
}

uint32_t TcpSackRexmitQueue::getNumOfDiscontiguousSacks(uint32_t fromSeqNum) const
{
    ASSERT(seqLE(begin, fromSeqNum) && seqLE(fromSeqNum, end));

    if (rexmitQueue.empty() || (fromSeqNum == end))
        return 0;

    RexmitQueue::const_iterator i = rexmitQueue.begin();
    uint32_t counter = 0;

    while (i != rexmitQueue.end() && seqLE(i->endSeqNum, fromSeqNum)) // search for seqNum
        i++;

    // search for discontiguous sacked regions
    bool prevSacked = false;

    while (i != rexmitQueue.end()) {
        if (i->sacked && !prevSacked)
            counter++;

        prevSacked = i->sacked;
        i++;
    }

    return counter;
}

void TcpSackRexmitQueue::checkSackBlock(uint32_t fromSeqNum, uint32_t& length, bool& sacked, bool& rexmitted) const
{
    ASSERT(seqLE(begin, fromSeqNum) && seqLess(fromSeqNum, end));

    RexmitQueue::const_iterator i = rexmitQueue.begin();

    while (i != rexmitQueue.end() && seqLE(i->endSeqNum, fromSeqNum)) // search for seqNum
        i++;

    ASSERT(i != rexmitQueue.end());
    ASSERT(seqLE(i->beginSeqNum, fromSeqNum) && seqLess(fromSeqNum, i->endSeqNum));

    length = (i->endSeqNum - fromSeqNum);
    sacked = i->sacked;
    rexmitted = i->rexmitted;
}

uint32_t TcpSackRexmitQueue::getLost() const
{
    uint32_t lost = 0;
    for (auto& region : rexmitQueue)
        if (region.lost)
            lost += region.endSeqNum - region.beginSeqNum;
    return lost;
}

uint32_t TcpSackRexmitQueue::getSacked() const
{
    uint32_t sacked = 0;
    for (auto& region : rexmitQueue)
        if (region.sacked)
            sacked += region.endSeqNum - region.beginSeqNum;
    return sacked;
}

uint32_t TcpSackRexmitQueue::getRetrans() const
{
    uint32_t retrans = 0;
    for (auto& region : rexmitQueue)
        if (region.rexmitted)
            retrans += region.endSeqNum - region.beginSeqNum;
    return retrans;
}

} // namespace tcp

} // namespace inet

