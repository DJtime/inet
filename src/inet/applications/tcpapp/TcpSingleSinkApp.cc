//
// Copyright (C) 2004 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


#include "inet/applications/tcpapp/TcpSingleSinkApp.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/lifecycle/NodeStatus.h"
#include "inet/common/packet/Message.h"
#include "inet/common/socket/SocketTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"

namespace inet {

Define_Module(TcpSingleSinkApp);

TcpSingleSinkApp::TcpSingleSinkApp()
{
}

TcpSingleSinkApp::~TcpSingleSinkApp()
{
}

void TcpSingleSinkApp::initialize(int stage)
{
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        bytesRcvd = 0;
        WATCH(bytesRcvd);
        readDelayTimer = new cMessage("readDelayTimer");
    }
}

void TcpSingleSinkApp::refreshDisplay() const
{
    ApplicationBase::refreshDisplay();

    std::ostringstream os;
    os << TcpSocket::stateName(socket.getState()) << "\nrcvd: " << bytesRcvd << " bytes";
    getDisplayString().setTagArg("t", 0, os.str().c_str());
}

void TcpSingleSinkApp::finish()
{
    ApplicationBase::finish();

    recordScalar("bytesRcvd", bytesRcvd);
}

void TcpSingleSinkApp::handleMessageWhenUp(cMessage *msg)
{
    if(msg->isSelfMessage()) {
        handleSelfMessage(msg);
    }
    else if (socket.belongsToSocket(msg))
        socket.processMessage(msg);
    else {
//        throw cRuntimeError("Unknown incoming message: '%s'", msg->getName());
        EV_ERROR << "message " << msg->getFullName() << "(" << msg->getClassName() << ") arrived for unknown socket \n";
        delete msg;
    }
}

void TcpSingleSinkApp::handleSelfMessage(cMessage *timer)
{
    if (timer == readDelayTimer) {
        // send read message to TCP
        socket.read(par("readSize"));
    }
    else
        throw cRuntimeError("Model error: unknown timer message arrived");
}

void TcpSingleSinkApp::sendOrScheduleReadCommandIfNeeded()
{
    if (!socket.getAutoRead() && socket.isOpen()) {
        simtime_t delay = par("readDelay");
        if (delay >= SIMTIME_ZERO) {
            scheduleAfter(delay, readDelayTimer);
        }
        else {
            // send read message to TCP
            socket.read(par("readSize"));
        }
    }
}

void TcpSingleSinkApp::handleStartOperation(LifecycleOperation *operation)
{
    const char *localAddress = par("localAddress");
    int localPort = par("localPort");
    bool autoRead = par("autoRead");

    socket.setOutputGate(gate("socketOut"));
    socket.setCallback(this);
    socket.bind(localAddress[0] ? L3Address(localAddress) : L3Address(), localPort);
    socket.setAutoRead(autoRead);
    socket.listenOnce();
}

void TcpSingleSinkApp::handleStopOperation(LifecycleOperation *operation)
{
    socket.close();
    delayActiveOperationFinish(par("stopOperationTimeout"));
}

void TcpSingleSinkApp::handleCrashOperation(LifecycleOperation *operation)
{
    // TODO always?
    if (operation->getRootModule() != getContainingNode(this))
        socket.destroy();
}

void TcpSingleSinkApp::socketDataArrived(TcpSocket *socket, Packet *pk, bool urgent)
{
    ASSERT(socket == &this->socket);

    long packetLength = pk->getByteLength();
    bytesRcvd += packetLength;

    emit(packetReceivedSignal, pk);
    delete pk;
    sendOrScheduleReadCommandIfNeeded();
}

void TcpSingleSinkApp::socketAvailable(TcpSocket *socket, TcpAvailableInfo *availableInfo)
{
    ASSERT(socket == &this->socket);
}

void TcpSingleSinkApp::socketEstablished(TcpSocket *socket)
{
    ASSERT(socket == &this->socket);
    bytesRcvd = 0;
    sendOrScheduleReadCommandIfNeeded();
}

void TcpSingleSinkApp::socketPeerClosed(TcpSocket *socket)
{
    ASSERT(socket == &this->socket);
    socket->close();
}

void TcpSingleSinkApp::socketClosed(TcpSocket *socket)
{
    ASSERT(socket == &this->socket);
}

void TcpSingleSinkApp::socketFailure(TcpSocket *socket, int code)
{
    ASSERT(socket == &this->socket);
}

void TcpSingleSinkApp::socketStatusArrived(TcpSocket *socket, TcpStatusInfo *status)
{
    ASSERT(socket == &this->socket);
}

void TcpSingleSinkApp::socketDeleted(TcpSocket *socket)
{
    ASSERT(socket == &this->socket);
    socket->renewSocket();
}

} // namespace inet

