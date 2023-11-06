//
// Copyright (C) 2004 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


#ifndef __INET_TCPSINGLESINKAPP_H
#define __INET_TCPSINGLESINKAPP_H

#include "inet/applications/base/ApplicationBase.h"
#include "inet/common/socket/SocketMap.h"
#include "inet/common/lifecycle/ILifecycle.h"
#include "inet/common/lifecycle/LifecycleOperation.h"
#include "inet/transportlayer/contract/tcp/TcpSocket.h"

namespace inet {

/**
 * Accepts any number of incoming connections, and discards whatever arrives
 * on them.
 */
class INET_API TcpSingleSinkApp : public ApplicationBase, public TcpSocket::ICallback
{
  protected:
    long bytesRcvd = 0;
    TcpSocket socket;
    cMessage *readDelayTimer = nullptr;

  protected:
    virtual void initialize(int stage) override;
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void finish() override;
    virtual void refreshDisplay() const override;

    // TcpSocket::ICallback methods:
    virtual void socketDataArrived(TcpSocket *socket, Packet *packet, bool urgent) override;
    virtual void socketAvailable(TcpSocket *socket, TcpAvailableInfo *availableInfo) override;
    virtual void socketEstablished(TcpSocket *socket) override;
    virtual void socketPeerClosed(TcpSocket *socket) override;
    virtual void socketClosed(TcpSocket *socket) override;
    virtual void socketFailure(TcpSocket *socket, int code) override;
    virtual void socketStatusArrived(TcpSocket *socket, TcpStatusInfo *status) override;
    virtual void socketDeleted(TcpSocket *socket) override;

    // OperationalMixin methods:
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void handleStartOperation(LifecycleOperation *operation) override;
    virtual void handleStopOperation(LifecycleOperation *operation) override;
    virtual void handleCrashOperation(LifecycleOperation *operation) override;

    virtual void handleSelfMessage(cMessage *msg);

    // READ support:
    virtual void sendOrScheduleReadCommandIfNeeded();

  public:
    TcpSingleSinkApp();
    ~TcpSingleSinkApp();
};

} // namespace inet

#endif
