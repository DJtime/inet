//
// Copyright (C) 2014 OpenSim Ltd.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

#include "inet/mobility/contract/IMobility.h"
#include "inet/physicallayer/wireless/apskradio/bitlevel/ApskEncoder.h"
#include "inet/physicallayer/wireless/apskradio/bitlevel/ApskLayeredTransmitter.h"
#include "inet/physicallayer/wireless/apskradio/bitlevel/ApskModulator.h"
#include "inet/physicallayer/wireless/apskradio/packetlevel/ApskPhyHeader_m.h"
#include "inet/physicallayer/wireless/common/analogmodel/bitlevel/LayeredTransmission.h"
#include "inet/physicallayer/wireless/common/analogmodel/bitlevel/ScalarSignalAnalogModel.h"
#include "inet/physicallayer/wireless/common/contract/bitlevel/ISignalAnalogModel.h"
#include "inet/physicallayer/wireless/common/contract/packetlevel/IRadio.h"

namespace inet {

namespace physicallayer {

Define_Module(ApskLayeredTransmitter);

ApskLayeredTransmitter::ApskLayeredTransmitter() :
    levelOfDetail(static_cast<LevelOfDetail>(-1)),
    encoder(nullptr),
    modulator(nullptr),
    pulseShaper(nullptr),
    digitalAnalogConverter(nullptr),
    power(W(NaN)),
    bitrate(bps(NaN)),
    bandwidth(Hz(NaN)),
    centerFrequency(Hz(NaN))
{
}

void ApskLayeredTransmitter::initialize(int stage)
{
    if (stage == INITSTAGE_LOCAL) {
        encoder = dynamic_cast<const IEncoder *>(getSubmodule("encoder"));
        modulator = dynamic_cast<const IModulator *>(getSubmodule("modulator"));
        pulseShaper = dynamic_cast<const IPulseShaper *>(getSubmodule("pulseShaper"));
        digitalAnalogConverter = dynamic_cast<const IDigitalAnalogConverter *>(getSubmodule("digitalAnalogConverter"));
        power = W(par("power"));
        bitrate = bps(par("bitrate"));
        if (bitrate <= bps(0))
            throw cRuntimeError("Invalid birate: %s", bitrate.str().c_str());
        bandwidth = Hz(par("bandwidth"));
        centerFrequency = Hz(par("centerFrequency"));
        const char *levelOfDetailStr = par("levelOfDetail");
        if (strcmp("packet", levelOfDetailStr) == 0)
            levelOfDetail = PACKET_DOMAIN;
        else if (strcmp("bit", levelOfDetailStr) == 0)
            levelOfDetail = BIT_DOMAIN;
        else if (strcmp("symbol", levelOfDetailStr) == 0)
            levelOfDetail = SYMBOL_DOMAIN;
        else if (strcmp("sample", levelOfDetailStr) == 0)
            levelOfDetail = SAMPLE_DOMAIN;
        else
            throw cRuntimeError("Unknown level of detail='%s'", levelOfDetailStr);
        if (levelOfDetail >= BIT_DOMAIN && !encoder)
            throw cRuntimeError("Encoder not configured");
        if (levelOfDetail >= SYMBOL_DOMAIN && !modulator)
            throw cRuntimeError("Modulator not configured");
        if (levelOfDetail >= SAMPLE_DOMAIN && !pulseShaper)
            throw cRuntimeError("Pulse shaper not configured");
    }
}

std::ostream& ApskLayeredTransmitter::printToStream(std::ostream& stream, int level, int evFlags) const
{
    stream << "ApskLayeredTransmitter";
    if (level <= PRINT_LEVEL_DETAIL)
        stream << EV_FIELD(levelOfDetail)
               << EV_FIELD(centerFrequency);
    if (level <= PRINT_LEVEL_TRACE)
        stream << EV_FIELD(encoder, printFieldToString(encoder, level + 1, evFlags))
               << EV_FIELD(modulator, printFieldToString(modulator, level + 1, evFlags))
               << EV_FIELD(pulseShaper, printFieldToString(pulseShaper, level + 1, evFlags))
               << EV_FIELD(digitalAnalogConverter, printFieldToString(digitalAnalogConverter, level + 1, evFlags))
               << EV_FIELD(power)
               << EV_FIELD(bitrate)
               << EV_FIELD(bandwidth);
    return stream;
}

const ITransmissionPacketModel *ApskLayeredTransmitter::createPacketModel(const Packet *packet) const
{
    return new TransmissionPacketModel(check_and_cast<const Packet *>(packet), bitrate);
}

const ITransmissionBitModel *ApskLayeredTransmitter::createBitModel(const ITransmissionPacketModel *packetModel) const
{
    if (levelOfDetail >= BIT_DOMAIN)
        return encoder->encode(packetModel);
    else {
        auto packet = packetModel->getPacket();
        b netHeaderLength = packet->peekAtFront<ApskPhyHeader>()->getChunkLength();
        b netDataLength = packet->getTotalLength() - netHeaderLength;
        if (encoder) {
            const ApskEncoder *apskEncoder = check_and_cast<const ApskEncoder *>(encoder);
            const ConvolutionalCode *forwardErrorCorrection = apskEncoder->getCode()->getConvolutionalCode();
            if (forwardErrorCorrection == nullptr)
                return new TransmissionBitModel(netHeaderLength, bitrate, netDataLength, bitrate, nullptr, forwardErrorCorrection, nullptr, nullptr);
            else {
                b grossHeaderLength = b(forwardErrorCorrection->getEncodedLength(b(netHeaderLength).get()));
                b grossDataLength = b(forwardErrorCorrection->getEncodedLength(b(netDataLength).get()));
                bps grossBitrate = bitrate / forwardErrorCorrection->getCodeRate();
                return new TransmissionBitModel(grossHeaderLength, grossBitrate, grossDataLength, grossBitrate, nullptr, forwardErrorCorrection, nullptr, nullptr);
            }
        }
        else
            return new TransmissionBitModel(netHeaderLength, bitrate, netDataLength, bitrate, nullptr, nullptr, nullptr, nullptr);
    }
}

const ITransmissionSymbolModel *ApskLayeredTransmitter::createSymbolModel(const ITransmissionBitModel *bitModel) const
{
    if (levelOfDetail >= SYMBOL_DOMAIN)
        return modulator->modulate(bitModel);
    else
        return new TransmissionSymbolModel(-1, NaN, -1, NaN, nullptr, modulator->getModulation(), modulator->getModulation());
}

const ITransmissionSampleModel *ApskLayeredTransmitter::createSampleModel(const ITransmissionSymbolModel *symbolModel) const
{
    if (levelOfDetail >= SAMPLE_DOMAIN)
        return pulseShaper->shape(symbolModel);
    else
        return nullptr;
}

const ITransmissionAnalogModel *ApskLayeredTransmitter::createAnalogModel(const ITransmissionPacketModel *packetModel, const ITransmissionBitModel *bitModel, const ITransmissionSampleModel *sampleModel) const
{
    if (digitalAnalogConverter) {
        if (sampleModel == nullptr)
            throw cRuntimeError("Digital analog converter needs sample domain representation");
        else
            return digitalAnalogConverter->convertDigitalToAnalog(sampleModel);
    }
    else {
        simtime_t duration = packetModel->getPacket()->getBitLength() / bitrate.get();
        return new ScalarTransmissionSignalAnalogModel(duration, centerFrequency, bandwidth, power);
    }
}

const ITransmission *ApskLayeredTransmitter::createTransmission(const IRadio *transmitter, const Packet *packet, const simtime_t startTime) const
{
    const ITransmissionPacketModel *packetModel = createPacketModel(packet);
    const ITransmissionBitModel *bitModel = createBitModel(packetModel);
    const ITransmissionSymbolModel *symbolModel = createSymbolModel(bitModel);
    const ITransmissionSampleModel *sampleModel = createSampleModel(symbolModel);
    const ITransmissionAnalogModel *analogModel = createAnalogModel(packetModel, bitModel, sampleModel);
    // assuming movement and rotation during transmission is negligible
    IMobility *mobility = transmitter->getAntenna()->getMobility();
    const simtime_t endTime = startTime + analogModel->getDuration();
    const Coord& startPosition = mobility->getCurrentPosition();
    const Coord& endPosition = mobility->getCurrentPosition();
    const Quaternion& startOrientation = mobility->getCurrentAngularPosition();
    const Quaternion& endOrientation = mobility->getCurrentAngularPosition();
    return new LayeredTransmission(packetModel, bitModel, symbolModel, sampleModel, analogModel, transmitter, packet, startTime, endTime, -1, -1, -1, startPosition, endPosition, startOrientation, endOrientation);
}

} // namespace physicallayer

} // namespace inet

