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

#ifndef __INET_ADDITIVESCRAMBLING_H
#define __INET_ADDITIVESCRAMBLING_H

#include "inet/common/ShortBitVector.h"
#include "inet/physicallayer/wireless/common/contract/bitlevel/IScrambler.h"

namespace inet {
namespace physicallayer {

class INET_API AdditiveScrambling : public IScrambling
{
  protected:
    ShortBitVector seed;
    ShortBitVector generatorPolynomial;

  public:
    AdditiveScrambling(const ShortBitVector& seed, const ShortBitVector& generatorPolynomial);

    virtual std::ostream& printToStream(std::ostream& stream, int level, int evFlags = 0) const override;

    const ShortBitVector& getGeneratorPolynomial() const { return generatorPolynomial; }
    const ShortBitVector& getSeed() const { return seed; }
};

} /* namespace physicallayer */
} /* namespace inet */

#endif

