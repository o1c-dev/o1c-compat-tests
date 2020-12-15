/*
 * Copyright 2020 Matt Sicker
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef O1C_GEN_SIGNCRYPT_H
#define O1C_GEN_SIGNCRYPT_H

#include <array>
#include <vector>
#include <string>

namespace o1c {

    typedef std::array<uint8_t, 32> secret_key;
    typedef std::array<uint8_t, 32> public_key;
    typedef std::vector<uint8_t> buffer;

    secret_key parse_secret_key(const std::string &hex);

    public_key gen_public_key(const secret_key &key);

    public_key parse_public_key(const std::string &hex);

    buffer signcrypt(const buffer &sender_id, const buffer &recipient_id, const buffer &info,
                     const secret_key &sender_key, const public_key &recipient_key, const buffer &message);

    buffer unsigncrypt(const buffer &sender_id, const buffer &recipient_id, const buffer &info,
                       const public_key &sender_key, const secret_key &recipient_key, const buffer &ciphertext);
}

#endif //O1C_GEN_SIGNCRYPT_H
