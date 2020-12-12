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

#ifndef O1C_GEN_SEALED_DATA_H
#define O1C_GEN_SEALED_DATA_H

#include "secure_buffer.h"

struct sealed_data {
    secure_buffer nonce;
    secure_buffer mac;
    secure_buffer sig;
    secure_buffer ct;

    sealed_data(secure_buffer nonce, secure_buffer mac, secure_buffer sig, secure_buffer ct) noexcept
            : nonce(std::move(nonce)), mac(std::move(mac)), sig(std::move(sig)), ct(std::move(ct)) {}

    friend std::ostream &operator<<(std::ostream &os, const sealed_data &data);
};

sealed_data seal(const secure_buffer &sender_id, const secure_buffer &recipient_id, const secure_buffer &info,
                 const secure_buffer &sender_sk, const secure_buffer &recipient_pk, const secure_buffer &msg);

secure_buffer unseal(const secure_buffer &sender_id, const secure_buffer &recipient_id, const secure_buffer &info,
                     const secure_buffer &sender_pk, const secure_buffer &recipient_sk, const sealed_data &data);

struct sealed_data_exception : std::exception {
};

#endif //O1C_GEN_SEALED_DATA_H
