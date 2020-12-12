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

#include <signcrypt_tbsbr.h>
#include "key_pair.h"

key_pair::key_pair() noexcept: sk(crypto_signcrypt_tbsbr_SECRETKEYBYTES), pk(crypto_signcrypt_tbsbr_PUBLICKEYBYTES) {
    crypto_signcrypt_tbsbr_keygen(pk.data(), sk.data());
}

std::ostream &operator<<(std::ostream &os, const key_pair &pair) {
    os << "sk: " << pair.sk << " pk: " << pair.pk;
    return os;
}
