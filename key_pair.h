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

#ifndef O1C_GEN_KEY_PAIR_H
#define O1C_GEN_KEY_PAIR_H

#include "secure_buffer.h"

struct key_pair {
    secure_buffer sk;
    secure_buffer pk;

    key_pair() noexcept;

    static key_pair generate() noexcept;

    friend std::ostream &operator<<(std::ostream &os, const key_pair &pair);
};


#endif //O1C_GEN_KEY_PAIR_H
