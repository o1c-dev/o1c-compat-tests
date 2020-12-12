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

#include <iostream>
#include <sodium.h>

#include "secure_buffer.h"
#include "key_pair.h"
#include "sealed_data.h"

int main() {
    if (sodium_init() == -1) {
        return -1;
    }

    auto alice = key_pair();
    auto aliceId = secure_buffer("Alice");
    auto bob = key_pair();
    auto bobId = secure_buffer("Bob");

    auto info = secure_buffer("whole bean");
    auto msg = secure_buffer(
            "Ristretto is traditionally a short shot of espresso coffee made with the normal amount of ground coffee "
            "but extracted with about half the amount of water in the same amount of time by using a finer grind. "
            "This produces a concentrated shot of coffee per volume. Just pulling a normal shot short will produce a "
            "weaker shot and is not a Ristretto as some believe.");
    auto sealed = seal(aliceId, bobId, info, alice.sk, bob.pk, msg);
    std::cout << "Alice " << alice << std::endl
              << "Bob " << bob << std::endl
              << "Sealed " << sealed << std::endl;

    auto unsealed = unseal(aliceId, bobId, info, alice.pk, bob.sk, sealed);
    std::cout << unsealed.string() << std::endl;

    return 0;
}
