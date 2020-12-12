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

#ifndef O1C_GEN_SECURE_BUFFER_H
#define O1C_GEN_SECURE_BUFFER_H

#include <string>
#include <ostream>

class secure_buffer {
    unsigned char *buf;
    size_t len;

public:
    secure_buffer() noexcept;

    explicit secure_buffer(size_t len) noexcept;

    // copy constructor for string literals
    explicit secure_buffer(const std::string &string) noexcept;

    // copy constructor
    secure_buffer(const secure_buffer &that) noexcept;

    // move constructor
    secure_buffer(secure_buffer &&that) noexcept;

    virtual ~secure_buffer() noexcept;

    // assignment operator (swap)
    secure_buffer &operator=(secure_buffer that) noexcept;

    // decode and copy constructor, may throw an exception
    static secure_buffer from_hex(const std::string &hex);

    size_t size() const noexcept {
        return len;
    }

    unsigned char *data() const noexcept {
        return buf;
    }

    // fill this buffer with cryptographically secure random bytes
    void randomize() noexcept;

    // TODO: expose mprotect stuff

    friend std::ostream &operator<<(std::ostream &os, const secure_buffer &buffer);
};


#endif //O1C_GEN_SECURE_BUFFER_H
