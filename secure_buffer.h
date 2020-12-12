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
    uint8_t *buf;
    size_t len;

public:
    explicit secure_buffer(size_t len) noexcept;

    explicit secure_buffer(const std::string &string) noexcept;

    secure_buffer(const secure_buffer &that) noexcept;

    secure_buffer(secure_buffer &&that) noexcept;

    virtual ~secure_buffer() noexcept;

    secure_buffer &operator=(secure_buffer that) noexcept;

    size_t size() const noexcept {
        return len;
    }

    uint8_t *data() const noexcept {
        return buf;
    }

    char *c_str() const noexcept {
        return reinterpret_cast<char *>(buf);
    }

    std::string string() const noexcept {
        return std::string(buf, buf + len);
    }

    void randomize() noexcept;

    friend std::ostream &operator<<(std::ostream &os, const secure_buffer &buffer);

};


#endif //O1C_GEN_SECURE_BUFFER_H
