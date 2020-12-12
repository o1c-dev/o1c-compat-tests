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

#include "secure_buffer.h"
#include <sodium.h>
#include <memory>

secure_buffer::secure_buffer(const size_t len) noexcept: len(len) {
    buf = static_cast<uint8_t *>(sodium_malloc(len));
}


secure_buffer::secure_buffer(const std::string &string) noexcept: len(string.size()) {
    buf = static_cast<uint8_t *>(sodium_malloc(len));
    std::copy(string.begin(), string.end(), buf);
}

secure_buffer::secure_buffer(const secure_buffer &that) noexcept: len(that.len) {
    buf = static_cast<uint8_t *>(sodium_malloc(len));
    std::memcpy(buf, that.buf, len);
}

secure_buffer::secure_buffer(secure_buffer &&that) noexcept {
    len = that.len;
    buf = that.buf;
    that.buf = nullptr;
}

secure_buffer::~secure_buffer() noexcept {
    if (buf) {
        sodium_free(buf);
        buf = nullptr;
    }
}

secure_buffer &secure_buffer::operator=(secure_buffer that) noexcept {
    std::swap(len, that.len);
    std::swap(buf, that.buf);
    return *this;
}

std::ostream &operator<<(std::ostream &os, const secure_buffer &buffer) {
    auto hex = secure_buffer(buffer.size() * 2 + 1);
    sodium_bin2hex(hex.c_str(), hex.size(), buffer.data(), buffer.size());
    os << hex.c_str();
    return os;
}

void secure_buffer::randomize() noexcept {
    randombytes_buf(buf, len);
}
