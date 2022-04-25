/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

enum class DataType
{
    CString
};

struct CString
{
    const char *m_data;
    size_t m_size;

    CString(const char *data, size_t size)
        : m_data(data), m_size(size)
    {
    }
};

class FuzzingDataProvider
{
public:
    void feed(const uint8_t *data, size_t size)
    {
        m_data = data;
        m_size = size;
        m_off = 0;
    }

    bool empty() const
    {
        return !capacity();
    }

    size_t capacity() const
    {
        return m_size - m_off;
    }

    template <typename DataType>
    std::optional<DataType> consume(size_t hint = 0)
    {
        if (empty() || capacity() < sizeof(DataType))
            return {};

        auto ret = *data<DataType>();
        m_off += sizeof(DataType);

        return ret;
    }

private:
    // TODO(goose): limit the types we can use here.
    template <typename DataType>
    DataType *data()
    {
        return (DataType *)(&m_data[m_off]);
    }

    const uint8_t *m_data{nullptr};
    size_t m_size{0};
    size_t m_off{0};
};

class AbstractFuzzer
{
public:
    virtual void fuzz(const uint8_t *data, size_t size) = 0;
    virtual ~AbstractFuzzer();

protected:
    FuzzingDataProvider m_data_provider;
    bool m_debug{false};
};
