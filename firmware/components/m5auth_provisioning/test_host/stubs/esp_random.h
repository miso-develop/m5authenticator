#pragma once

#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

void esp_fill_random(void* buffer, std::size_t length);

#ifdef __cplusplus
}
#endif
