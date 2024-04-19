#include "Public.h"

size_t AlignByMemory(size_t originValue, size_t alignment)
{
    size_t reminder = originValue / alignment;
    size_t mod = originValue % alignment;
    if (mod != 0) {
        reminder += 1;
    }
    return reminder * alignment;
}