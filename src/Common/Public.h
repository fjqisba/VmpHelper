#pragma once
#include <string>

template<typename T>
class Singleton {
public:
    static T& Instance() {
        static T instance;
        return instance;
    }
    Singleton(const Singleton&) = delete;
    Singleton& operator=(const Singleton&) = delete;
protected:
    Singleton() {}
    ~Singleton() {}
};

size_t AlignByMemory(size_t originValue, size_t alignment);

template<typename T>
T readFromMemory(unsigned char* buffer) {
    T result;
    std::memcpy(&result, buffer, sizeof(T));
    return result;
}