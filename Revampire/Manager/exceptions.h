#pragma once
#include <string>
#include <exception>

class Exception : public std::exception {
protected:
    std::string message;
public:
    Exception(const char* message) {
        this->message = std::string(message);
    };
   Exception(const std::string& message) {
        this->message = message;
    };
    const char* what() const throw () {
        return this->message.c_str();
    };
};

class DisasmException : public Exception
{
public:
    DisasmException(const char* message):Exception(message){};
    DisasmException(const std::string& message) :Exception(message) {};
};

class VmpTraceException :public Exception
{
public:
    VmpTraceException(const char* message) :Exception(message) {};
    VmpTraceException(const std::string& message) :Exception(message) {};
};

//vmp°æ±¾´íÎó

class VmpVersionException :public Exception
{
public:
    VmpVersionException(const char* message) :Exception(message) {};
    VmpVersionException(const std::string& message) :Exception(message) {};
};

class GhidraException :public Exception
{
public:
    GhidraException(const char* message) :Exception(message) {};
    GhidraException(const std::string& message) :Exception(message) {};
};