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

