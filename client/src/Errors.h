#pragma once

#include <stdexcept>
#include <string>

class ClientError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class ServerError : public ClientError {
public:
    using ClientError::ClientError;
};

class ProtocolError : public ServerError {
public:
    using ServerError::ServerError;
};

class FatalError : public ClientError {
public:
    using ClientError::ClientError;
};

class FileError : public ClientError {
public:
    using ClientError::ClientError;
};
