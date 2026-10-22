#pragma once

#include <stdexcept>
#include <string>

// ServerError (and ProtocolError) are retried, FatalError ends the program
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

// a local file that cannot be sent; the client skips it and goes on
class FileError : public ClientError {
public:
    using ClientError::ClientError;
};
