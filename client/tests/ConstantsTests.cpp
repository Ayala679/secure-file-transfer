#include "Constants.h"
#include "Errors.h"
#include "TestFramework.h"

#include <type_traits>

static_assert(protocol::REQUEST_HEADER_SIZE == 23);
static_assert(protocol::RESPONSE_HEADER_SIZE == 7);
static_assert(protocol::PUBLIC_KEY_PAYLOAD_SIZE == 415);
static_assert(protocol::FILE_PACKET_HEADER_SIZE == 267);
static_assert(protocol::FILE_RECEIVED_PAYLOAD_SIZE == 279);
static_assert(crypto::AES_KEY_SIZE * 8 == 256);

static_assert(static_cast<int>(protocol::RequestCode::Register) == 825);
static_assert(static_cast<int>(protocol::RequestCode::CrcAbort) == 902);
static_assert(static_cast<int>(protocol::ResponseCode::RegisterOk) == 1600);
static_assert(static_cast<int>(protocol::ResponseCode::GeneralError) == 1607);

static_assert(std::is_base_of_v<ServerError, ProtocolError>);
static_assert(std::is_base_of_v<ClientError, FatalError>);
static_assert(!std::is_base_of_v<ServerError, FatalError>);

TEST_CASE(protocol_error_is_retryable)
{
    CHECK_THROWS(throw ProtocolError("bad response"), ServerError);
    CHECK_THROWS(throw FatalError("no config"), ClientError);
}
