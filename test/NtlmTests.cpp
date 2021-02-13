#include "ntlm/ntlm.h"

#include "catch.hpp"
#include "ApprovalTests.hpp"

using namespace ApprovalTests;

const std::string type2_message = "TlRMTVNTUAACAAAADAAMADAAAAABAoEAASNFZ4mrze8AAAAAAAAAAGIAYgA8AAAARABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABQAZABvAG0AYQBpAG4ALgBjAG8AbQADACIAcwBlAHIAdgBlAHIALgBkAG8AbQBhAGkAbgAuAGMAbwBtAAAAAAA=";

TEST_CASE("type1 msg, Test domain, Test host, V1")
{
    Approvals::verify(make_type1_msg("Test domain", "Test host", NtlmResponseType::v1));
}

TEST_CASE("type1 msg, Test domain, Test host, V2")
{
    Approvals::verify(make_type1_msg("Test domain", "Test host", NtlmResponseType::v2));
}

TEST_CASE("type1 msg, Test domain, Test host, V2Session")
{
    Approvals::verify(make_type1_msg("Test domain", "Test host", NtlmResponseType::v2Session));
}

TEST_CASE("type3 msg, test username, test password, test domain, test host, V1")
{
    Approvals::verify(
            make_type3_msg("Test username", "Test password", "Test domain", "Test host", type2_message, NtlmResponseType::v1));
}

TEST_CASE("type3 msg, test username, test password, test domain, test host, V2")
{
    Approvals::verify(
            make_type3_msg("Test username", "Test password", "Test domain", "Test host", type2_message, NtlmResponseType::v2));
}

TEST_CASE("type3 msg, test username, test password, test domain, test host, V2Session")
{
    Approvals::verify(make_type3_msg("Test username", "Test password", "Test domain", "Test host", type2_message,
                                     NtlmResponseType::v2Session));
}
