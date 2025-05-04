#include <iostream>
#include <algorithm>
#include <string>
#include <cctype>
#include <mutex>
#include <chrono>
#include <Windows.h>

#include <httpengine/HttpFilteringEngineControl.hpp>
#include <sqlite_orm/sqlite_orm.h>
#include <boost/algorithm/string.hpp>
#include <logger.h>

namespace http_transaction {

    std::vector<std::string> binaries_check;    // array of binaries for check

    std::string transaction_storage_path;       // path to store transactions

// Define a structure for the database table
struct HttpTransaction {
    int id; // Primary key
    std::string requestHeaders;
    std::vector<char> requestBody;  // binary format
    std::string responseHeaders;
    std::vector<char> responseBody; // binary format
    std::string timestamp;
};

using namespace sqlite_orm;

// Function to store HTTP request and response in SQLite
void storeHttpTransaction(
    const std::string& requestHeaders,
    const std::vector<char>& requestBody,
    const std::string& responseHeaders,
    const std::vector<char>& responseBody
) {
    // Create a storage object for SQLite
    auto storage = sqlite_orm::make_storage(
        transaction_storage_path,
        sqlite_orm::make_table(
            "http_transactions",
            sqlite_orm::make_column("id", &HttpTransaction::id, primary_key().autoincrement()),
            sqlite_orm::make_column("request_headers", &HttpTransaction::requestHeaders),
            sqlite_orm::make_column("request_body", &HttpTransaction::requestBody),
            sqlite_orm::make_column("response_headers", &HttpTransaction::responseHeaders),
            sqlite_orm::make_column("response_body", &HttpTransaction::responseBody),
            sqlite_orm::make_column("timestamp", &HttpTransaction::timestamp)
        )
    );

    // Sync the schema (creates the table if it doesn't exist)
    storage.sync_schema();

    // Get the current timestamp
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string timestamp = std::ctime(&now);
    timestamp.pop_back(); // Remove the trailing newline character

    // Insert the HTTP transaction into the database
    HttpTransaction transaction{
        0, // ID will be auto-incremented
        requestHeaders,
        requestBody,
        responseHeaders,
        responseBody,
        timestamp
    };

    storage.insert(transaction);

    std::cout << "[" << timestamp << "] transaction stored" << std::endl;
}

bool stringContain(std::string str1, std::string str2) 
{
    std::transform(str1.begin(), str1.end(), str1.begin(),
    [](unsigned char c){ return std::tolower(c); });

    std::transform(str2.begin(), str2.end(), str2.begin(),
    [](unsigned char c){ return std::tolower(c); });

    return str1.find(str2) != std::string::npos; 
}

static void OnHttpMessageBegin(
    const char* requestHeaders, 
    const uint32_t requestHeadersLength,
    const char* requestBody,
    const uint32_t requestBodyLength, 
	const char* responseHeaders, 
    const uint32_t responseHeadersLength,
    const char* responseBody, 
    const uint32_t responseBodyLength,
    uint32_t* nextAction, 
    const CustomResponseStreamWriter customBlockResponseStreamWriter
    ) {

    // Set the next action for the HTTP message
    // 0: Allow without inspection, but still monitor the response if it comes.
    // 1: Allow and inspect the payload.
    // 2: Block the request.
    // 3: Allow without inspection for both request and response.
    *nextAction = 1;
}

// Create object for mutex
std::mutex mtx;

static void OnHttpMessageEnd(
    const char* requestHeaders, 
    const uint32_t requestHeadersLength,
    const char* requestBody,
    const uint32_t requestBodyLength, 
	const char* responseHeaders, 
    const uint32_t responseHeadersLength,
    const char* responseBody, 
    const uint32_t responseBodyLength,
    bool* shouldBlock, 
    const CustomResponseStreamWriter customBlockResponseStreamWriter
    ) {
    try {
        std::string requestHeadersStr(requestHeaders, requestHeadersLength);
        std::vector<char> requestBodyStr(requestBody, requestBody + requestBodyLength);
        std::string responseHeadersStr(responseHeaders, responseHeadersLength);
        std::vector<char> responseBodyStr(responseBody, responseBody + responseBodyLength);

        // Lock the thread using lock
        mtx.lock();

        // Store the HTTP transaction in SQLite
        storeHttpTransaction(requestHeadersStr, requestBodyStr, responseHeadersStr, responseBodyStr);
        
        // Release the lock using unlock()
        mtx.unlock();

    } catch (const std::exception& e) {
        std::cerr << "Error storing HTTP transaction: " << e.what() << std::endl;
    }

    *shouldBlock = false;
}

bool onFirewallBinaryCheck(const char* binaryAbsolutePath, const size_t binaryAbsolutePathLength)
{
    for (auto binary : binaries_check) {
        if (stringContain(std::string(binaryAbsolutePath, binaryAbsolutePathLength), binary)) {
            return true;
        }
        else {
            continue;
        }
    }

    return false;
}

static void OnEngineMessage(
    const char* Message, 
    const uint32_t MessageLength
){
    //LOG_MSG().log_message(std::string(Message, MessageLength));
}

}

bool is_mandatory_high_process()
{
    DWORD dwLengthNeeded = 0;
    bool result = false;
    GetTokenInformation(GetCurrentProcessToken(), TokenIntegrityLevel, NULL, 0, &dwLengthNeeded);
    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, dwLengthNeeded);
    if (GetTokenInformation(GetCurrentProcessToken(), TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded))
    {
        auto dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid)-1));
        if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        {
            result = true;
        }
    }
    LocalFree(pTIL);
    return result;
}

int main(int argc, char* argv[]) {
    // init logger
    logger::InitBoostLogFilter();

    setlocale(LC_ALL, "Russian");

    if (!is_mandatory_high_process()) {
        std::cout << "Sorry, your need run program as administrator for working with system CA store!" << std::endl;
        return -1;
    }

    http_transaction::binaries_check = {
        "browser",
        "firefox",
        "msedge",
        "opera",
        "brave",
        "vivaldi",
        "iexplore"
    };
    
    auto pem_path = std::string("cacert-2025-02-25.pem");

    http_transaction::transaction_storage_path = "transactions.sqlite";

    auto control = te::httpengine::HttpFilteringEngineControl(
        http_transaction::onFirewallBinaryCheck,
        pem_path,
        1111,
        2222,
        std::thread::hardware_concurrency() / 2,
        http_transaction::OnHttpMessageBegin,
        http_transaction::OnHttpMessageEnd,
        http_transaction::OnEngineMessage,
        http_transaction::OnEngineMessage,
        http_transaction::OnEngineMessage
    );

    control.Start();
    
    while (control.IsRunning())
    {
        _sleep(5000);
    }

    return 0;
}


