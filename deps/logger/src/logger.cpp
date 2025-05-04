#include <logger.h>
#include <boost/log/trivial.hpp> 
#include <boost/log/core.hpp>        
#include <boost/log/expressions.hpp> 
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/manipulators/add_value.hpp>
#include <boost/date_time.hpp>
#include <string>

namespace logger {
using namespace std::literals;
namespace logging = boost::log;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;
namespace expr = boost::log::expressions;
namespace attrs = boost::log::attributes;

BOOST_LOG_ATTRIBUTE_KEYWORD(timestamp, "TimeStamp", boost::posix_time::ptime)
BOOST_LOG_ATTRIBUTE_KEYWORD(data, "Data", boost::json::object)
BOOST_LOG_ATTRIBUTE_KEYWORD(msg, "Msg", std::string)
BOOST_LOG_ATTRIBUTE_KEYWORD(thread_id, "ThreadId", std::string)

static void log_json(logging::record_view const& rec, logging::formatting_ostream& strm) {
    auto ts = *rec[timestamp];
    boost::json::object log_data;
    log_data["timestamp"] = to_iso_extended_string(ts);
    log_data["data"] = *rec[data];
    log_data["message"] = *rec[msg];
    log_data["thread_id"] = *rec[thread_id];
    strm << boost::json::serialize(log_data) << std::endl;
}

void InitBoostLogFilter() {
    logging::core::get()->set_filter(
        logging::trivial::severity >= logging::trivial::info
    );
    logging::add_common_attributes();
    //log to file filter
    logging::add_file_log(
        keywords::file_name = "sample_log_%N.log",
        keywords::format = &log_json,
        keywords::open_mode = std::ios_base::app | std::ios_base::out,
        keywords::rotation_size = 10 * 1024 * 1024,
        keywords::time_based_rotation = sinks::file::rotation_at_time_point(12, 0, 0)
    );
    //log to console filter
    logging::add_console_log(
        std::cout,
        keywords::format = &log_json,
        keywords::auto_flush = true
    );
}

void Log::print(const boost::json::object& data_, const std::string& message_) {
    std::lock_guard<std::mutex> mutex{mutex_};
    BOOST_LOG_TRIVIAL(info) 
        << logging::add_value(data, data_) 
        << logging::add_value(thread_id, std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()))) 
        << logging::add_value(msg, message_)
        << std::endl;
}

void Log::print(const std::string& message_) {
    std::lock_guard<std::mutex> mutex{mutex_};
    BOOST_LOG_TRIVIAL(info)
        << logging::add_value(data, boost::json::object{})
        << logging::add_value(thread_id, std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()))) 
        << logging::add_value(msg, message_)
        << std::endl;
}

void LogMessage::log_message(const std::string& message) {
    log_.print(message);
}
}