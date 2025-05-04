/*
* Copyright � 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#include <cstring>
#include <string>
#include <map>
#include <boost/functional.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/utility/string_ref.hpp>
#include "http_parser.h"
#include "../../util/cb/EventReporter.hpp"

#ifdef _MSC_VER 
	#define strncasecmp _strnicmp
	#define strcasecmp _stricmp
#endif

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace http
			{

				/// <summary>
				/// Just for code clarity, rather than having literal 1.0/1.1/2.0 sprinked
				/// everywhere.
				/// </summary>
				enum class HttpProtocolVersion
				{
					HTTP1, 
					HTTP1_1,
					HTTP2
				};

				/// <summary>
				/// Binary predicate for case insensitive lookups in std::multimap.
				/// </summary>
				struct CaseInsensitiveComparer : public boost::functional::detail::binary_function<std::string,
					std::string, bool>
				{
					bool operator()(const std::string &strOne, const std::string &strTwo) const
					{
						return strcasecmp(strOne.c_str(), strTwo.c_str()) < 0;
					}
				};

				/// <summary>
				/// Basic string/string multimap for storing the headers with case insensitive key
				/// comparison.
				/// </summary>
				typedef std::multimap<std::string, std::string, CaseInsensitiveComparer> HttpHeaderMap;

				/// <summary>
				/// Shorthand map constant iterator type.
				/// </summary>
				typedef HttpHeaderMap::const_iterator HttpHeaderConstIterator;

				/// <summary>
				/// We need to be able to support multiple header entries by the same name, since
				/// this is legal according to the spec. So, all methods that query against the map,
				/// looking for a specific entry, will return a range based match, rather than a
				/// single string value.
				/// </summary>					
				typedef std::pair<HttpHeaderConstIterator, HttpHeaderConstIterator> HttpHeaderRangeMatch;

				/// <summary>
				/// Abstract base class for HTTP Requests and Responses. This class is meant to
				/// parse, contain and manage the headers for the transaction as well as the
				/// transaction payload. The class is meant to serve as a minimal wrapper for these
				/// things, focusing less on integrating maninipulation code internally, and rather
				/// exposing this data to external manipulation.
				/// 
				/// Several convenience functions do exist which will manipulate the internal state
				/// of the transaction, but of course only through explicit external invocation. Due
				/// to the complexity of the protocol, an attempt is made to strike a balance
				/// between offering such conveniences, exposing internal data in a controlled
				/// fashion, and maintaining a correct state at the same time. This balance is
				/// unstable with some provided methods, but heavy warnings abound.
				/// </summary>
				class BaseHttpTransaction : public util::cb::EventReporter
				{
				public:

					BaseHttpTransaction();
					
					virtual ~BaseHttpTransaction();

					/// <summary>
					/// Fetches the value of the defined HTTP Protocol Version for the transaction.
					/// </summary>
					/// <returns>
					/// A HttpProtocolVersion enum indicating the current determined HTTP Protocol
					/// Version of the transaction.
					/// </returns>
					const HttpProtocolVersion GetHttpVersion() const;

					/// <summary>
					/// Sets the value of the defined HTTP Protocol Version for the transaction. 
					/// </summary>
					/// <param name="httpVersion"></param>
					void SetHttpVersion(const HttpProtocolVersion httpVersion);

					/// <summary>
					/// Inserts the specified header and corresponding value into the transaction's
					/// header map, which will be transmitted if and when the transaction has been
					/// approved to be sent to the remote peer.Note that inserting headers after the
					/// transaction has begun moving outbound from the proxy to the remote peer, is
					/// completely useless. Once the headers are sent for the transaction they are
					/// never considered again for the lifetime of the transaction, except in
					/// Filters. So all you'd accomplish by adding them is interfering with accurate
					/// filter detection.
					/// 
					/// In short, ensure all header manipulation is done as soon as you receive 
					/// headers in the transaction, to ensure they have an effect.
					/// </summary>
					/// <param name="name">
					/// The name of the header to insert. 
					/// </param>
					/// <param name="value">
					/// The value for the specified header. 
					/// </param>
					/// <param name="replaceIfExists">
					/// If any instances of the specified header exist, remove them and replace with
					/// this value. True by default.
					/// </param>
					void AddHeader(const std::string& name, std::string value, const bool replaceIfExists = true);

					/// <summary>
					/// Will remove a header that matches exactly the provided name and value, case
					/// insensitive. Note that removing headers after the transaction has begun
					/// moving outbound from the proxy to the remote peer, is completely useless.
					/// Once the headers are sent for the transaction they are never considered
					/// again for the lifetime of the transaction, except in Filters. So all you'd
					/// accomplish by removing them is interfering with accurate filter detection.
					/// 
					/// In short, ensure all header manipulation is done as soon as you receive 
					/// headers in the transaction, to ensure they have an effect.
					/// </summary>
					/// <param name="name">
					/// The name of the header to remove. 
					/// </param>
					/// <param name="value">
					/// The value for the specified header, which must be exactly matched. 
					/// </param>
					void RemoveHeader(const std::string& name, const std::string& value);

					/// <summary>
					/// Will remove all headers that matches exactly the provided name key, case
					/// insensitive. Note that removing headers after the transaction has begun
					/// moving outbound from the proxy to the remote peer, is completely useless.
					/// Once the headers are sent for the transaction they are never considered
					/// again for the lifetime of the transaction, except in Filters. So all you'd
					/// accomplish by removing them is interfering with accurate filter detection.
					/// 
					/// In short, ensure all header manipulation is done as soon as you receive 
					/// headers in the transaction, to ensure they have an effect.
					/// </summary>
					/// <param name="name">
					/// The name of the header to remove. 
					/// </param>
					void RemoveHeader(const std::string& name);

					/// <summary>
					/// Check for the existence of a header by the specified header name. Lookups
					/// are case insensitive.
					/// 
					/// Since the storage mechanism for the headers is a multimap, a range is
					/// returned, which may contain zero or more entries.
					/// </summary>
					/// <param name="header">
					/// The name of the HTTP header to lookup. Example: "Content-Type" 
					/// </param>
					/// <returns>
					/// A constant range based iterator which may contain zero or more entries. 
					/// </returns>
					const HttpHeaderRangeMatch GetHeader(const std::string& header) const;

					/// <summary>
					/// Check to see if all headers for the transaction have successfully been
					/// parsed.
					/// </summary>
					/// <returns>
					/// True if all headers have been parsed, false if not.
					/// </returns>
					const bool HeadersComplete() const;

					/// <summary>
					/// Convenience function for formatting the transaction headers into a
					/// std::string container.
					/// </summary>
					/// <returns>
					/// std::string populated with the complete, formatted transaction 
					/// headers.
					/// </returns>
					virtual std::string HeadersToString() = 0;

					/// <summary> 
					/// Convenience function for formatting the transaction headers into a
					/// std::vector char container. 
					/// </summary> 
					/// <returns> 
					/// std::vector char populated with the complete formatted transaction 
					/// headers. 
					/// </returns>
					virtual std::vector<char> HeadersToVector() = 0;

					/// <summary>
					/// Force the transaction to parse its content. This method absolutely must be
					/// called immediately following any completed read operations using this
					/// object.
					/// 
					/// This object owns two different objects which are used as buffers for reading
					/// the content of HTTP transactions. The first is a boost::asio::streambuf,
					/// which is used for reading the header content of a transaction in
					/// asio::async_read_until(...) operations. The second is a vector of char
					/// elements which holds the raw payload of the transaction, if any.
					/// 
					/// Conversion from chunked to fixed-length content and decompression will be
					/// done entirely manually by this objects own conversion implementation, thus
					/// making the sole purpose of the http_parser object to accurately extract
					/// header information and signal when the end of the transaction has been
					/// reached.
					/// </summary>
					/// <param name="bytes_transferred">
					/// The number of bytes_transferred indicated in the asio::async_read* handler
					/// that this function should always be called from within. This absolutely must
					/// be accurate and unomodified, as for example the asio::async_read_until(...)
					/// operations will very often read beyond the specified completion condition.
					/// 
					/// This means in the case of this software, that it is highly likely that the
					/// internal boost::asio::streambuf used for header reads will contain body data
					/// as well. The value of this parameter is the key to successfully determining
					/// this and acting accordingly.
					/// </param>
					/// <returns>
					/// True of the parsing operation was a success, false otherwise.
					/// </returns>
					const bool Parse(const size_t bytes_transferred);

					/// <summary>
					/// Gets the internal transaction buffer wrapped in a
					/// boost::asio::mutable_buffers_1 object for use in asio::async_read(...)
					/// methods. ::Parse(...) absolutely must be called immediately in the completion
					/// handler wherever this buffer is used.
					///
					/// Depending on how the transaction is configured, this buffer may already
					/// contain data and and is configured to begin writing at a position other than
					/// 0. All of these details are handled internally, so be advised that you should
					/// provide the returned mutable_buffers_1 to asio::async_read(...) methods
					/// without any modification to ensure an accurate state is maintained.
					///
					/// An example is when ::ConsumeAllBeforeSending() is true. This transaction may
					/// take more than one read to complete and as such, the internal buffer will
					/// already be partially populated with some of the content. This is tracked
					/// internally so don't concern yourself with it, but be aware of it.
					/// </summary>
					/// <returns>
					/// A boost::asio::mutable_buffers_1 which wraps the internal buffer, configured
					/// for reading according to the state and configuration of this object.
					/// </returns>
					boost::asio::mutable_buffers_1 GetReadBuffer();

					/// <summary>
					/// Retrieve a boost::asio::const_buffers_1 object which wraps the internal
					/// transaction payload. Call this method when you intend to write the entire
					/// contents of the transaction outbound from the proxy.
					/// 
					/// Note that this method lacks a right-hand const declaration. The internal
					/// state of the object will be irreversibly altered once this method is called,
					/// as if the headers have not yet been set, the headers must be merged into the
					/// final, separated payload storage before being supplied as a single buffer
					/// for writing.
					/// </summary>
					/// <returns>
					/// A boost::asio::const_buffers_1 object wrapping the internal transaction
					/// payload data.
					/// </returns>
					boost::asio::const_buffers_1 GetWriteBuffer();

					/// <summary>
					/// Fetch the raw payload data. In the event that ::ConsumeAllBeforeSending() is
					/// true and ::IsPayloadComplete() is also true, the payload data should be
					/// provided decompressed, barring any errors that arose in the process of
					/// decompressing. To be sure, check the value of ::IsPayloadCompressed().
					/// 
					/// Also, when ::ConsumeAllBeforeSending() and ::IsPayloadComplete() is true,
					/// the payload should never be chunked content, as in these circumstances,
					/// chunked content is automatically converted to a fixed-length response
					/// (content-length header present).
					/// 
					/// This data is exposed purely for analysis.
					/// </summary>
					/// <returns>
					/// The transaction payload, aka the body. May or may not be compressed. 
					/// </returns>
					const std::vector<char>& GetPayload() const;

					/// <summary>
					/// Moves the supplied payload to the internal transaction payload buffer. Sets
					/// the state of the transaction to complete, removes all headers about
					/// compression, content length or transfer encoding, then injects a new
					/// content-length header with the size of the supplied payload.
					///
					/// As such, this method assumes that the supplied payload is uncompressed. If
					/// compression is required, pass uncompressed data here, then call the
					/// ::CompressDeflate() or ::CompressGzip() members.
					/// </summary>
					/// <param name="payload">
					/// The payload to be moved to the internal payload buffer.
					/// </param>
					/// <param name="includesHeaders">
					/// If set to true, it will be assumed that headers are included in the supplied
					/// payload. Note that the headers will not be parsed out. Rather, the internal
					/// state will be irrevocably modified to force the headers to be read from the
					/// payload only.
					/// </param>
					void SetPayload(std::vector<char>&& payload, const bool includesHeaders = false);

					/// <summary>
					/// Copies the supplied payload to the internal transaction payload buffer. Sets
					/// the state of the transaction to complete, removes all headers about
					/// compression, content length or transfer encoding, then injects a new
					/// content-length header with the size of the supplied payload.
					/// 
					/// As such, this method assumes that the supplied payload is uncompressed. If
					/// compression is required, pass uncompressed data here, then call the
					/// ::CompressDeflate() or ::CompressGzip() members.
					/// </summary>
					/// <param name="payload">
					/// The payload to be copied to the internal payload buffer.
					/// </param>
					/// <param name="includesHeaders">
					/// If set to true, it will be assumed that headers are included in the supplied
					/// payload. Note that the headers will not be parsed out. Rather, the internal
					/// state will be irrevocably modified to force the headers to be read from the
					/// payload only.
					/// </param>
					void SetPayload(const std::vector<char>& payload, const bool includesHeaders = false);

					/// <summary>
					/// Check to see if the transaction payload has been fully received. This will
					/// return true only when the http_parser has flagged that either all chunked
					/// content has been parsed, or a byte-sequence matching the length of the
					/// specified "Content-Length" header has been read.
					/// 
					/// This is primarily used to either determine that the entire payload has been
					/// read into memory and is ready for some sort of deep content analysis, and/or
					/// that all data has been read and sent from the remote peer back to the client,
					/// at which point, if specified, subsequent requests can be read from the client
					/// (keep-alive) or the entire transaction can be terminated.
					/// </summary>
					/// <returns>
					/// True if the last chunk or byte in the transaction has been read, false
					/// otherwise.
					/// </returns>
					const bool IsPayloadComplete() const;

					/// <summary>
					/// Check to see if the transaction has been marked for blocking. If any
					/// non-zero value is returned, the transaction has been assigned a category
					/// under which it should be blocked from completing.
					/// </summary>
					/// <returns>
					/// A non-zero value if the transaction has been marked for blocking, zero if
					/// the transaction is not marked for blocking.
					/// </returns>
					const int32_t GetShouldBlock() const;

					/// <summary>
					/// Set the value of ShouldBlock if it has been determined externally that the
					/// transaction should be blocked from completing. Note that setting ShouldBlock
					/// to any non-zero value will cause IsPayloadComplete() to internally be set to
					/// true, as IsPayloadComplete() is used to determine that the transaction is
					/// complete.
					/// 
					/// However, ShouldBlock will not transform the internal state of the headers or
					/// the transaction payload. This is because in cases like setting ShouldBlock()
					/// to a non-zero value on HttpRequest objects, we still want to transmit at
					/// least the request headers to the remote peer for reading the total size of
					/// the blocked transaction, just for statistics collection measuring the
					/// efficacy of the software on reducing energy waste.
					/// 
					/// The only exception to this upstream request transmission when ShouldBlock()
					/// holds a non-zero value on HttpRequest objects is the case where
					/// ShouldBlock() contains a value representing a malicious category, like when
					/// the request has been determined to go outbound to a suspected malware
					/// source. Note that even in this exception, the body and headers are not
					/// modified internally still, the connection is simply terminated before any
					/// upstream connection is initiated.
					/// 
					/// For transforming a transaction into a valid HTTP 204 response for the
					/// purpose of silently blocking a request in a non-error indicating fashion,
					/// use the convenience function Make204().
					/// </summary>
					/// <param name="category">
					/// The numerical representation of the category that the transaction has been
					/// determined to belong to and as such marked for blocking, or zero to indicate
					/// that the transaction should not be blocked.
					/// </param>
					void SetShouldBlock(const int32_t category);

					/// <summary>
					/// Convenience function for internally modifying the transaction headers and
					/// payload to represent an HTTP 204 response. This would, at face value, make
					/// little to no sense for an HttpRequest object. However, rather than wasting
					/// the resources to create a separate HttpResponse object from which to
					/// construct the response, the request can simply be transformed into this
					/// canned response, the buffer written immediately back to the client and the
					/// connection terminated.
					/// 
					/// This is useful and saves resources in situations like when the request was
					/// marked for blocking due to the remote host being found in a malicious
					/// category. No upstream connection to such a host is desired, so quickly
					/// blocking and terminating the connection is the cheapest and fastest
					/// solution.
					/// </summary>
					void Make204();

					/// <summary>
					/// Check to see if the transaction has been configured so that all headers and
					/// the transaction payload (body) must be consumed and held in memory before
					/// allowing the data to be sent outbound from the proxy. This is necessary to
					/// perform any type of deep content analysis, as it's too much of a burden to
					/// expect the user to do such a thing in chunks and depending on the content,
					/// this just isn't possible anyway.
					/// </summary>
					/// <returns>
					/// True if the option is set, false if not. 
					/// </returns>
					const bool GetConsumeAllBeforeSending() const;

					/// <summary>
					/// Set whether or not the all headers as well as the entire transaction payload
					/// (body) must be read into memory before allowing the transaction to move
					/// outbound from the proxy. This is necessary to perform any type of deep
					/// content analysis, as it's too much of a burden to expect the user to do such
					/// a thing in chunks and depending on the content, this just isn't possible
					/// anyway.
					/// 
					/// When set to true, if the transaction uses chunked transfer encoding, the
					/// headers specifying information about the chunked transfer will be removed
					/// and the transaction will be transformed into a precalculated, fixed-length
					/// (Content-Length specified) transaction. Also, the entire transaction payload
					/// will be decompressed. Recompression is not automatic, not even for upstream
					/// payloads, rather this is left to the user to determine and apply using the
					/// provided convenience functions.
					/// 
					/// Use caution with this, as this will blindly continue to consume the
					/// payload/body of a transaction until the parser signals that it is complete.
					/// The only burden placed on the user is to ensure you're not telling the
					/// library to consume multi-gigabyte files!
					/// </summary>
					/// <param name="value">
					/// </param>
					void SetConsumeAllBeforeSending(const bool value);

					/// <summary>
					/// Determine if the payload is chunked or not. Looks for the transfer-encoding header.
					/// </summary>
					/// <returns>
					/// True if the payload is chunked, false otherwise.
					/// </returns>
					const bool IsPayloadChunked() const;

					/// <summary>
					/// Determine if the payload is compressed or not.
					/// </summary>
					/// <returns>
					/// True if the payload is compressed, false otherwise.
					/// </returns>
					const bool IsPayloadCompressed() const;

					/// <summary>
					/// Convenience function to determine if the payload of the transaction is JSON
					/// data.
					/// </summary>
					/// <returns>
					/// True if the transaction payload is JSON data, false if not. 
					/// </returns>
					const bool IsPayloadJson() const;

					/// <summary>
					/// Convenience function to determine if the payload of the transaction is HTML
					/// data.
					/// </summary>
					/// <returns>
					/// True if the transaction payload is HTML data, false if not. 
					/// </returns>
					const bool IsPayloadHtml() const;

					/// <summary>
					/// Convenience function to determine if the payload of the transaction is a
					/// type of text data. Text data can still be useful for other forms of
					/// inspection, such as document classification. The types that this function
					/// will match against are JSON, HTML and any other content-type containing
					/// "text/".
					/// </summary>
					/// <returns>
					/// True if the transaction payload is text data, false if not. 
					/// </returns>
					const bool IsPayloadText() const;

					/// <summary>
					/// Convenience function to determine if the payload of the transaction is image
					/// data.
					/// </summary>
					/// <returns>
					/// True if the transaction payload is image data, false if not. 
					/// </returns>
					const bool IsPayloadImage() const;

					/// <summary>
					/// Convenience function to determine if the payload of the transaction is CSS
					/// data.
					/// </summary>
					/// <returns>
					/// True if the transaction payload is CSS data, false if not. 
					/// </returns>
					const bool IsPayloadCss() const;

					/// <summary>
					/// Convenience function to determine if the payload of the transaction is
					/// Javscript data.
					/// </summary>
					/// <returns>
					/// True if the transaction payload is Javscript data, false if not. 
					/// </returns>
					const bool IsPayloadJavascript() const;

					/// <summary>
					/// Convenience function for checking to see if the Content-Type header for the
					/// transaction is an exact, case insensitive match to the specified type.
					/// </summary>
					/// <param name="type">
					/// The Content-Type type to exactly match. Example: "application/xhtml+xml" 
					/// </param>
					/// <returns>
					/// True if the transaction Content-Type header value exactly matches the
					/// specified type, false otherwise.
					/// </returns>
					const bool DoesContentTypeMatch(const boost::string_ref type) const;

					/// <summary>
					/// Convenience function for checking to see if the Content-Type header for the
					/// transaction contains a case insensitive match to the specified type
					/// information.
					/// </summary>
					/// <param name="type">
					/// The Content-Type type to exactly or partially match. Example: "text/" 
					/// </param>
					/// <returns>
					/// True if the specified type information completely or partially matches the
					/// transaction Content-Type header value in a case insensitive search, false
					/// otherwise.
					/// </returns>
					const bool DoesContentTypeContain(const boost::string_ref type) const;

					/// <summary>
					/// Compress the transaction payload using gzip. Note that the decompression
					/// methods are not exposed publicly. Automatically decompressing the contents
					/// for analysis is controlled based on the value of
					/// ::ConsumeAllBeforeSending(). Recompression however is not automatic, but may
					/// be desired for request payloads, as to not be sending decompressed data
					/// upstream. Therefore, a public interface to manually recompress is provided.
					/// </summary>
					/// <returns>
					/// True if the compression operation succeeded, false otherwise. Warnings and
					/// or errors would have been generated in the case of a return value of false,
					/// so subscribe to appropriate events through the EventReporter interface.
					/// </returns>
					const bool CompressGzip();

					/// <summary>
					/// Compress the transaction payload using deflate. Note that the decompression
					/// methods are not exposed publicly. Automatically decompressing the contents
					/// for analysis is controlled based on the value of
					/// ::ConsumeAllBeforeSending(). Recompression however is not automatic, but may
					/// be desired for request payloads, as to not be sending decompressed data
					/// upstream. Therefore, a public interface to manually recompress is provided.
					/// </summary>
					/// <returns>
					/// True if the compression operation succeeded, false otherwise. Warnings and
					/// or errors would have been generated in the case of a return value of false,
					/// so subscribe to appropriate events through the EventReporter interface.
					/// </returns>
					const bool CompressDeflate();

					/// <summary>
					/// Attempts to decompress the payload. This will modify the object internally,
					/// adjusting headers and the payload buffer itself to reflect the new state in
					/// the event that decompression is successful.
					/// </summary>
					/// <returns>
					/// True if the payload was successfully decompressed, false otherwise. Note that
					/// if the payload is already decompressed, this function will return true, so
					/// a return value of false should always indicate an error. Note also that this
					/// will return false if the payload is incomplete.
					/// </returns>
					const bool DecompressPayload();

				protected:
					
					/// <summary>
					/// Used to aid in the IsPayloadX functions, for matching specific
					/// keywords in HTTP headers.
					/// </summary>
					static const boost::string_ref ContentTypeText;

					/// <summary>
					/// Used to aid in the IsPayloadX functions, for matching specific
					/// keywords in HTTP headers.
					/// </summary>
					static const boost::string_ref ContentTypeHtml;

					/// <summary>
					/// Used to aid in the IsPayloadX functions, for matching specific
					/// keywords in HTTP headers.
					/// </summary>
					static const boost::string_ref ContentTypeJson;

					/// <summary>
					/// Used to aid in the IsPayloadX functions, for matching specific
					/// keywords in HTTP headers.
					/// </summary>
					static const boost::string_ref ContentTypeImage;

					/// <summary>
					/// Used to aid in the IsPayloadX functions, for matching specific
					/// keywords in HTTP headers.
					/// </summary>
					static const boost::string_ref ContentTypeCss;

					/// <summary>
					/// Used to aid in the IsPayloadX functions, for matching specific
					/// keywords in HTTP headers.
					/// </summary>
					static const boost::string_ref ContentTypeJavascript;

					/// <summary>
					/// Increments by which the payload buffer will be resized, also the initial
					/// reserved size.
					/// </summary>
					static constexpr uint32_t PayloadBufferReadSize = 131072;

					/// <summary>
					/// Maximum size that the payload buffer can be resized to.
					/// </summary>
					static constexpr uint32_t MaxPayloadResize = 10485760;

					/// <summary>
					/// The http_parser object that gets stuck with doing all of the hard work.
					/// </summary>
					http_parser* m_httpParser = nullptr;

					/// <summary>
					/// Configuration settings for the http_parser* member m_httpParser.
					/// </summary>
					http_parser_settings m_httpParserSettings;

					/// <summary>
					/// The extracted version of the Http Protocol used for this transaction.
					/// </summary>
					HttpProtocolVersion m_httpVersion;

					/// <summary>
					/// Case insensitive multimap for storing the http header fields and values
					/// read during the transaction.
					/// </summary>
					HttpHeaderMap m_headers;

					/// <summary>
					/// Due to the nature of the protocol and specifically how the http_parser
					/// processes data, a reference to the last header read by the parser has
					/// to be kept during the header parsing process. When the OnHeaderValue(...)
					/// method is called, this should be set to the last header name read, at
					/// which time the complete header can be inserted and this variable reset
					/// to be empty.
					/// </summary>
					std::string m_lastHeader;

					bool m_lastHeaderValueFresh = false;

					bool m_lastHeaderFieldFresh = false;

					std::vector<char> m_buffer;

					std::vector<char> m_payload;

					/// <summary>
					/// Flag used to indicate if the headers for the transaction have been fully
					/// read from the client/remote peer.
					/// </summary>
					bool m_headersComplete = false;

					/// <summary>
					/// Used internally only to determine if the headers have been written outbound
					/// for the transaction. This is required because the headers and the actualy
					/// payload are stored in two different containers and, when m_headersSent is
					/// false and the payload is requested for writing, the headers must be
					/// prepended to the payload, of course.
					/// </summary>
					bool m_headersSent = false;

					/// <summary>
					/// Flag used to indicate if the payload for the transaction has been fully
					/// read from the client/remote peer.
					/// </summary>
					bool m_payloadComplete = false;

					/// <summary>
					/// Flag used to determine if the transaction should be blocked. Any
					/// greater-than-zero value represents a filtering category, and as such, any
					/// greater-than-zero value indicates that the request should indeed be blocked,
					/// which zero indicates that the transaction should be blocked. A negative value
					/// indicates that the transaction is whitelisted.
					/// </summary>
					int32_t m_shouldBlock = 0;

					/// <summary>
					/// Flag used to determine if the entire transaction headers and payload (body)
					/// should be read into memory before allowing the data to be moved outbound
					/// from the proxy. This is necessary for things such as deep content analysis.
					/// </summary>
					bool m_consumeAllBeforeSending = false;

					/// <summary>
					/// Decompress the payload contents, expecting gzip format.
					/// </summary>
					/// <returns>
					/// True if the decompression succeeded, false otherwise.
					/// </returns>
					const bool DecompressGzip();

					/// <summary>
					/// Decompress the payload contents, expecting deflate format.
					/// </summary>
					/// <returns>
					/// True if the decompression succeeded, false otherwise.
					/// </returns>
					const bool DecompressDeflate();

					/// <summary>
					/// In the even that the user has specified that they wish collect the entire
					/// payload of a transaction for inspection, certain guarantees are provided:
					/// that chunked content will be converted to a normal,
					/// fixed-length/precalculated transfer, and the payload will be decompressed.
					/// 
					/// Since this object owns the buffers directly used on the sockets, and in
					/// order to maintain a valid state during and up-till a completely read
					/// request/response, even though the http_parser is parsing the data on every
					/// read, chunked data is not being extracted during any read operation leading
					/// up to a completed transaction. This is to avoid fragmenting the object state
					/// so that it remains valid. See notes on ::Parse(..) for more on that.
					/// 
					/// As such, when and only when the the following two conditions are met, the
					/// transaction payload can/should be converted to a normal precalcuated
					/// transfer and decompressed: ::ConsumeAllBeforeSending() is true, and
					/// ::IsPayloadComplete() is also true. If these conditions are met, this object
					/// will automatically provide the described functionality via this method once
					/// the final ::Parse(...) has been called.
					/// </summary>
					/// <returns>
					/// True if the conversion succeeded, false otherwise. 
					/// </returns>
					const bool ConvertPayloadFromChunkedToFixedLength();					

					/// <summary>
					/// Called when the http_parser has begun reading a new transaction.
					/// </summary>
					/// <param name="parser">
					/// The http_parser, returned in the callback for establishing context, since
					/// the callback is static. A pointer to the transaction object is held in
					/// parser->data.
					/// </param>
					/// <returns>
					/// The parsing status determined within the callback. Callbacks must return 0
					/// on success. Returning a non-zero value indicates error to the parser, making
					/// it exit immediately.
					/// </returns>
					static int OnMessageBegin(http_parser* parser);

					/// <summary>
					/// Called when the http_parser has finished reading all HTTP headers for a 
					/// transaction.
					/// </summary>
					/// <param name="parser">
					/// The http_parser, returned in the callback for establishing context, since
					/// the callback is static. A pointer to the transaction object is held in
					/// parser->data.
					/// </param>
					/// <returns>
					/// The parsing status determined within the callback. Callbacks must return 0
					/// on success. Returning a non-zero value indicates error to the parser, making
					/// it exit immediately.
					/// </returns>
					static int OnHeadersComplete(http_parser* parser);

					/// <summary>
					/// Called when the http_parser has completed reading all data for a transaction.
					/// </summary>
					/// <param name="parser">
					/// The http_parser, returned in the callback for establishing context, since
					/// the callback is static. A pointer to the transaction object is held in
					/// parser->data.
					/// </param>
					/// <returns>
					/// The parsing status determined within the callback. Callbacks must return 0
					/// on success. Returning a non-zero value indicates error to the parser, making
					/// it exit immediately.
					/// </returns>
					static int OnMessageComplete(http_parser* parser);
					
					/// <summary>
					/// Called when a chunk header is processed by http_parser. When on_chunk_header
					/// is called, the current chunk length is stored in parser->content_length.
					/// </summary>
					/// <param name="parser">
					/// The http_parser, returned in the callback for establishing context, since
					/// the callback is static. A pointer to the transaction object is held in
					/// parser->data.
					/// </param>
					/// <returns>
					/// The parsing status determined within the callback. Callbacks must return 0
					/// on success. Returning a non-zero value indicates error to the parser, making
					/// it exit immediately.
					/// </returns>
					static int OnChunkHeader(http_parser* parser);

					/// <summary>
					/// Called when a chunk read has been completed by http_parser.
					/// </summary>
					/// <param name="parser">
					/// The http_parser, returned in the callback for establishing context, since
					/// the callback is static. A pointer to the transaction object is held in
					/// parser->data.
					/// </param>
					/// <returns>
					/// The parsing status determined within the callback. Callbacks must return 0
					/// on success. Returning a non-zero value indicates error to the parser, making
					/// it exit immediately.
					/// </returns>
					static int OnChunkComplete(http_parser* parser);

					/// <summary>
					/// Called when a header field name has been read by the http_parser.
					/// </summary>
					/// <param name="parser">
					/// The http_parser, returned in the callback for establishing context, since
					/// the callback is static. A pointer to the transaction object is held in
					/// parser->data.
					/// </param>
					/// <param name="at">
					/// A pointer to the position in the data buffer where the data begins. 
					/// </param>
					/// <param name="length">
					/// The length of the data in the buffer. 
					/// </param>
					/// <returns>
					/// The parsing status determined within the callback. Callbacks must return 0
					/// on success. Returning a non-zero value indicates error to the parser, making
					/// it exit immediately.
					/// </returns>
					static int OnHeaderField(http_parser* parser, const char *at, size_t length);

					/// <summary>
					/// Called when a header field value has been read by the http_parser.
					/// </summary>
					/// <param name="parser">
					/// The http_parser, returned in the callback for establishing context, since
					/// the callback is static. A pointer to the transaction object is held in
					/// parser->data.
					/// </param>
					/// <param name="at">
					/// A pointer to the position in the data buffer where the data begins. 
					/// </param>
					/// <param name="length">
					/// The length of the data in the buffer. 
					/// </param>
					/// <returns>
					/// The parsing status determined within the callback. Callbacks must return 0
					/// on success. Returning a non-zero value indicates error to the parser, making
					/// it exit immediately.
					/// </returns>
					static int OnHeaderValue(http_parser* parser, const char *at, size_t length);

					/// <summary>
					/// Called when the transaction body has been read by the http_parser.
					/// </summary>
					/// <param name="parser">
					/// The http_parser, returned in the callback for establishing context, since
					/// the callback is static. A pointer to the transaction object is held in
					/// parser->data.
					/// </param>
					/// <param name="at">
					/// A pointer to the position in the data buffer where the data begins. 
					/// </param>
					/// <param name="length">
					/// The length of the data in the buffer. 
					/// </param>
					/// <returns>
					/// The parsing status determined within the callback. Callbacks must return 0
					/// on success. Returning a non-zero value indicates error to the parser, making
					/// it exit immediately.
					/// </returns>
					static int OnBody(http_parser* parser, const char *at, size_t length);

				};
			} /* namespace http */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */