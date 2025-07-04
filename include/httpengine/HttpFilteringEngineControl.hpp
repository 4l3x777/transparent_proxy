/*
* Copyright � 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#ifdef WIN32
#include <sdkddkver.h>
#endif

#include <cstdint>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <cstdint>

#include "util/cb/EventReporter.hpp"
#include "mitm/secure/TlsCapableHttpAcceptor.hpp"

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace diversion
			{
				class DiversionControl;
			} /* namespace diversion */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */

namespace te
{
	namespace httpengine
	{

		/// <summary>
		/// The HttpFilteringEngineControl class is the managing class that employs all other
		/// classes in this Engine to provide the combined functionality of intercepting and
		/// diverting HTTP/S traffic, a transparent proxy listening for and handling the traffic for
		/// those diverted clients, and the Http Filtering Engine for inspecting and filtering
		/// requests and response payloads based on user loaded rulesets.
		/// </summary>
		class HttpFilteringEngineControl : public util::cb::EventReporter
		{

		public:

			/// <summary>
			/// Constructs a new HttpFilteringEngineControl. Requires a valid firewall callback
			/// function pointer on Windows or the constructor will throw. Optionally, callbacks for
			/// information, warning and error events within the underlying Engine can be supplied as
			/// well.
			/// </summary>
			/// <param name="firewallCb">
			/// A function that is meant to determine if the supplied absolute binary path points to
			/// a binary that has been approved for internet access. Required.
			/// </param>
			/// <param name="caBundleAbsolutePath">
			/// A an absolute path to a CA bundle that will be used globally while acting as the
			/// upstream client on behalf of all downstream client connections for the purpose of
			/// verifying server certificates. Optional and default value is "none", which means none
			/// will be configured internally. It is recommended to supply a path to the cURL/Mozilla
			/// ca-bundle. Internally, openSSL is set to use default verify path(s), but this is
			/// configuration and platform specific. If this fails and no CA bundle is supplied,
			/// TLS/SSL will basically be non functional.
			/// </param>
			/// <param name="httpListenerPort">
			/// The desired port for the proxy to listen for incoming plain TCP HTTP clients on.
			/// Default is zero, as it is recommended to allow the OS to select an available port
			/// from the ephimeral port range.
			/// </param>
			/// <param name="httpsListenerPort">
			/// The desired port for the proxy to listen for incoming secure HTTP clients on. Default
			/// is zero, as it is recommended to allow the OS to select an available port from the
			/// ephimeral port range.
			/// </param>
			/// <param name="proxyNumThreads">
			/// The number of thread to be run against the io_service that drives the proxy and all
			/// associated functionality, barring the platform dependent Diverter. Default value is
			/// the number of logical cores on the device. Be advised that these threads are the same
			/// threads that execute the filtering functionality.
			/// </param>
			/// <param name="onMessageBegin">
			/// Called when a new HTTP transaction starts, with, at-minimum headers, complete.
			/// </param>
			/// <param name="onMessageEnd">
			/// Called when a HTTP transaction that was flagged for content inspection has completed.
			/// </param>
			/// <param name="onInfo">
			/// A function that can accept string informational data generated by the underlying
			/// Engine. Default is nullptr. This callback cannot be supplied post-construction.
			/// </param>
			/// <param name="onWarn">
			/// A function that can accept string warning data generated by the underlying Engine.
			/// Default is nullptr. This callback cannot be supplied post-construction.
			/// </param>
			/// <param name="onError">
			/// A function that can accept string error data generated by the underlying Engine.
			/// Default is nullptr. This callback cannot be supplied post-construction.
			/// </param>
			HttpFilteringEngineControl(
				util::cb::FirewallCheckFunction firewallCb,				
				std::string caBundleAbsolutePath = std::string("none"),
				uint16_t httpListenerPort = 0,
				uint16_t httpsListenerPort = 0,
				uint32_t proxyNumThreads = std::thread::hardware_concurrency(),
				util::cb::HttpMessageBeginCheckFunction onMessageBegin = nullptr,
				util::cb::HttpMessageEndCheckFunction onMessageEnd = nullptr,
				util::cb::MessageFunction onInfo = nullptr,
				util::cb::MessageFunction onWarn = nullptr,
				util::cb::MessageFunction onError = nullptr
				);

			/// <summary>
			/// Default destructor.
			/// </summary>
			~HttpFilteringEngineControl();

			/// <summary>
			/// If the underlying Engine is not running at the time that this method is invoked, the
			/// Engine will begin diverting traffic to itself and listening for incoming diverted
			/// HTTP and HTTPS connections to filter. If the underlying Engine is already running,
			/// the call will have no effect.
			/// 
			/// Expect this function to potentially throw std::runtime_error and std::exception.
			/// </summary>
			void Start();

			/// <summary>
			/// If the underlying Engine is running at the time that this method is invoked, the
			/// Engine will cease diverting traffic to itself and cease listening for incoming
			/// diverted HTTP and HTTPS connections. If the underlying Engine is not running, the
			/// call will have no effect.
			/// </summary>
			void Stop();

			/// <summary>
			/// Checks whether the underlying Engine and its associated mechanisms are presently
			/// diverting traffic to itself and listening for incoming diverted HTTP and HTTPS
			/// connections to filter.
			/// </summary>
			/// <returns>
			/// True if the underlying Engine is actively diverting and receiving HTTP and HTTPS
			/// connections for filtering at the time of the call, false otherwise.
			/// </returns>
			bool IsRunning() const;

			/// <summary>
			/// Gets the port on which the plain TCP HTTP acceptor is listening.
			/// </summary>
			/// <returns>
			/// If the Engine is running, the port on which the plain TCP HTTP acceptor is
			/// listening. Zero otherwise.
			/// </returns>
			const uint32_t GetHttpListenerPort() const;

			/// <summary>
			/// Gets the port on which the secure HTTP acceptor is listening.
			/// </summary>
			/// <returns>
			/// If the Engine is running, the port on which the plain TCP HTTP acceptor is
			/// listening. Zero otherwise.
			/// </returns>
			const uint32_t GetHttpsListenerPort() const;

			/// <summary>
			/// Gets a copy of the root certificate, if any, in PEM format.
			/// </summary>
			/// <returns>
			/// On success, a vector populated with the bytes for the current root CA in PEM
			/// format. In the event that an error occurred or there is no current root CA,
			/// an empty vector.
			/// </returns>
			std::vector<char> GetRootCertificatePEM() const;

		private:

			/// <summary>
			/// If defined, called whenever a packet flow is being considered for diversion to the
			/// proxy, but the binary responsible for sending or receiving the flow has not yet been
			/// identified as a binary permitted to have internet access by the system firewall. If
			/// defined and the return from this callback is true, the binary has permission to
			/// access the internet, and diversion will take place. If false, no diversion will take place.
			/// 
			/// The purpose of this check is to avoid allowing an arbitrary program that would
			/// otherwise be blocked from accessing the internet, to access the internet. Since
			/// intercepted packets are never sent outbound, but rather this software acts as an
			/// agent to fulfill the request(s) itself, an application firewall would not be able to
			/// stop us from bypassing it on behalf of other software, once it has permitted this
			/// software to have internet access.
			/// </summary>
			util::cb::FirewallCheckFunction m_firewallCheckCb = nullptr;			

			/// <summary>
			/// The absolute path provided for a CA bundle to configure the upstream client context
			/// to use in certificate verification. This is only held as a class member because the
			/// underlying mechanism that takes this argument is not initialized in-constructor.
			/// It's necessary to store it here.
			/// </summary>
			std::string m_caBundleAbsolutePath;

			/// <summary>
			/// The desired port on which the proxy will listen for plain TCP HTTP clients. This is
			/// only held as a class member because the underlying mechanism that takes this
			/// argument is not initialized in-constructor. It's necessary to store it here. This is
			/// not to be returned in the public getter, since the listner itself may have bound to
			/// a different port when this argument is zero.
			/// </summary>
			uint16_t m_httpListenerPort;

			/// <summary>
			/// The desired port on which the proxy will listen for secure HTTP clients. This is
			/// only held as a class member because the underlying mechanism that takes this
			/// argument is not initialized in-constructor. It's necessary to store it here. This is
			/// not to be returned in the public getter, since the listner itself may have bound to
			/// a different port when this argument is zero.
			/// </summary>
			uint16_t m_httpsListenerPort;

			/// <summary>
			/// The number of threads to be run against the main io_service.
			/// </summary>
			uint32_t m_proxyNumThreads;

			/// <summary>
			/// Container for the threads driving the io_service.
			/// </summary>
			std::vector<std::thread> m_proxyServiceThreads;

			/// <summary>
			/// The io_service that will drive the proxy.
			/// </summary>
			std::unique_ptr<boost::asio::io_context> m_service = nullptr;

			/// <summary>
			/// The certificate store that will be used for secure clients.
			/// </summary>
			std::unique_ptr<mitm::secure::BaseInMemoryCertificateStore> m_store = nullptr;

			/// <summary>
			/// The diversion class that is responsible for diverting HTTP and HTTPS flows to the
			/// HTTP and HTTPS listeners for filtering.
			/// </summary>
			std::unique_ptr<mitm::diversion::DiversionControl> m_diversionControl;			

			/// <summary>
			/// Our acceptor for plain TCP HTTP clients.
			/// </summary>
			std::unique_ptr<mitm::secure::TcpAcceptor> m_httpAcceptor = nullptr;

			/// <summary>
			/// Our acceptor for secure TLS HTTP clients.
			/// </summary>
			std::unique_ptr<mitm::secure::TlsAcceptor> m_httpsAcceptor = nullptr;		

			/// <summary>
			/// Used in ::Start() ::Stop() members.
			/// </summary>
			std::mutex m_ctlMutex;

			/// <summary>
			/// Used to indicate if all compontents were initialized and started correctly, and are
			/// currently handling the process of diverting HTTP and HTTPS clients to the proxy to
			/// be served.
			/// </summary>
			std::atomic_bool m_isRunning;

			util::cb::HttpMessageBeginCheckFunction m_onMessageBegin;
			util::cb::HttpMessageEndCheckFunction m_onMessageEnd;

			static void DummyOnMessageBeginCallback(
				const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
				const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
				uint32_t* nextAction, CustomResponseStreamWriter responseWriter
			);

			static void DummyOnMessageEndCallback(
				const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
				const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
				bool* shouldBlock, CustomResponseStreamWriter responseWriter
			);

		};

	} /* namespace httpengine */
} /* namespace te */
