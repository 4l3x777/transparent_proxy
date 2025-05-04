/*
* Copyright � 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

/*
* Note: Not all fields marked as "Status: Proposed" may in fact be defined
* technically as "informational." Any place where there is a complete
* list of provisional and permanent headers, the status fields are
* incomplete. As such, I operated under the assumption that they fall
* under the category of "proposed" unless explicitly marked as
* "permanent." Some may be actually defined as "informational", but
* currently I'm not willing to read through hundreds if not thousands of
* pages of RFC's and make sure they are correctly marked "proposed" or
* "informational". Standard headers should be marked correctly, that's
* currently the depth of concern with accuracy for these listings.
*
* These listings are not meant to provide 100% accurate summaries of the
* status of the headers, but rather to be a complete list of known headers
* for convenience to the developer, with information about the origin of the
* RFC definition so that one might know where to do to get 100% accurate
* summaries and definitions.
*/

#include <string>

namespace te
{
	namespace httpengine
	{
		namespace util
		{
			namespace http
			{
				namespace headers
				{

					/// <summary>
					/// Header Name: A-IM
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>					
					const std::string AIM{ "A-IM" };

					/// <summary>
					/// Header Name: Accept
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.2]
					/// </summary>
					const std::string Accept{ "Accept" };

					/// <summary>
					/// Header Name: Accept-Additions
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string AcceptAdditions{ "Accept-Additions" };

					/// <summary>
					/// Header Name: Accept-Charset
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.3]
					/// </summary>
					const std::string AcceptCharset{ "Accept-Charset" };

					/// <summary>
					/// Header Name: Accept-Datetime
					/// Protocol: HTTP
					/// Status: Informational
					/// Defined In: [RFC7089]
					/// </summary>
					const std::string AcceptDatetime{ "Accept-Datetime" };

					/// <summary>
					/// Header Name: Accept-Encoding
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.4][RFC-ietf-httpbis-cice-03, Section 3]
					/// </summary>
					const std::string AcceptEncoding{ "Accept-Encoding" };

					/// <summary>
					/// Header Name: Accept-Features
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string AcceptFeatures{ "Accept-Features" };

					/// <summary>
					/// Header Name: Accept-Language
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.3.5]
					/// </summary>
					const std::string AcceptLanguage{ "Accept-Language" };

					/// <summary>
					/// Header Name: Accept-Patch
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC5789]
					/// </summary>
					const std::string AcceptPatch{ "Accept-Patch" };

					/// <summary>
					/// Header Name: Accept-Ranges
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 2.3]
					/// </summary>
					const std::string AcceptRanges{ "Accept-Ranges" };

					/// <summary>
					/// Header Name: Access-Control
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControl{ "Access-Control" };

					/// <summary>
					/// Header Name: Access-Control-Allow-Credentials
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowCredentials{ "Access-Control-Allow-Credentials" };

					/// <summary>
					/// Header Name: Access-Control-Allow-Headers
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowHeaders{ "Access-Control-Allow-Headers" };

					/// <summary>
					/// Header Name: Access-Control-Allow-Methods
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowMethods{ "Access-Control-Allow-Methods" };

					/// <summary>
					/// Header Name: Access-Control-Allow-Origin
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlAllowOrigin{ "Access-Control-Allow-Origin" };

					/// <summary>
					/// Header Name: Access-Control-Max-Age
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlMaxAge{ "Access-Control-Max-Age" };

					/// <summary>
					/// Header Name: Access-Control-Request-Headers
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlRequestHeaders{ "Access-Control-Request-Headers" };

					/// <summary>
					/// Header Name: Access-Control-Request-Method
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string AccessControlRequestMethod{ "Access-Control-Request-Method" };

					/// <summary>
					/// Header Name: Age
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.1]
					/// </summary>
					const std::string Age{ "Age" };

					/// <summary>
					/// Header Name: Allow
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.4.1]
					/// </summary>
					const std::string Allow{ "Allow" };

					/// <summary>
					/// Header Name: ALPN
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7639, Section 2]
					/// </summary>
					const std::string ALPN{ "ALPN" };

					/// <summary>
					/// Header Name: Alternates
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Alternates{ "Alternates" };

					/// <summary>
					/// Header Name: Apply-To-Redirect-Ref
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4437]
					/// </summary>
					const std::string ApplyToRedirectRef{ "Apply-To-Redirect-Ref" };

					/// <summary>
					/// Header Name: Authentication-Info
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7615, Section 3]
					/// </summary>
					const std::string AuthenticationInfo{ "Authentication-Info" };

					/// <summary>
					/// Header Name: Authorization
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.2]
					/// </summary>
					const std::string Authorization{ "Authorization" };

					/// <summary>
					/// Header Name: Base
					/// Protocol: MIME
					/// Status: obsoleted
					/// Defined In: [RFC1808][RFC2068 Section 14.11]
					/// </summary>
					const std::string Base{ "Base" };

					/// <summary>
					/// Header Name: Body
					/// Protocol: none
					/// Status: reserved
					/// Defined In: [RFC6068]
					/// </summary>
					const std::string Body{ "Body" };

					/// <summary>
					/// Header Name: C-Ext
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CExt{ "C-Ext" };

					/// <summary>
					/// Header Name: C-Man
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CMan{ "C-Man" };

					/// <summary>
					/// Header Name: C-Opt
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string COpt{ "C-Opt" };

					/// <summary>
					/// Header Name: C-PEP
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CPEP{ "C-PEP" };

					/// <summary>
					/// Header Name: C-PEP-Info
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string CPEPInfo{ "C-PEP-Info" };

					/// <summary>
					/// Header Name: Cache-Control
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.2]
					/// </summary>
					const std::string CacheControl{ "Cache-Control" };

					/// <summary>
					/// Header Name: CalDAV-Timezones
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC-ietf-tzdist-caldav-timezone-ref-05, Section 7.1]
					/// </summary>
					const std::string CalDAVTimezones{ "CalDAV-Timezones" };

					/// <summary>
					/// Header Name: Close
					/// Protocol: HTTP
					/// Status: reserved
					/// Defined In: [RFC7230, Section 8.1]
					/// </summary>
					const std::string Close{ "Close" };

					/// <summary>
					/// Header Name: Compliance
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Compliance{ "Compliance" };

					/// <summary>
					/// Header Name: Connection
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 6.1]
					/// </summary>
					const std::string Connection{ "Connection" };

					/// <summary>
					/// Header Name: Content-Alternative
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string ContentAlternative{ "Content-Alternative" };

					/// <summary>
					/// Header Name: Content-Base
					/// Protocol: HTTP
					/// Status: obsoleted
					/// Defined In: [RFC2068][RFC2616]
					/// </summary>
					const std::string ContentBase{ "Content-Base" };

					/// <summary>
					/// Header Name: Content-Description
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string ContentDescription{ "Content-Description" };

					/// <summary>
					/// Header Name: Content-Disposition
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6266]
					/// </summary>
					const std::string ContentDisposition{ "Content-Disposition" };

					/// <summary>
					/// Header Name: Content-Duration
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string ContentDuration{ "Content-Duration" };

					/// <summary>
					/// Header Name: Content-Encoding
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.2.2]
					/// </summary>
					const std::string ContentEncoding{ "Content-Encoding" };

					/// <summary>
					/// Header Name: Content-features
					/// Protocol: MIME
					/// Status: Proposed
					/// Defined In: [RFC4021]
					/// </summary>
					const std::string Contentfeatures{ "Content-features" };

					/// <summary>
					/// Header Name: Content-ID
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentID{ "Content-ID" };

					/// <summary>
					/// Header Name: Content-Language
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.3.2]
					/// </summary>
					const std::string ContentLanguage{ "Content-Language" };

					/// <summary>
					/// Header Name: Content-Length
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 3.3.2]
					/// </summary>
					const std::string ContentLength{ "Content-Length" };

					/// <summary>
					/// Header Name: Content-Location
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.4.2]
					/// </summary>
					const std::string ContentLocation{ "Content-Location" };

					/// <summary>
					/// Header Name: Content-MD5
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentMD5{ "Content-MD5" };

					/// <summary>
					/// Header Name: Content-Range
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 4.2]
					/// </summary>
					const std::string ContentRange{ "Content-Range" };

					/// <summary>
					/// Header Name: Content-Script-Type
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentScriptType{ "Content-Script-Type" };

					/// <summary>
					/// Header Name: Content-Style-Type
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentStyleType{ "Content-Style-Type" };

					/// <summary>
					/// Header Name: Content-Transfer-Encoding
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentTransferEncoding{ "Content-Transfer-Encoding" };

					/// <summary>
					/// Header Name: Content-Type
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 3.1.1.5]
					/// </summary>
					const std::string ContentType{ "Content-Type" };

					/// <summary>
					/// Header Name: Content-Version
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ContentVersion{ "Content-Version" };

					/// <summary>
					/// Header Name: Cookie
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6265]
					/// </summary>
					const std::string Cookie{ "Cookie" };

					/// <summary>
					/// Header Name: Cookie2
					/// Protocol: HTTP
					/// Status: obsoleted
					/// Defined In: [RFC2965][RFC6265]
					/// </summary>
					const std::string Cookie2{ "Cookie2" };

					/// <summary>
					/// Header Name: Cost
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Cost{ "Cost" };

					/// <summary>
					/// Header Name: DASL
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC5323]
					/// </summary>
					const std::string DASL{ "DASL" };

					/// <summary>
					/// Header Name: Date
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.1.2]
					/// </summary>
					const std::string Date{ "Date" };

					/// <summary>
					/// Header Name: DAV
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string DAV{ "DAV" };

					/// <summary>
					/// Header Name: Default-Style
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DefaultStyle{ "Default-Style" };

					/// <summary>
					/// Header Name: Delta-Base
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DeltaBase{ "Delta-Base" };

					/// <summary>
					/// Header Name: Depth
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Depth{ "Depth" };

					/// <summary>
					/// Header Name: Derived-From
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DerivedFrom{ "Derived-From" };

					/// <summary>
					/// Header Name: Destination
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Destination{ "Destination" };

					/// <summary>
					/// Header Name: Differential-ID
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string DifferentialID{ "Differential-ID" };

					/// <summary>
					/// Header Name: Digest
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Digest{ "Digest" };

					/// <summary>
					/// Header Name: EDIINT-Features
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC6017]
					/// </summary>
					const std::string EDIINTFeatures{ "EDIINT-Features" };

					/// <summary>
					/// Header Name: ETag
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 2.3]
					/// </summary>
					const std::string ETag{ "ETag" };

					/// <summary>
					/// Header Name: Expect
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.1.1]
					/// </summary>
					const std::string Expect{ "Expect" };

					/// <summary>
					/// Header Name: Expires
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.3]
					/// </summary>
					const std::string Expires{ "Expires" };

					/// <summary>
					/// Header Name: Ext
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Ext{ "Ext" };

					/// <summary>
					/// Header Name: Forwarded
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7239]
					/// </summary>
					const std::string Forwarded{ "Forwarded" };

					/// <summary>
					/// Header Name: From
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.5.1]
					/// </summary>
					const std::string From{ "From" };

					/// <summary>
					/// Header Name: GetProfile
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string GetProfile{ "GetProfile" };

					/// <summary>
					/// Header Name: Hobareg
					/// Protocol: HTTP
					/// Status: experimental
					/// Defined In: [RFC7486, Section 6.1.1]
					/// </summary>
					const std::string Hobareg{ "Hobareg" };

					/// <summary>
					/// Header Name: Host
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 5.4]
					/// </summary>
					const std::string Host{ "Host" };

					/// <summary>
					/// Header Name: HTTP2-Settings
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7540, Section 3.2.1]
					/// </summary>
					const std::string HTTP2Settings{ "HTTP2-Settings" };

					/// <summary>
					/// Header Name: If
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string If{ "If" };

					/// <summary>
					/// Header Name: If-Match
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.1]
					/// </summary>
					const std::string IfMatch{ "If-Match" };

					/// <summary>
					/// Header Name: If-Modified-Since
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.3]
					/// </summary>
					const std::string IfModifiedSince{ "If-Modified-Since" };

					/// <summary>
					/// Header Name: If-None-Match
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.2]
					/// </summary>
					const std::string IfNoneMatch{ "If-None-Match" };

					/// <summary>
					/// Header Name: If-Range
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 3.2]
					/// </summary>
					const std::string IfRange{ "If-Range" };

					/// <summary>
					/// Header Name: If-Schedule-Tag-Match
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6638]
					/// </summary>
					const std::string IfScheduleTagMatch{ "If-Schedule-Tag-Match" };

					/// <summary>
					/// Header Name: If-Unmodified-Since
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 3.4]
					/// </summary>
					const std::string IfUnmodifiedSince{ "If-Unmodified-Since" };

					/// <summary>
					/// Header Name: IM
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string IM{ "IM" };

					/// <summary>
					/// Header Name: Keep-Alive
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string KeepAlive{ "Keep-Alive" };

					/// <summary>
					/// Header Name: Label
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Label{ "Label" };

					/// <summary>
					/// Header Name: Last-Modified
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7232, Section 2.2]
					/// </summary>
					const std::string LastModified{ "Last-Modified" };

					/// <summary>
					/// Header Name: Link
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC5988]
					/// </summary>
					const std::string Link{ "Link" };

					/// <summary>
					/// Header Name: Location
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.2]
					/// </summary>
					const std::string Location{ "Location" };

					/// <summary>
					/// Header Name: Lock-Token
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string LockToken{ "Lock-Token" };

					/// <summary>
					/// Header Name: Man
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Man{ "Man" };

					/// <summary>
					/// Header Name: Max-Forwards
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.1.2]
					/// </summary>
					const std::string MaxForwards{ "Max-Forwards" };

					/// <summary>
					/// Header Name: Memento-Datetime
					/// Protocol: HTTP
					/// Status: Informational
					/// Defined In: [RFC7089]
					/// </summary>
					const std::string MementoDatetime{ "Memento-Datetime" };

					/// <summary>
					/// Header Name: Message-ID
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string MessageID{ "Message-ID" };

					/// <summary>
					/// Header Name: Meter
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Meter{ "Meter" };

					/// <summary>
					/// Header Name: Method-Check
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string MethodCheck{ "Method-Check" };

					/// <summary>
					/// Header Name: Method-Check-Expires
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string MethodCheckExpires{ "Method-Check-Expires" };

					/// <summary>
					/// Header Name: MIME-Version
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Appendix A.1]
					/// </summary>
					const std::string MIMEVersion{ "MIME-Version" };

					/// <summary>
					/// Header Name: Negotiate
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Negotiate{ "Negotiate" };

					/// <summary>
					/// Header Name: Non-Compliance
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string NonCompliance{ "Non-Compliance" };

					/// <summary>
					/// Header Name: Opt
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Opt{ "Opt" };

					/// <summary>
					/// Header Name: Optional
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Optional{ "Optional" };

					/// <summary>
					/// Header Name: Ordering-Type
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string OrderingType{ "Ordering-Type" };

					/// <summary>
					/// Header Name: Origin
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6454]
					/// </summary>
					const std::string Origin{ "Origin" };

					/// <summary>
					/// Header Name: Overwrite
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Overwrite{ "Overwrite" };

					/// <summary>
					/// Header Name: P3P
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string P3P{ "P3P" };

					/// <summary>
					/// Header Name: PEP
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string PEP{ "PEP" };

					/// <summary>
					/// Header Name: Pep-Info
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string PepInfo{ "Pep-Info" };

					/// <summary>
					/// Header Name: PICS-Label
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string PICSLabel{ "PICS-Label" };

					/// <summary>
					/// Header Name: Position
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Position{ "Position" };

					/// <summary>
					/// Header Name: Pragma
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.4]
					/// </summary>
					const std::string Pragma{ "Pragma" };

					/// <summary>
					/// Header Name: Prefer
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7240]
					/// </summary>
					const std::string Prefer{ "Prefer" };

					/// <summary>
					/// Header Name: Preference-Applied
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7240]
					/// </summary>
					const std::string PreferenceApplied{ "Preference-Applied" };

					/// <summary>
					/// Header Name: ProfileObject
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProfileObject{ "ProfileObject" };

					/// <summary>
					/// Header Name: Protocol
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Protocol{ "Protocol" };

					/// <summary>
					/// Header Name: Protocol-Info
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProtocolInfo{ "Protocol-Info" };

					/// <summary>
					/// Header Name: Protocol-Query
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProtocolQuery{ "Protocol-Query" };

					/// <summary>
					/// Header Name: Protocol-Request
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProtocolRequest{ "Protocol-Request" };

					/// <summary>
					/// Header Name: Proxy-Authenticate
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.3]
					/// </summary>
					const std::string ProxyAuthenticate{ "Proxy-Authenticate" };

					/// <summary>
					/// Header Name: Proxy-Authentication-Info
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7615, Section 4]
					/// </summary>
					const std::string ProxyAuthenticationInfo{ "Proxy-Authentication-Info" };

					/// <summary>
					/// Header Name: Proxy-Authorization
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.4]
					/// </summary>
					const std::string ProxyAuthorization{ "Proxy-Authorization" };

					/// <summary>
					/// Header Name: Proxy-Features
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProxyFeatures{ "Proxy-Features" };

					/// <summary>
					/// Header Name: Proxy-Instruction
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ProxyInstruction{ "Proxy-Instruction" };

					/// <summary>
					/// Header Name: Public
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Public{ "Public" };

					/// <summary>
					/// Header Name: Public-Key-Pins
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7469]
					/// </summary>
					const std::string PublicKeyPins{ "Public-Key-Pins" };

					/// <summary>
					/// Header Name: Public-Key-Pins-Report-Only
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7469]
					/// </summary>
					const std::string PublicKeyPinsReportOnly{ "Public-Key-Pins-Report-Only" };

					/// <summary>
					/// Header Name: Range
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7233, Section 3.1]
					/// </summary>
					const std::string Range{ "Range" };

					/// <summary>
					/// Header Name: Redirect-Ref
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4437]
					/// </summary>
					const std::string RedirectRef{ "Redirect-Ref" };

					/// <summary>
					/// Header Name: Referer
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.5.2]
					/// </summary>
					const std::string Referer{ "Referer" };

					/// <summary>
					/// Header Name: Referer-Root
					/// Protocol: HTTP
					/// Status: deprecated
					/// Defined In: [W3C Web Application Formats Working Group]
					/// </summary>
					const std::string RefererRoot{ "Referer-Root" };

					/// <summary>
					/// Header Name: Resolution-Hint
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ResolutionHint{ "Resolution-Hint" };

					/// <summary>
					/// Header Name: Resolver-Location
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string ResolverLocation{ "Resolver-Location" };

					/// <summary>
					/// Header Name: Retry-After
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.3]
					/// </summary>
					const std::string RetryAfter{ "Retry-After" };

					/// <summary>
					/// Header Name: Safe
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Safe{ "Safe" };

					/// <summary>
					/// Header Name: Schedule-Reply
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6638]
					/// </summary>
					const std::string ScheduleReply{ "Schedule-Reply" };

					/// <summary>
					/// Header Name: Schedule-Tag
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6638]
					/// </summary>
					const std::string ScheduleTag{ "Schedule-Tag" };

					/// <summary>
					/// Header Name: Sec-WebSocket-Accept
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketAccept{ "Sec-WebSocket-Accept" };

					/// <summary>
					/// Header Name: Sec-WebSocket-Extensions
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketExtensions{ "Sec-WebSocket-Extensions" };

					/// <summary>
					/// Header Name: Sec-WebSocket-Key
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketKey{ "Sec-WebSocket-Key" };

					/// <summary>
					/// Header Name: Sec-WebSocket-Protocol
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketProtocol{ "Sec-WebSocket-Protocol" };

					/// <summary>
					/// Header Name: Sec-WebSocket-Version
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6455]
					/// </summary>
					const std::string SecWebSocketVersion{ "Sec-WebSocket-Version" };

					/// <summary>
					/// Header Name: Security-Scheme
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SecurityScheme{ "Security-Scheme" };

					/// <summary>
					/// Header Name: Server
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.4.2]
					/// </summary>
					const std::string Server{ "Server" };

					/// <summary>
					/// Header Name: Set-Cookie
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6265]
					/// </summary>
					const std::string SetCookie{ "Set-Cookie" };

					/// <summary>
					/// Header Name: Set-Cookie2
					/// Protocol: HTTP
					/// Status: obsoleted
					/// Defined In: [RFC2965][RFC6265]
					/// </summary>
					const std::string SetCookie2{ "Set-Cookie2" };

					/// <summary>
					/// Header Name: SetProfile
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SetProfile{ "SetProfile" };

					/// <summary>
					/// Header Name: SLUG
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC5023]
					/// </summary>
					const std::string SLUG{ "SLUG" };

					/// <summary>
					/// Header Name: SoapAction
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SoapAction{ "SoapAction" };

					/// <summary>
					/// Header Name: Status-URI
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string StatusURI{ "Status-URI" };

					/// <summary>
					/// Header Name: Strict-Transport-Security
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC6797]
					/// </summary>
					const std::string StrictTransportSecurity{ "Strict-Transport-Security" };

					/// <summary>
					/// Header Name: SubOK
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SubOK{ "SubOK" };

					/// <summary>
					/// Header Name: Subst
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Subst{ "Subst" };

					/// <summary>
					/// Header Name: Surrogate-Capability
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SurrogateCapability{ "Surrogate-Capability" };

					/// <summary>
					/// Header Name: Surrogate-Control
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string SurrogateControl{ "Surrogate-Control" };

					/// <summary>
					/// Header Name: TCN
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string TCN{ "TCN" };

					/// <summary>
					/// Header Name: TE
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 4.3]
					/// </summary>
					const std::string TE{ "TE" };

					/// <summary>
					/// Header Name: Timeout
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC4918]
					/// </summary>
					const std::string Timeout{ "Timeout" };

					/// <summary>
					/// Header Name: Title
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Title{ "Title" };

					/// <summary>
					/// Header Name: Trailer
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 4.4]
					/// </summary>
					const std::string Trailer{ "Trailer" };

					/// <summary>
					/// Header Name: Transfer-Encoding
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 3.3.1]
					/// </summary>
					const std::string TransferEncoding{ "Transfer-Encoding" };

					/// <summary>
					/// Header Name: UA-Color
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAColor{ "UA-Color" };

					/// <summary>
					/// Header Name: UA-Media
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAMedia{ "UA-Media" };

					/// <summary>
					/// Header Name: UA-Pixels
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAPixels{ "UA-Pixels" };

					/// <summary>
					/// Header Name: UA-Resolution
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAResolution{ "UA-Resolution" };

					/// <summary>
					/// Header Name: UA-Windowpixels
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string UAWindowpixels{ "UA-Windowpixels" };

					/// <summary>
					/// Header Name: Upgrade
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 6.7]
					/// </summary>
					const std::string Upgrade{ "Upgrade" };

					/// <summary>
					/// Header Name: URI
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string URI{ "URI" };

					/// <summary>
					/// Header Name: User-Agent
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 5.5.3]
					/// </summary>
					const std::string UserAgent{ "User-Agent" };

					/// <summary>
					/// Header Name: Variant-Vary
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string VariantVary{ "Variant-Vary" };

					/// <summary>
					/// Header Name: Vary
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7231, Section 7.1.4]
					/// </summary>
					const std::string Vary{ "Vary" };

					/// <summary>
					/// Header Name: Version
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string Version{ "Version" };

					/// <summary>
					/// Header Name: Via
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7230, Section 5.7.1]
					/// </summary>
					const std::string Via{ "Via" };

					/// <summary>
					/// Header Name: Want-Digest
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [RFC4229]
					/// </summary>
					const std::string WantDigest{ "Want-Digest" };

					/// <summary>
					/// Header Name: Warning
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7234, Section 5.5]
					/// </summary>
					const std::string Warning{ "Warning" };

					/// <summary>
					/// Header Name: WWW-Authenticate
					/// Protocol: HTTP
					/// Status: Standard
					/// Defined In: [RFC7235, Section 4.1]
					/// </summary>
					const std::string WWWAuthenticate{ "WWW-Authenticate" };

					/// <summary>
					/// Header Name: X-Device-Accept
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAccept{ "X-Device-Accept" };

					/// <summary>
					/// Header Name: X-Device-Accept-Charset
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAcceptCharset{ "X-Device-Accept-Charset" };

					/// <summary>
					/// Header Name: X-Device-Accept-Encoding
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAcceptEncoding{ "X-Device-Accept-Encoding" };

					/// <summary>
					/// Header Name: X-Device-Accept-Language
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceAcceptLanguage{ "X-Device-Accept-Language" };

					/// <summary>
					/// Header Name: X-Device-User-Agent
					/// Protocol: HTTP
					/// Status: Proposed
					/// Defined In: [W3C Mobile Web Best Practices Working Group]
					/// </summary>
					const std::string XDeviceUserAgent{ "X-Device-User-Agent" };

					/// <summary>
					/// Header Name: X-Frame-Options
					/// Protocol: HTTP
					/// Status: Informational
					/// Defined In: [RFC7034]
					/// </summary>
					const std::string XFrameOptions{ "X-Frame-Options" };
					// Common but non-standard request headers

					/// <summary>
					/// Header Name: X-Requested-With
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XRequestedWith{ "X-Requested-With" };

					/// <summary>
					/// Header Name: DNT
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string DNT{ "DNT" };

					/// <summary>
					/// Header Name: X-Forwarded-For
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XForwardedFor{ "X-Forwarded-For" };

					/// <summary>
					/// Header Name: X-Forwarded-Host
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XForwardedHost{ "X-Forwarded-Host" };

					/// <summary>
					/// Header Name: X-Forwarded-Proto
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XForwardedProto{ "X-Forwarded-Proto" };

					/// <summary>
					/// Header Name: Front-End-Https
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string FrontEndHttps{ "Front-End-Https" };

					/// <summary>
					/// Header Name: X-Http-Method-Override
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XHttpMethodOverride{ "X-Http-Method-Override" };

					/// <summary>
					/// Header Name: X-ATT-DeviceId
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XATTDeviceId{ "X-ATT-DeviceId" };

					/// <summary>
					/// Header Name: X-Wap-Profile
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XWapProfile{ "X-Wap-Profile" };

					/// <summary>
					/// Header Name: Proxy-Connection
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string ProxyConnection{ "Proxy-Connection" };

					/// <summary>
					/// Header Name: X-UIDH
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XUIDH{ "X-UIDH" };

					/// <summary>
					/// Header Name: X-Csrf-Token
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XCsrfToken{ "X-Csrf-Token" };
					// Common but non-standard response headers

					/// <summary>
					/// Header Name: X-XSS-Protection
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XXSSProtection{ "X-XSS-Protection" };

					/// <summary>
					/// Header Name: Content-Security-Policy
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string ContentSecurityPolicy{ "Content-Security-Policy" };

					/// <summary>
					/// Header Name: X-Content-Security-Policy
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XContentSecurityPolicy{ "X-Content-Security-Policy" };

					/// <summary>
					/// Header Name: X-WebKit-CSP
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XWebKitCSP{ "X-WebKit-CSP" };

					/// <summary>
					/// Header Name: X-Content-Type-Options
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XContentTypeOptions{ "X-Content-Type-Options" };

					/// <summary>
					/// Header Name: X-Powered-By
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XPoweredBy{ "X-Powered-By" };

					/// <summary>
					/// Header Name: X-UA-Compatible
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XUACompatible{ "X-UA-Compatible" };

					/// <summary>
					/// Header Name: X-Content-Duration
					/// Protocol: HTTP
					/// Status: Non-Standard Common
					/// Defined In: Nowhereville
					/// </summary>
					const std::string XContentDuration{ "X-Content-Duration" };

					/// <summary>
					/// Header Name: Get-Dictionary
					/// Protocol: HTTP
					/// Status: Non-Standard
					/// Defined In: Made up by Google to support SDHC compression.
					/// </summary>
					const std::string GetDictionary{ "Get-Dictionary" };

					/// <summary>
					/// Header Name: X-SDHC
					/// Protocol: HTTP
					/// Status: Non-Standard
					/// Defined In: Made up by Google to support SDHC compression.
					/// </summary>
					const std::string XSDHC{ "X-SDHC" };

					/// <summary>
					/// Header Name: Avail-Dictionary
					/// Protocol: HTTP
					/// Status: Non-Standard
					/// Defined In: Made up by Google to support SDHC compression.
					/// </summary>
					const std::string AvailDictionary{ "Avail-Dictionary" };

					/// <summary>
					/// Header Name: Alternate-Protocol
					/// Protocol: HTTP
					/// Status: Non-Standard
					/// Defined In: Made up by Google to hint to use QUIC over HTTP.
					/// </summary>
					const std::string AlternateProtocol{ "Alternate-Protocol" };

					/// <summary>
					/// Header Name: Alternate-Protocol
					/// Protocol: HTTP Extension
					/// Status: Unknown
					/// Defined In: http://httpwg.org/http-extensions/alt-svc.html
					/// </summary>
					const std::string AltSvc{ "Alt-Svc" };

				} /* namespace headers */
			} /* namespace http */
		} /* namespace util */
	} /* namespace httpengine */
} /* namespace te */