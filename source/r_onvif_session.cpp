#ifdef IS_WINDOWS
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1
#endif

#include <thread>
#include <sstream>
#include <map>
#include "r_http/r_client_request.h"
#include "r_http/r_methods.h"
#include "r_utils/r_sha1.h"
#include "r_utils/r_string_utils.h"


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <sys/stat.h>
#include "libxml/xpathInternals.h"
#include "r_onvif/r_onvif_session.h"
#include "r_utils/r_socket.h"
#include "r_utils/r_string_utils.h"
#include "r_utils/r_sha1.h"
#include "r_utils/r_time_utils.h"
#include "r_utils/r_uuid.h"
#include "r_utils/r_udp_sender.h"
#include "r_utils/r_udp_receiver.h"
#include "r_utils/r_udp_socket.h"
#include "r_utils/r_std_utils.h"
#include "r_http/r_utils.h"
#include "r_http/r_client_response.h"
#include "r_http/r_status_codes.h"
#include "r_http/r_utils.h"

#ifdef IS_WINDOWS
    #include <ws2tcpip.h>
    #include <winsock2.h>
    #include <wincrypt.h>
    #include <iphlpapi.h>
    #include <io.h>
    #include <fcntl.h>
    #include <stdio.h>
    #include <time.h>
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <ifaddrs.h>
    #include <sys/ioctl.h>
    #include <sys/types.h>
    #include <net/if.h>
    #include <netinet/in.h>
    #include <sys/time.h>
#endif

using namespace r_onvif;
using namespace r_utils;
using namespace r_utils::r_std_utils;
using namespace std;

static pair<int, string> _http_interact(
    const string& host,
    int port,
    const string& http_method,
    const string& uri,
    const string& body
)
{
    r_socket socket;
    socket.connect(host, port);

    r_http::r_client_request request(host, port);
    request.set_method(r_http::method_type(http_method));
    request.set_uri(uri);
    request.set_body(body);

    request.write_request(socket);

    r_http::r_client_response response;
    response.read_response(socket);

    socket.close();

    auto maybe_body = response.get_body_as_string();

    if(maybe_body.is_null())
        return make_pair(response.get_status(), string());

    return make_pair(response.get_status(), maybe_body.value());
}

static time_t _portable_timegm(struct tm* t)
{
#ifdef IS_WINDOWS
    // Windows implementation
    return _mkgmtime(t); // Windows has _mkgmtime for UTC time
#else
    // POSIX implementation
    char* tz = getenv("TZ");
    setenv("TZ", "UTC", 1);
    tzset();
    time_t result = mktime(t);
    if (tz)
        setenv("TZ", tz, 1);
    else unsetenv("TZ");
    tzset();
    return result;
#endif
}

static r_nullable<time_t> _parse_onvif_date_time(const std::string& xmlResponse)
{
    r_nullable<time_t> response;

    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_string(xmlResponse.c_str());

    // Check for DaylightSavings
    bool daylightSavings = false;
    pugi::xpath_node dstNode = doc.select_node("//tt:DaylightSavings");
    if (dstNode)
    {
        std::string dstValue = dstNode.node().child_value();
        daylightSavings = (dstValue == "true" || dstValue == "1");
    }
    
    // Try to get timezone information
    std::string timezone;
    pugi::xpath_node tzNode = doc.select_node("//tt:TZ");
    if (tzNode)
    {
        timezone = tzNode.node().child_value();
    }
    
    // First try to get UTCDateTime
    struct tm timeinfo = {};
    bool useUtc = false;
    
    pugi::xpath_node utcNode = doc.select_node("//tt:UTCDateTime");
    if (utcNode)
    {
        pugi::xml_node utcElement = utcNode.node();
        
        // Get year, month, day
        pugi::xpath_node dateNode = utcElement.select_node(".//tt:Date");
        if (dateNode)
        {
            pugi::xml_node dateElement = dateNode.node();
            
            pugi::xpath_node yearNode = dateElement.select_node(".//tt:Year");
            pugi::xpath_node monthNode = dateElement.select_node(".//tt:Month");
            pugi::xpath_node dayNode = dateElement.select_node(".//tt:Day");
            
            if (yearNode && monthNode && dayNode)
            {
                timeinfo.tm_year = std::stoi(yearNode.node().child_value()) - 1900;
                timeinfo.tm_mon = std::stoi(monthNode.node().child_value()) - 1;
                timeinfo.tm_mday = std::stoi(dayNode.node().child_value());
            }
        }
        
        // Get hour, minute, second
        pugi::xpath_node timeNode = utcElement.select_node(".//tt:Time");
        if (timeNode)
        {
            pugi::xml_node timeElement = timeNode.node();
            
            pugi::xpath_node hourNode = timeElement.select_node(".//tt:Hour");
            pugi::xpath_node minuteNode = timeElement.select_node(".//tt:Minute");
            pugi::xpath_node secondNode = timeElement.select_node(".//tt:Second");
            
            if (hourNode && minuteNode && secondNode)
            {
                timeinfo.tm_hour = std::stoi(hourNode.node().child_value());
                timeinfo.tm_min = std::stoi(minuteNode.node().child_value());
                timeinfo.tm_sec = std::stoi(secondNode.node().child_value());
            }
        }
        
        useUtc = true;
    }
    
    // If no UTCDateTime, try LocalDateTime
    if (!useUtc)
    {
        pugi::xpath_node localNode = doc.select_node("//tt:LocalDateTime");
        if (localNode)
        {
            pugi::xml_node localElement = localNode.node();
            
            // Get year, month, day
            pugi::xpath_node dateNode = localElement.select_node(".//tt:Date");
            if (dateNode)
            {
                pugi::xml_node dateElement = dateNode.node();
                
                pugi::xpath_node yearNode = dateElement.select_node(".//tt:Year");
                pugi::xpath_node monthNode = dateElement.select_node(".//tt:Month");
                pugi::xpath_node dayNode = dateElement.select_node(".//tt:Day");
                
                if (yearNode && monthNode && dayNode)
                {
                    timeinfo.tm_year = std::stoi(yearNode.node().child_value()) - 1900;
                    timeinfo.tm_mon = std::stoi(monthNode.node().child_value()) - 1;
                    timeinfo.tm_mday = std::stoi(dayNode.node().child_value());
                }
            }
            
            // Get hour, minute, second
            pugi::xpath_node timeNode = localElement.select_node(".//tt:Time");
            if (timeNode)
            {
                pugi::xml_node timeElement = timeNode.node();
                
                pugi::xpath_node hourNode = timeElement.select_node(".//tt:Hour");
                pugi::xpath_node minuteNode = timeElement.select_node(".//tt:Minute");
                pugi::xpath_node secondNode = timeElement.select_node(".//tt:Second");
                
                if (hourNode && minuteNode && secondNode)
                {
                    timeinfo.tm_hour = std::stoi(hourNode.node().child_value());
                    timeinfo.tm_min = std::stoi(minuteNode.node().child_value());
                    timeinfo.tm_sec = std::stoi(secondNode.node().child_value());
                }
            }
        }
    }

    // Convert to time_t
    time_t timestamp = 0;
    
    // If we have local time with timezone info
    if (!useUtc && !timezone.empty())
    {
        // First convert the local time to a time_t (treating it temporarily as UTC)
        time_t localAsUtc = _portable_timegm(&timeinfo);
        
        // Parse timezone in format like "GMT-05:00" or "GMT+01:00"
        int offsetSeconds = 0;
        
        // Skip the "GMT" prefix
        size_t pos = timezone.find("GMT");
        if (pos != std::string::npos)
        {
            std::string offset = timezone.substr(pos + 3);
            
            char sign = offset[0];
            if (sign == '+' || sign == '-')
            {
                // Parse hours and minutes
                size_t colonPos = offset.find(':');
                if (colonPos != std::string::npos)
                {
                    int offsetHours = std::stoi(offset.substr(1, colonPos - 1));
                    int offsetMinutes = std::stoi(offset.substr(colonPos + 1));
                    
                    // Calculate total seconds
                    offsetSeconds = (offsetHours * 3600) + (offsetMinutes * 60);
                    
                    // Apply the sign (note the direction - when converting local to UTC)
                    // For example: GMT-05:00 means UTC is 5 hours ahead of local time
                    // So to convert local to UTC, we ADD 5 hours
                    if (sign == '-')
                        offsetSeconds = offsetSeconds; // Positive - add to local time
                    else
                        offsetSeconds = -offsetSeconds; // Negative - subtract from local time
                }
            }
        }
        
        // Apply DST correction if needed
        if (daylightSavings)
            offsetSeconds -= 3600; // Subtract 1 hour
        
        // Apply both timezone and DST adjustments to get UTC
        timestamp = localAsUtc + offsetSeconds;
    }
    else if (useUtc)
        timestamp = _portable_timegm(&timeinfo); // We already have UTC time, just convert it
    else
    {
        // No timezone info, assume it's in local timezone
        timeinfo.tm_isdst = daylightSavings ? 1 : 0;
        timestamp = mktime(&timeinfo);
    }

    response = timestamp;
    
    return response;
}

static string _find_element_value(const string& xml, const vector<string>& path, const map<string, string>& namespaces)
{
    // Parse the XML document
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_string(xml.c_str());
    if (!result)
        throw std::runtime_error("XML parsing failed: " + string(result.description()));

    // Start at document element
    pugi::xml_node currentNode = doc.document_element();

    // Helper function to check if element matches a name with namespace
    auto matchesElement = [&namespaces](const pugi::xml_node& element, const string& pathPart)
    {
        // Check if path part contains namespace prefix
        size_t colonPos = pathPart.find(':');
        if (colonPos != string::npos)
        {
            string nsPrefix = pathPart.substr(0, colonPos);
            string localName = pathPart.substr(colonPos + 1);

            // Look up namespace URI
            auto nsIter = namespaces.find(nsPrefix);
            if (nsIter != namespaces.end())
            {
                // PugiXML: Check namespace and local name
                string elementName = element.name();
                string elementPrefix;
                size_t elemColonPos = elementName.find(':');
                if (elemColonPos != string::npos)
                    elementPrefix = elementName.substr(0, elemColonPos);

                // Get namespace from element
                string elementNsUri = element.attribute("xmlns:" + elementPrefix).value();
                if (elementNsUri.empty())
                {
                    // Look for namespace in parent hierarchy
                    pugi::xml_node parent = element.parent();
                    while (parent && elementNsUri.empty())
                    {
                        elementNsUri = parent.attribute("xmlns:" + elementPrefix).value();
                        parent = parent.parent();
                    }
                }

                // Check if namespace matches and element name matches the local name
                if (elementNsUri == nsIter->second)
                {
                    string elemLocalName = (elemColonPos != string::npos) ? 
                        elementName.substr(elemColonPos + 1) : elementName;
                    return elemLocalName == localName;
                }
                return false;
            }
            return false;
        }
        else
        {
            // Just check node name directly if no namespace
            string elementName = element.name();
            size_t elemColonPos = elementName.find(':');
            string elemLocalName = (elemColonPos != string::npos) ? 
                elementName.substr(elemColonPos + 1) : elementName;
            
            return elemLocalName == pathPart || elementName == pathPart;
        }
    };

    // Navigate through each level of the path
    for (size_t i = 0; i < path.size(); i++)
    {
        const string& pathPart = path[i];
        bool found = false;

        // Check if current element matches this path part
        if (matchesElement(currentNode, pathPart))
        {
            found = true;
            // If this is the last part of the path, we've found our target
            if (i == path.size() - 1)
            {
                // Return the text content
                return currentNode.child_value();
            }

            // Navigate to first child for next iteration
            pugi::xml_node child = currentNode.first_child();
            while (child)
            {
                if (child.type() == pugi::node_element)
                {
                    currentNode = child;
                    break;
                }
                child = child.next_sibling();
            }
            if (!child)
                return ""; // No child elements to continue path
            continue; // Skip to next path part
        }

        // Look for matching child element
        pugi::xml_node child = currentNode.first_child();
        while (child)
        {
            if (child.type() == pugi::node_element)
            {
                if (matchesElement(child, pathPart))
                {
                    currentNode = child;
                    found = true;
                    break;
                }
            }
            child = child.next_sibling();
        }

        if (!found)
        {
            // Try to find any descendant that matches
            // PugiXML doesn't have a direct equivalent to getElementsByTagName
            // so we'll use a recursive approach or XPath
            string xpathQuery = ".//" + pathPart;
            pugi::xpath_node descendant = currentNode.select_node(xpathQuery.c_str());
            if (descendant)
            {
                currentNode = descendant.node();
                found = true;
            }
        }

        if (!found)
            return ""; // Path part not found

        // If this is the last part of the path, we've found our target
        if (i == path.size() - 1)
        {
            // Return the text content
            return currentNode.child_value();
        }
    }

    return ""; // Should not reach here if path is non-empty
}

static string _extract_value(const string& xmlDocument, const string& path, const map<string, string>& namespaces)
{
    vector<string> elementPath;
    size_t start = 0;
    size_t pos = 0;
 
    // Split path by '//' to create element path
    while ((pos = path.find("//", start)) != string::npos)
    {
        if (pos > start)
            elementPath.push_back(path.substr(start, pos - start));
        start = pos + 2;
    }
 
    // Add last element
    if (start < path.length())
        elementPath.push_back(path.substr(start));
 
    return _find_element_value(xmlDocument, elementPath, namespaces);
}

static string _extract_onvif_value(const string& xmlDocument, const string& path)
{
    map<string, string> namespaces =
    {
        {"s", "http://www.w3.org/2003/05/soap-envelope"},
        {"tds", "http://www.onvif.org/ver10/device/wsdl"},
        {"tt", "http://www.onvif.org/ver10/schema"},
        {"trt", "http://www.onvif.org/ver10/media/wsdl"},
        {"timg", "http://www.onvif.org/ver20/imaging/wsdl"},
        {"tev", "http://www.onvif.org/ver10/events/wsdl"},
        {"tan", "http://www.onvif.org/ver20/analytics/wsdl"},
        {"tptz", "http://www.onvif.org/ver20/ptz/wsdl"}
    };
 
    return _extract_value(xmlDocument, path, namespaces);
}

static r_nullable<string> _get_scope_field(const string& scope, const string& field_name)
{
    r_nullable<string> output;

    auto pos = scope.find(field_name);
    if(pos != string::npos)
    {
        auto space_pos = scope.find(" ", pos);

        auto contents = (space_pos != string::npos)?scope.substr(pos, space_pos - pos):scope.substr(pos);
        auto last_slash = contents.rfind("/");
        auto start = (last_slash == string::npos)?0:last_slash + 1;
        output.set_value(r_string_utils::uri_decode(contents.substr(start)));
    }

    return output;
}

vector<string> r_onvif::discover(const string& uuid)
{
    auto id = r_string_utils::format("urn:uuid:%s", uuid.c_str());

    vector<string> discovered;

    string broadcast_message =
    "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"><SOAP-ENV:Header><a:Action SOAP-ENV:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action><a:MessageID>" + id + "</a:MessageID><a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:To SOAP-ENV:mustUnderstand=\"1\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></SOAP-ENV:Header><SOAP-ENV:Body><p:Probe xmlns:p=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><d:Types xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:dp0=\"http://www.onvif.org/ver10/network/wsdl\">dp0:NetworkVideoTransmitter</d:Types></p:Probe></SOAP-ENV:Body></SOAP-ENV:Envelope>";

    r_udp_socket socket;

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    int broadcast = 1000;
    char loopch = 0;
    int status = 0;
    struct in_addr localInterface;

#ifdef IS_WINDOWS
    PMIB_IPADDRTABLE pIPAddrTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    IN_ADDR IPAddr;

    pIPAddrTable = (MIB_IPADDRTABLE *) malloc(sizeof(MIB_IPADDRTABLE));
    if (pIPAddrTable) {
        if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
            free(pIPAddrTable);
            pIPAddrTable = (MIB_IPADDRTABLE *) malloc(dwSize);
        }
        if (pIPAddrTable == NULL) {
            printf("Memory allocation failed for GetIpAddrTable\n");
            return;
        }
    }

    if ((dwRetVal = GetIpAddrTable(pIPAddrTable, &dwSize, 0)) != NO_ERROR) {
        printf("GetIpAddrTable failed with error %lu\n", dwRetVal);
        return;
    }

    int p = 0;
    while (p < (int)pIPAddrTable->dwNumEntries) {
        IPAddr.S_un.S_addr = (u_long)pIPAddrTable->table[p].dwAddr;
        IPAddr.S_un.S_addr = (u_long)pIPAddrTable->table[p].dwMask;
        if (pIPAddrTable->table[p].dwAddr != inet_addr("127.0.0.1") && pIPAddrTable->table[p].dwMask == inet_addr("255.255.255.0")) {
            localInterface.s_addr = pIPAddrTable->table[p].dwAddr;
            status = setsockopt(socket.fd(), IPPROTO_IP, IP_MULTICAST_IF, (const char *)&localInterface, sizeof(localInterface));
            if (status < 0)
                printf("ip_multicast_if error");
            p = (int)pIPAddrTable->dwNumEntries;
        }
        p++;
    }

    if (pIPAddrTable) {
        free(pIPAddrTable);
        pIPAddrTable = NULL;
    }

    status = setsockopt(socket.fd(), SOL_SOCKET, SO_RCVTIMEO, (const char *)&broadcast, sizeof(broadcast));
#else
    status = setsockopt(socket.fd(), SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
#endif
    status = setsockopt(socket.fd(), IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch));

    r_socket_address addr(3702, "239.255.255.250");

    socket.sendto((uint8_t*)broadcast_message.c_str(), broadcast_message.length(), addr);

    char buf[2048];
    int len;

    bool done = false;
    while(!done)
    {
        len = socket.recvfrom((uint8_t*)buf, 2048, addr);

        if(len < 0)
            done = true;
        else if(len > 0)
        {
            discovered.push_back(string(buf, len));
        }
    }

    return discovered;
}

std::vector<discovered_info> r_onvif::filter_discovered(const std::vector<std::string>& discovered)
{
    std::vector<discovered_info> filtered;
    std::map<std::string, bool> hosts_seen;
    for( auto d : discovered)
    {
        try
        {
            pugi::xml_document doc;
            pugi::xml_parse_result result = doc.load_string(d.c_str());
            if (!result)
                throw std::runtime_error("Failed to parse XML: " + std::string(result.description()));
            
            // Define namespaces
            const char* d_ns_uri = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
            const char* s_ns_uri = "http://www.w3.org/2003/05/soap-envelope";
            const char* a_ns_uri = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
            
            // Use XPath with namespace to find XAddrs nodes
            std::string xpath_query = "//*[local-name()='XAddrs' and namespace-uri()='" + std::string(d_ns_uri) + "']";
            pugi::xpath_query query(xpath_query.c_str());
            pugi::xpath_node_set nodes = query.evaluate_node_set(doc);
            
            // Use XPath to find Address node
            std::string addr_xpath = "//*[local-name()='Body' and namespace-uri()='" + std::string(s_ns_uri) + "']"
                                    "/*[local-name()='ProbeMatches' and namespace-uri()='" + std::string(d_ns_uri) + "']"
                                    "/*[local-name()='ProbeMatch' and namespace-uri()='" + std::string(d_ns_uri) + "']"
                                    "/*[local-name()='EndpointReference' and namespace-uri()='" + std::string(a_ns_uri) + "']"
                                    "/*[local-name()='Address' and namespace-uri()='" + std::string(a_ns_uri) + "']";
            
            pugi::xpath_query addr_query(addr_xpath.c_str());
            pugi::xpath_node addr_node = addr_query.evaluate_node(doc);
            
            // Get the address value
            std::string address = "";
            if (addr_node)
            {
                address = addr_node.node().text().get();
            }
            
            // Use XPath to find Scopes node
            std::string scopes_xpath = "//*[local-name()='Body' and namespace-uri()='" + std::string(s_ns_uri) + "']"
                                      "/*[local-name()='ProbeMatches' and namespace-uri()='" + std::string(d_ns_uri) + "']"
                                      "/*[local-name()='ProbeMatch' and namespace-uri()='" + std::string(d_ns_uri) + "']"
                                      "/*[local-name()='Scopes' and namespace-uri()='" + std::string(d_ns_uri) + "']";
            
            pugi::xpath_query scopes_query(scopes_xpath.c_str());
            pugi::xpath_node scopes_node = scopes_query.evaluate_node(doc);
            
            // Get the scopes value
            std::string scopes = "";
            if (scopes_node)
            {
                scopes = scopes_node.node().text().get();
            }
            
            std::vector<std::string> xaddrs_services;
            for (pugi::xpath_node node : nodes)
            {
                std::string text = node.node().text().get();
                std::vector<std::string> addresses = r_string_utils::split(text, " ");
                xaddrs_services.insert(end(xaddrs_services), begin(addresses), end(addresses));
            }
            if (xaddrs_services.empty())
                throw std::runtime_error("No ONVIF services found1.");
            int first_connnected_index = -1;
            for(int i = 0; i < xaddrs_services.size(); ++i)
            {
                auto service = xaddrs_services[i];
                string url, host, protocol, uri;
                int port;
                r_http::parse_url_parts(service, host, port, protocol, uri);
                if(protocol != "http")
                    continue;
                
                try
                {
                    r_socket socket;
                    socket.set_io_timeout(500);
                    socket.connect(host, port);
                    socket.close();
                    first_connnected_index = i;
                    break;
                }
                catch(...)
                {
                    // ignoring individual connection errors...
                }
            }
            // But, we do need to throw if we couldn't connect to ANY of the services.
            if(first_connnected_index == -1)
                throw std::runtime_error("No ONVIF services found2.");
            discovered_info di;
            r_http::parse_url_parts(xaddrs_services[first_connnected_index], di.host, di.port, di.protocol, di.uri);
            di.address = address; // Assign the extracted address to the discovered_info struct

            auto mfgr = _get_scope_field(scopes, (char*)"onvif://www.onvif.org/name/");
            auto hdwr = _get_scope_field(scopes, (char*)"onvif://www.onvif.org/hardware/");

            // SAMSUNG E4500n
            // SAMSUNG 192.168.1.11
            // E4500n 192

            string camera_name;

            if(!mfgr.is_null())
                camera_name = mfgr.value();

            if(camera_name.empty())
                camera_name = di.host;

            di.camera_name = camera_name;

            if(hosts_seen.find(di.host) == hosts_seen.end())
            {
                filtered.push_back(di);
                hosts_seen[di.host] = true;
            }
        }
        catch(...)
        {
            // Some problem parsing something we discovered. squelching here so we can continue.
        }
    }
    return filtered;
}

r_onvif::r_onvif_cam::r_onvif_cam(const std::string& host, int port, const std::string& protocol, const std::string& uri, const r_utils::r_nullable<std::string>& username, const r_utils::r_nullable<std::string>& password)
{
    _service_host = host;
    _service_port = port;
    _service_protocol = protocol;
    _service_uri = uri;

    auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
    auto camera_time = get_camera_system_date_and_time();

    _time_offset_seconds = (int)((int64_t)camera_time - (int64_t)now);

    _username = username;
    _password = password;
}

time_t r_onvif::r_onvif_cam::get_camera_system_date_and_time() const
{
    // Create the equivalent SOAP XML document using PugiXML
    pugi::xml_document doc;

    // Add XML declaration
    pugi::xml_node declaration = doc.append_child(pugi::node_declaration);
    declaration.append_attribute("version") = "1.0";
    declaration.append_attribute("encoding") = "UTF-8";

    // Create the envelope element with namespace
    pugi::xml_node envelope = doc.append_child("SOAP-ENV:Envelope");
    envelope.append_attribute("xmlns:SOAP-ENV") = "http://www.w3.org/2003/05/soap-envelope";
    envelope.append_attribute("xmlns:tds") = "http://www.onvif.org/ver10/device/wsdl";

    // Create the body element with namespace
    pugi::xml_node body = envelope.append_child("SOAP-ENV:Body");

    // Create the GetSystemDateAndTime element with namespace
    pugi::xml_node getSysDateAndTime = body.append_child("tds:GetSystemDateAndTime");

    // Convert to string
    std::stringstream ss;
    doc.save(ss, "", pugi::format_raw); // format_raw for minimal formatting

    auto result = _http_interact(_service_host, _service_port, "POST", _service_uri, ss.str());

    auto maybe_parsed_ts = _parse_onvif_date_time(result.second);

    if(maybe_parsed_ts.is_null())
        throw std::runtime_error("Failed to parse ONVIF date and time.");

    return maybe_parsed_ts.value();
}

r_onvif::onvif_capabilities r_onvif::r_onvif_cam::get_camera_capabilities() const
{
    // Create XML document
    pugi::xml_document doc;
    
    // Add XML declaration
    pugi::xml_node declaration = doc.append_child(pugi::node_declaration);
    declaration.append_attribute("version") = "1.0";
    declaration.append_attribute("encoding") = "UTF-8";
    
    // Create root SOAP envelope element with namespace
    pugi::xml_node root = doc.append_child("SOAP-ENV:Envelope");
    root.append_attribute("xmlns:SOAP-ENV") = "http://www.w3.org/2003/05/soap-envelope";
    root.append_attribute("xmlns:tds") = "http://www.onvif.org/ver10/device/wsdl";
    
    // Add authentication header if credentials are provided
    if (_username && _password)
        _add_username_digest_header(&doc, root, _username.value(), _password.value(), _time_offset_seconds);
    
    // Create SOAP body
    pugi::xml_node body = root.append_child("SOAP-ENV:Body");
    
    // Create GetCapabilities element
    pugi::xml_node capabilities = body.append_child("tds:GetCapabilities");
    
    // Create Category element
    pugi::xml_node category = capabilities.append_child("tds:Category");
    
    // Set category text to "All"
    category.text().set("All");
    
    // Write XML to string
    std::ostringstream oss;
    doc.save(oss, "  ", pugi::format_default | pugi::format_indent);
    
    // Send HTTP request
    auto result = _http_interact(_service_host, _service_port, "POST", _service_uri, oss.str());
    
    // Check status code
    if (result.first != 200)
        throw std::runtime_error("Failed to get camera capabilities");
    
    return result.second;
}

r_onvif::onvif_media_service r_onvif::r_onvif_cam::get_media_service(const r_onvif::onvif_capabilities& capabilities) const
{
    return _extract_onvif_value(capabilities, "//tt:Media//tt:XAddr");
#if 0
    auto media_service = _extract_onvif_value(capabilities, "//tt:Media//tt:XAddr");

    string host, protocol, uri;
    int port;
    r_http::parse_url_parts(media_service, host, port, protocol, uri);

    return uri;
#endif
}

std::vector<r_onvif::onvif_profile_info> r_onvif::r_onvif_cam::get_profile_tokens(r_onvif::onvif_media_service media_service)
{
    // Create the SOAP request document
    pugi::xml_document doc;

    // Add XML declaration
    pugi::xml_node declaration = doc.append_child(pugi::node_declaration);
    declaration.append_attribute("version") = "1.0";
    declaration.append_attribute("encoding") = "UTF-8";

    // Create root element with namespace
    pugi::xml_node root = doc.append_child("SOAP-ENV:Envelope");
    root.append_attribute("xmlns:SOAP-ENV") = "http://www.w3.org/2003/05/soap-envelope";
    root.append_attribute("xmlns:trt") = "http://www.onvif.org/ver10/media/wsdl";
    root.append_attribute("xmlns:tt") = "http://www.onvif.org/ver10/schema"; // Add this line

    // Add authentication header if credentials are provided
    if(_username && _password)
        _add_username_digest_header(&doc, root, _username.value(), _password.value(), _time_offset_seconds);

    // Create SOAP body
    pugi::xml_node body = root.append_child("SOAP-ENV:Body");

    // Create GetProfiles element
    pugi::xml_node getProfiles = body.append_child("trt:GetProfiles");

    // Serialize to string with pretty printing
    std::ostringstream oss;
    doc.save(oss, "  ", pugi::format_default | pugi::format_indent);
    auto request = oss.str();

    string host, protocol, uri;
    int port;
    r_http::parse_url_parts(media_service, host, port, protocol, uri);

    // Send HTTP request
    auto result = _http_interact(host, port, "POST", uri, request);
    if(result.first != 200)
        throw std::runtime_error("Failed to get camera profiles");

    vector<onvif_profile_info> profiles;
    try
    {
        // Parse the response
        pugi::xml_document response_doc;
        pugi::xml_parse_result parse_result = response_doc.load_string(result.second.c_str());
        if (!parse_result)
            throw std::runtime_error("XML parsing failed: " + std::string(parse_result.description()));

        // Try multiple namespace patterns
        pugi::xpath_node_set profileNodes = response_doc.select_nodes("//tt:Profiles");
        if (profileNodes.empty())
            profileNodes = response_doc.select_nodes("//trt:Profiles");
        if (profileNodes.empty())
            profileNodes = response_doc.select_nodes("//Profiles");

        // Process each profile
        for (const auto& profileNode : profileNodes)
        {
            pugi::xml_node profileElement = profileNode.node();
            onvif_profile_info profile;
            
            // Get profile token
            profile.token = profileElement.attribute("token").value();
            
            // Default values in case we can't find the data
            profile.encoding = "Unknown";
            profile.width = 0;
            profile.height = 0;
            
            // Get video encoder configuration
            pugi::xpath_node videoEncoderConfigNode = profileElement.select_node(".//tt:VideoEncoderConfiguration");
            if (videoEncoderConfigNode)
            {
                pugi::xml_node videoEncoderConfigElement = videoEncoderConfigNode.node();
                
                // Get encoding
                pugi::xpath_node encodingNode = videoEncoderConfigElement.select_node(".//tt:Encoding");
                if (encodingNode)
                    profile.encoding = encodingNode.node().child_value();
                
                // Get resolution
                pugi::xpath_node resolutionNode = videoEncoderConfigElement.select_node(".//tt:Resolution");
                if (resolutionNode)
                {
                    pugi::xml_node resolutionElement = resolutionNode.node();
                    
                    pugi::xpath_node widthNode = resolutionElement.select_node(".//tt:Width");
                    pugi::xpath_node heightNode = resolutionElement.select_node(".//tt:Height");
                    
                    if (widthNode)
                        profile.width = static_cast<uint16_t>(std::stoi(widthNode.node().child_value()));
                    if (heightNode)
                        profile.height = static_cast<uint16_t>(std::stoi(heightNode.node().child_value()));
                }
            }
            
            // Add the profile to our list
            profiles.push_back(profile);
        }
    }
    catch (const std::exception& exc)
    {
        printf("Error parsing profiles: %s\n", exc.what());
    }

    return profiles;
}

string r_onvif::r_onvif_cam::get_stream_uri(onvif_media_service media_service, onvif_profile_token profile_token)
{
    // Create a new XML document
    pugi::xml_document doc;
    
    // Add XML declaration
    pugi::xml_node declaration = doc.append_child(pugi::node_declaration);
    declaration.append_attribute("version") = "1.0";
    declaration.append_attribute("encoding") = "UTF-8";
    
    // Create root element with namespace
    pugi::xml_node root = doc.append_child("SOAP-ENV:Envelope");
    root.append_attribute("xmlns:SOAP-ENV") = "http://www.w3.org/2003/05/soap-envelope";
    root.append_attribute("xmlns:trt") = "http://www.onvif.org/ver10/media/wsdl";
    root.append_attribute("xmlns:tt") = "http://www.onvif.org/ver10/schema";
    
    // Add authentication header if credentials are provided
    if(_username && _password)
        _add_username_digest_header(&doc, root, _username.value(), _password.value(), _time_offset_seconds);
    
    // Create Body element
    pugi::xml_node body = root.append_child("SOAP-ENV:Body");
    
    // Create GetStreamUri element
    pugi::xml_node getStreamUri = body.append_child("trt:GetStreamUri");
    
    // Create StreamSetup element
    pugi::xml_node streamSetup = getStreamUri.append_child("trt:StreamSetup");
    
    // Create Stream element
    pugi::xml_node stream = streamSetup.append_child("tt:Stream");
    stream.text().set("RTP-Unicast");
    
    // Create Transport element
    pugi::xml_node transport = streamSetup.append_child("tt:Transport");
    
    // Create Protocol element
    pugi::xml_node protocol = transport.append_child("tt:Protocol");
    protocol.text().set("RTSP");
    
    // Create ProfileToken element
    pugi::xml_node profileTokenElem = getStreamUri.append_child("trt:ProfileToken");
    profileTokenElem.text().set(profile_token.c_str());
    
    // Convert the document to a string for transmission
    std::ostringstream oss;
    doc.save(oss, "  ", pugi::format_default | pugi::format_indent);
    auto request = oss.str();

    string host, http_protocol, uri;
    int port;
    r_http::parse_url_parts(media_service, host, port, http_protocol, uri);

    auto result = _http_interact(host, port, "POST", uri, request);
    
    if(result.first != 200)
        throw std::runtime_error("Failed to get stream uri");
    
    return _extract_onvif_value(result.second, "s:Body//trt:GetStreamUriResponse//tt:Uri");
}

void r_onvif::r_onvif_cam::_add_username_digest_header(
    pugi::xml_document* doc,
    pugi::xml_node root, 
    const std::string& username, 
    const std::string& password, 
    int time_offset_seconds
) const
{
    srand((unsigned int)time(NULL));

#ifdef IS_WINDOWS
    _setmode(0, O_BINARY);
#endif

    unsigned int nonce_chunk_size = 20;
    unsigned char nonce_buffer[20];
    char nonce_base64[1024] = {0};
    char time_holder[1024] = {0};
    char digest_base64[1024] = {0};

    for (unsigned int i=0; i<nonce_chunk_size; i++)
        nonce_buffer[i] = (unsigned char)rand();

    unsigned char nonce_result[30];
    memset(nonce_result, 0, 30);

    auto b64_encoded = r_utils::r_string_utils::to_base64(nonce_buffer, nonce_chunk_size);
    memcpy(nonce_result, b64_encoded.c_str(), b64_encoded.length());

#ifdef IS_WINDOWS
    strcpy_s(nonce_base64, 1024, (char*)nonce_result);
#endif
#ifdef IS_LINUX
    strcpy(nonce_base64, (char*)nonce_result);
#endif

    auto now = chrono::system_clock::now();
    auto delta = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch());

    struct timeval tv;
    tv.tv_sec = (long)(delta.count() / 1000);
    tv.tv_usec = (delta.count() % 1000) * 1000;

    int millisec = tv.tv_usec / 1000;

    char time_buffer[1024];
    struct tm* this_tm = nullptr;
#ifdef IS_WINDOWS
    struct tm tm_storage;
    time_t then = tv.tv_sec + time_offset_seconds;
    auto err = gmtime_s(&tm_storage, &then);
    if(err != 0)
        R_THROW(("gmtime_s failed"));
    this_tm = &tm_storage;
#endif
#ifdef IS_LINUX
    time_t then = tv.tv_sec + time_offset_seconds;
    //time_t then = camera_time;
    this_tm = gmtime((time_t*)&then);
#endif
    size_t time_buffer_length = strftime(time_buffer, 1024, "%Y-%m-%dT%H:%M:%S.", this_tm);
    time_buffer[time_buffer_length] = '\0';

    char milli_buf[16] = {0};
#ifdef IS_WINDOWS
    sprintf_s(milli_buf, 16, "%03dZ", millisec);
#endif
#ifdef IS_LINUX
    sprintf(milli_buf, "%03dZ", millisec);
#endif
#ifdef IS_WINDOWS
    strcat_s(time_buffer, 1024, milli_buf);
#endif
#ifdef IS_LINUX
    strcat(time_buffer, milli_buf);
#endif

    r_sha1 ctx;
    ctx.update(nonce_buffer, nonce_chunk_size);
    ctx.update((const unsigned char*)time_buffer, strlen(time_buffer));
    ctx.update((const unsigned char*)password.c_str(), strlen(password.c_str()));
    ctx.finalize();

    unsigned char hash[20];
    ctx.get(&hash[0]);

    unsigned int digest_chunk_size = 20;
    unsigned char digest_result[128];
    b64_encoded = r_string_utils::to_base64(&hash[0], digest_chunk_size);
    memset(digest_result, 0, 128);
    memcpy(digest_result, b64_encoded.c_str(), b64_encoded.length());

#ifdef IS_WINDOWS
    strcpy_s(time_holder, 1024, time_buffer);
    strcpy_s(digest_base64, 1024, (char*)digest_result);
#endif
#ifdef IS_LINUX
    strcpy(time_holder, time_buffer);
    strcpy(digest_base64, (const char *)digest_result);
#endif

    // Add WSSE and WSU namespaces
    root.append_attribute("xmlns:wsse") = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    root.append_attribute("xmlns:wsu") = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    
    // Create Header element
    pugi::xml_node header = root.prepend_child("SOAP-ENV:Header");
    
    // Create Security element
    pugi::xml_node security = header.append_child("wsse:Security");
    security.append_attribute("SOAP-ENV:mustUnderstand") = "1";
    
    // Create UsernameToken element
    pugi::xml_node usernameToken = security.append_child("wsse:UsernameToken");
    
    // Create Username element
    pugi::xml_node usernameElem = usernameToken.append_child("wsse:Username");
    usernameElem.text().set(username.c_str());
    
    // Create Password element
    pugi::xml_node passwordElem = usernameToken.append_child("wsse:Password");
    passwordElem.append_attribute("Type") = 
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
    passwordElem.text().set(digest_base64);
    
    // Create Nonce element
    pugi::xml_node nonceElem = usernameToken.append_child("wsse:Nonce");
    nonceElem.append_attribute("EncodingType") = 
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
    nonceElem.text().set(nonce_base64);
    
    // Create Created element
    pugi::xml_node createdElem = usernameToken.append_child("wsu:Created");
    createdElem.text().set(time_holder);
}































r_onvif_session::r_onvif_session() :
    _buf(),
    _len(),
    _uuid(r_string_utils::format("urn:uuid:%s", r_uuid::generate().c_str()))
{
    xmlInitParser();
}

r_onvif_session::~r_onvif_session()
{
    xmlCleanupParser();
}

vector<r_onvif_discovery_info> r_onvif_session::discover()
{
    _uuid = r_string_utils::format("urn:uuid:%s", r_uuid::generate().c_str());

    vector<r_onvif_discovery_info> discovered;

    string broadcast_message = _get_discovery_xml();

    printf("broadcast_message=%s\n", broadcast_message.c_str());

    r_udp_socket socket;
    _set_socket_options(socket.fd());

    r_socket_address addr(3702, "239.255.255.250");

    socket.sendto((uint8_t*)broadcast_message.c_str(), broadcast_message.length(), addr);

    int i = 0;
    unsigned char looping = 1;
    while(looping)
    {
        _len[i] = socket.recvfrom((uint8_t*)_buf[i], sizeof(_buf[i]), addr);

        if(_len[i] > 0)
        {
            _buf[i][_len[i]] = '\0';

            try
            {
                r_onvif_discovery_info info;
                info.index = i;

                auto all_xaddrs = _extract_all_xaddrs(i);

                auto connectable_xaddr = _find_connectable_xaddr(all_xaddrs);

                info.xaddrs = connectable_xaddr;

                string host, protocol, uri;
                int port;
                r_http::parse_url_parts(info.xaddrs, host, port, protocol, uri);
                info.ipv4 = host;

                info.camera_name = _get_camera_name(i, info.ipv4);

                info.address = _extract_address(i);
                discovered.push_back(info);
            }
            catch(const std::exception& e)
            {
                R_LOG_EXCEPTION_AT(e, __FILE__, __LINE__);
            }

            i++;

        } else looping = 0;
    }

    return discovered;
}

r_nullable<r_onvif_device_info> r_onvif_session::get_rtsp_url(
    const std::string& camera_name,
    const std::string& ipv4,
    const std::string& xaddrs,
    const std::string& address,
    r_nullable<string> username,
    r_nullable<string> password
) const
{
    r_nullable<r_onvif_device_info> result;

    auto service = _extract_onvif_service(xaddrs, true);

    auto timeOffset = _get_time_offset(service, xaddrs);

    raii_ptr<xmlDoc> capsDoc(_send_get_capabilities(username, password, xaddrs, timeOffset), xmlFreeDoc);

    if(!capsDoc.get())
        R_THROW(("Unable to fetch device capabilities."));

    _check_for_xml_error_msg(capsDoc.get(), xaddrs);

    auto media_service = _extract_onvif_service(_get_xml_value(capsDoc.get(), "//s:Body//tds:GetCapabilitiesResponse//tds:Capabilities//tt:Media//tt:XAddr", xaddrs), true);

    auto profile_token = _get_first_profile_token(username, password, xaddrs, media_service, timeOffset);

    auto rtsp_url = _get_stream_uri(username, password, timeOffset, profile_token, xaddrs, media_service);

    raii_ptr<xmlDoc> di_doc(_send_get_device_information(username, password, timeOffset, xaddrs, media_service), xmlFreeDoc);

    if(!di_doc.get())
        R_THROW(("Unable to fetch device information."));

    _check_for_xml_error_msg(di_doc.get(), xaddrs);

    auto serial_number = _get_xml_value(di_doc.get(), "//s:Body//tds:GetDeviceInformationResponse//tds:SerialNumber", xaddrs);
    auto model_number = _get_xml_value(di_doc.get(), "//s:Body//tds:GetDeviceInformationResponse//tds:Model", xaddrs);
    auto firmware_version = _get_xml_value(di_doc.get(), "//s:Body//tds:GetDeviceInformationResponse//tds:FirmwareVersion", xaddrs);
    auto manufacturer = _get_xml_value(di_doc.get(), "//s:Body//tds:GetDeviceInformationResponse//tds:Manufacturer", xaddrs);
    auto hardware_id = _get_xml_value(di_doc.get(), "//s:Body//tds:GetDeviceInformationResponse//tds:HardwareId", xaddrs);

    r_onvif_device_info rdi;
    rdi.camera_name = camera_name;
    rdi.ipv4 = ipv4;
    rdi.xaddrs = xaddrs;
    rdi.address = address;
    rdi.serial_number = serial_number;
    rdi.model_number = model_number;
    rdi.firmware_version = firmware_version;
    rdi.manufacturer = manufacturer;
    rdi.hardware_id = hardware_id;
    rdi.rtsp_url = rtsp_url;

    result.set_value(rdi);

    return result;
}

string r_onvif_session::_get_discovery_xml() const
{
    raii_ptr<xmlDoc> doc(xmlNewDoc((xmlChar*)"1.0"), xmlFreeDoc);
    xmlNodePtr root = xmlNewDocNode(doc.get(), NULL, (xmlChar*)"Envelope", NULL);
    xmlDocSetRootElement(doc.get(), root);
    xmlNewProp(root, (xmlChar*)"xmlns:SOAP-ENV", (xmlChar*)"http://www.w3.org/2003/05/soap-envelope");
    xmlNewProp(root, (xmlChar*)"xmlns:a", (xmlChar*)"http://schemas.xmlsoap.org/ws/2004/08/addressing");
    xmlNsPtr ns_env = xmlNewNs(root, NULL, (xmlChar*)"SOAP-ENV");
    xmlNsPtr ns_a = xmlNewNs(root, NULL, (xmlChar*)"a");
    xmlSetNs(root, ns_env);
    xmlNodePtr header = xmlNewTextChild(root, ns_env, (xmlChar*)"Header", NULL);
    xmlNodePtr action = xmlNewTextChild(header, ns_a, (xmlChar*)"Action", (xmlChar*)"http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe");
    xmlNewProp(action, (xmlChar*)"SOAP-ENV:mustUnderstand", (xmlChar*)"1");
    xmlNodePtr messageid = xmlNewTextChild(header, ns_a, (xmlChar*)"MessageID", (xmlChar*)_uuid.c_str());
    xmlNodePtr replyto = xmlNewTextChild(header, ns_a, (xmlChar*)"ReplyTo", NULL);
    xmlNodePtr address = xmlNewTextChild(replyto, ns_a, (xmlChar*)"Address", (xmlChar*)"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous");
    xmlNodePtr to = xmlNewTextChild(header, ns_a, (xmlChar*)"To", (xmlChar*)"urn:schemas-xmlsoap-org:ws:2005:04:discovery");
    xmlNewProp(to, (xmlChar*)"SOAP-ENV:mustUnderstand", (xmlChar*)"1");
    xmlNodePtr body = xmlNewTextChild(root, ns_env, (xmlChar*)"Body", NULL);
    xmlNodePtr probe = xmlNewTextChild(body, NULL, (xmlChar*)"Probe", NULL);
    xmlNewProp(probe, (xmlChar*)"xmlns:p", (xmlChar*)"http://schemas.xmlsoap.org/ws/2005/04/discovery");
    xmlNsPtr ns_p = xmlNewNs(probe, NULL, (xmlChar*)"p");
    xmlSetNs(probe, ns_p);
    xmlNodePtr types = xmlNewTextChild(probe, NULL, (xmlChar*)"Types", (xmlChar*)"dp0:NetworkVideoTransmitter");
    xmlNewProp(types, (xmlChar*)"xmlns:d", (xmlChar*)"http://schemas.xmlsoap.org/ws/2005/04/discovery");
    xmlNewProp(types, (xmlChar*)"xmlns:dp0", (xmlChar*)"http://www.onvif.org/ver10/network/wsdl");
    xmlNsPtr ns_d = xmlNewNs(types, NULL, (xmlChar*)"d");
    xmlSetNs(types, ns_d);
    raii_ptr<xmlOutputBuffer> outputBuffer(xmlAllocOutputBuffer(NULL), xmlOutputBufferClose);
    xmlNodeDumpOutput(outputBuffer.get(), doc.get(), root, 0, 0, NULL);
    //int size = xmlOutputBufferGetSize(outputBuffer.get());
    string result((char*)xmlOutputBufferGetContent(outputBuffer.get()));
    xmlOutputBufferFlush(outputBuffer.get());

    return result;
}

string r_onvif_session::_get_discovery_xml2() const
{
    return string("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"><s:Header><a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action><a:MessageID>uuid:6bbdae2d-f229-42c8-a27b-93880fb80826</a:MessageID><a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><a:To s:mustUnderstand=\"1\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header><s:Body><Probe xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><d:Types xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" xmlns:dp0=\"http://www.onvif.org/ver10/device/wsdl\">dp0:Device</d:Types></Probe></s:Body></s:Envelope>");
}

void r_onvif_session::_set_socket_options(
    int fd
) const
{
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    int broadcast = 500;
    char loopch = 0;
    int status = 0;
    struct in_addr localInterface;

#ifdef _WIN32
    PMIB_IPADDRTABLE pIPAddrTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    IN_ADDR IPAddr;

    pIPAddrTable = (MIB_IPADDRTABLE *) malloc(sizeof(MIB_IPADDRTABLE));
    if (pIPAddrTable) {
        if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
            free(pIPAddrTable);
            pIPAddrTable = (MIB_IPADDRTABLE *) malloc(dwSize);
        }
        if (pIPAddrTable == NULL) {
            printf("Memory allocation failed for GetIpAddrTable\n");
            return;
        }
    }

    if ((dwRetVal = GetIpAddrTable(pIPAddrTable, &dwSize, 0)) != NO_ERROR) {
        printf("GetIpAddrTable failed with error %lu\n", dwRetVal);
        return;
    }

    int p = 0;
    while (p < (int)pIPAddrTable->dwNumEntries) {
        IPAddr.S_un.S_addr = (u_long)pIPAddrTable->table[p].dwAddr;
        IPAddr.S_un.S_addr = (u_long)pIPAddrTable->table[p].dwMask;
        if (pIPAddrTable->table[p].dwAddr != inet_addr("127.0.0.1") && pIPAddrTable->table[p].dwMask == inet_addr("255.255.255.0")) {
            localInterface.s_addr = pIPAddrTable->table[p].dwAddr;
            status = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&localInterface, sizeof(localInterface));
            if (status < 0)
                printf("ip_multicast_if error");
            p = (int)pIPAddrTable->dwNumEntries;
        }
        p++;
    }

    if (pIPAddrTable) {
        free(pIPAddrTable);
        pIPAddrTable = NULL;
    }

    status = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&broadcast, sizeof(broadcast));
#else
    status = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
#endif
    status = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch));
}

r_nullable<string> r_onvif_session::_get_scope_field(
    const string& scope,
    const string& field_name
) const
{
    r_nullable<string> output;

    auto pos = scope.find(field_name);
    if(pos != string::npos)
    {
        auto space_pos = scope.find(" ", pos);

        auto contents = (space_pos != string::npos)?scope.substr(pos, space_pos - pos):scope.substr(pos);
        auto last_slash = contents.rfind("/");
        auto start = (last_slash == string::npos)?0:last_slash + 1;
        output.set_value(r_string_utils::uri_decode(contents.substr(start)));
    }

    return output;
}

string r_onvif_session::_get_camera_name(
    int index,
    const string& default_name
) const
{
    raii_ptr<xmlDoc> xml_input(xmlParseMemory(_buf[index], _len[index]), xmlFreeDoc);

    auto scopes = _get_xml_value(xml_input.get(), "//s:Body//d:ProbeMatches//d:ProbeMatch//d:Scopes", default_name);

    auto mfgr = _get_scope_field(scopes, (char*)"onvif://www.onvif.org/name/");

    auto hdwr = _get_scope_field(scopes, (char*)"onvif://www.onvif.org/hardware/");

    // SAMSUNG E4500n
    // SAMSUNG 192.168.1.11
    // E4500n 192

    string output;

    if(!mfgr.is_null())
        output = mfgr.value();

    if(!hdwr.is_null())
        output += " " + hdwr.value();
    
    if(output.empty())
        output = default_name;

    return output;
}

std::string r_onvif_session::_extract_xaddrs(
    int index
) const
{
    raii_ptr<xmlDoc> xml_input(xmlParseMemory(_buf[index], _len[index]), [](xmlDoc* p){xmlFreeDoc(p);});

    auto value = _get_xml_value(xml_input.get(), "//s:Body//d:ProbeMatches//d:ProbeMatch//d:XAddrs", string(_buf[index], _len[index]));

    return r_string_utils::split(value, " ").front();
}

std::vector<std::string> r_onvif_session::_extract_all_xaddrs(int index) const
{
    raii_ptr<xmlDoc> xml_input(xmlParseMemory(_buf[index], _len[index]), [](xmlDoc* p){xmlFreeDoc(p);});

    auto value = _get_xml_value(xml_input.get(), "//s:Body//d:ProbeMatches//d:ProbeMatch//d:XAddrs", string(_buf[index], _len[index]));

    return r_string_utils::split(value, " ");
}

std::string r_onvif_session::_find_connectable_xaddr(const std::vector<std::string>& xaddrs) const
{
    for(const auto& xaddr : xaddrs)
    {
        try
        {
            r_utils::r_socket socket;

            string host, protocol, uri;
            int port;
            r_http::parse_url_parts(xaddr, host, port, protocol, uri);

            if(protocol == "https")
                continue;

            socket.connect(host, port);
        }
        catch(...)
        {
            continue;
        }

        return xaddr;
    }

    return std::string();
}

std::string r_onvif_session::_extract_address(
    int index
) const
{
    raii_ptr<xmlDoc> xml_input(xmlParseMemory(_buf[index], _len[index]), [](xmlDoc* p){xmlFreeDoc(p);});
                          
    return _get_xml_value(xml_input.get(), "//s:Body//d:ProbeMatches//d:ProbeMatch//a:EndpointReference//a:Address", string(_buf[index], _len[index]));
}

string r_onvif_session::_get_xml_value(
    xmlDocPtr doc,
    const string& xpath,
    const std::string& id
) const
{
    auto value = _maybe_get_xml_value(doc, xpath);
    if(value.is_null())
        R_THROW(("Unable to find XPath: id(%s)", id.c_str()));
    return value.value();
}

bool r_onvif_session::_has_xml_node(xmlDocPtr doc, const std::string& xpath) const
{
    raii_ptr<xmlXPathContext> context(xmlXPathNewContext(doc), xmlXPathFreeContext);
    if(!context.get())
        return false;

    xmlXPathRegisterNs(context.get(), (xmlChar*)"s", (xmlChar*)"http://www.w3.org/2003/05/soap-envelope");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"trt", (xmlChar*)"http://www.onvif.org/ver10/media/wsdl");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"tt", (xmlChar*)"http://www.onvif.org/ver10/schema");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"tds", (xmlChar*)"http://www.onvif.org/ver10/device/wsdl");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"timg", (xmlChar*)"http://www.onvif.org/ver20/imaging/wsdl");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"wsa5", (xmlChar*)"http://www.w3.org/2005/08/addressing");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"wsnt", (xmlChar*)"http://docs.oasis-open.org/wsn/b-2");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"d", (xmlChar*)"http://schemas.xmlsoap.org/ws/2005/04/discovery");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"ter", (xmlChar*)"http://www.onvif.org/ver10/error");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"a", (xmlChar*)"http://schemas.xmlsoap.org/ws/2004/08/addressing");

    raii_ptr<xmlXPathObject> xpo(xmlXPathEvalExpression((xmlChar*)xpath.c_str(), context.get()), xmlXPathFreeObject);
    if(xpo.get() == NULL || xmlXPathNodeSetIsEmpty(xpo.get()->nodesetval))
        return false;
    return true;
}

r_nullable<string> r_onvif_session::_maybe_get_xml_value(
    xmlDocPtr doc,
    const std::string& xpath
) const
{
    r_nullable<string> result;

    raii_ptr<xmlXPathContext> context(xmlXPathNewContext(doc), xmlXPathFreeContext);
    if(!context.get())
        return result;

    xmlXPathRegisterNs(context.get(), (xmlChar*)"s", (xmlChar*)"http://www.w3.org/2003/05/soap-envelope");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"trt", (xmlChar*)"http://www.onvif.org/ver10/media/wsdl");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"tt", (xmlChar*)"http://www.onvif.org/ver10/schema");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"tds", (xmlChar*)"http://www.onvif.org/ver10/device/wsdl");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"timg", (xmlChar*)"http://www.onvif.org/ver20/imaging/wsdl");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"wsa5", (xmlChar*)"http://www.w3.org/2005/08/addressing");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"wsnt", (xmlChar*)"http://docs.oasis-open.org/wsn/b-2");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"d", (xmlChar*)"http://schemas.xmlsoap.org/ws/2005/04/discovery");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"ter", (xmlChar*)"http://www.onvif.org/ver10/error");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"a", (xmlChar*)"http://schemas.xmlsoap.org/ws/2004/08/addressing");

    raii_ptr<xmlXPathObject> xpo(xmlXPathEvalExpression((xmlChar*)xpath.c_str(), context.get()), xmlXPathFreeObject);
    if(xpo.get() == NULL || xmlXPathNodeSetIsEmpty(xpo.get()->nodesetval))
        return result;

    raii_ptr<char> keyword((char*)xmlNodeListGetString(doc, xpo.get()->nodesetval->nodeTab[0]->xmlChildrenNode, 1), xmlFree);
    if(keyword.get() == NULL)
        return result;
    result.set_value(string((char*)keyword.get()));

    return result;
}

string r_onvif_session::_get_node_attribute(
    xmlDocPtr doc,
    const string& xpath,
    const string& attribute
) const
{
    raii_ptr<xmlXPathContext> context(xmlXPathNewContext(doc), xmlXPathFreeContext);
    if(!context.get())
        R_THROW(("Unable to create xml path context."));

    xmlXPathRegisterNs(context.get(), (xmlChar*)"s", (xmlChar*)"http://www.w3.org/2003/05/soap-envelope");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"trt", (xmlChar*)"http://www.onvif.org/ver10/media/wsdl");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"tt", (xmlChar*)"http://www.onvif.org/ver10/schema");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"tds", (xmlChar*)"http://www.onvif.org/ver10/device/wsdl");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"timg", (xmlChar*)"http://www.onvif.org/ver20/imaging/wsdl");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"wsa5", (xmlChar*)"http://www.w3.org/2005/08/addressing");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"wsnt", (xmlChar*)"http://docs.oasis-open.org/wsn/b-2");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"ter", (xmlChar*)"http://www.onvif.org/ver10/error");
    xmlXPathRegisterNs(context.get(), (xmlChar*)"a", (xmlChar*)"http://schemas.xmlsoap.org/ws/2004/08/addressing");

    raii_ptr<xmlXPathObject> result(xmlXPathEvalExpression((xmlChar*)xpath.c_str(), context.get()), xmlXPathFreeObject);
    if(!result.get())
        R_THROW(("Unable to find xpath."));

    raii_ptr<char> val((char*)xmlGetProp(result.get()->nodesetval->nodeTab[0], (xmlChar*)attribute.c_str()), xmlFree);

    return string(val.get());
}

string r_onvif_session::_extract_onvif_service(
    const std::string& service,
    bool post
) const
{
    string host, protocol, uri;
    int port;
    r_http::parse_url_parts(service, host, port, protocol, uri);

    if(post)
        uri = "POST " + uri + " HTTP/1.1\r\n";
    
    return uri;
}

#if 0
int r_onvif_session::_get_time_offset(
    const string& device_service,
    const string& xaddrs
) const
{
    int result = 0;

    raii_ptr<xmlDoc> doc(xmlNewDoc((xmlChar*)"1.0"), xmlFreeDoc);
    xmlNodePtr root = xmlNewDocNode(doc.get(), NULL, (xmlChar*)"Envelope", NULL);
    xmlDocSetRootElement(doc.get(), root);
    xmlNsPtr ns_env = xmlNewNs(root, (xmlChar*)"http://www.w3.org/2003/05/soap-envelope", (xmlChar*)"SOAP-ENV");
    xmlNsPtr ns_tds = xmlNewNs(root, (xmlChar*)"http://www.onvif.org/ver10/device/wsdl", (xmlChar*)"tds");
    xmlSetNs(root, ns_env);
    xmlNodePtr body = xmlNewTextChild(root, ns_env, (xmlChar*)"Body", NULL);
    xmlNewTextChild(body, ns_tds, (xmlChar*)"GetSystemDateAndTime", NULL);
    auto cmd = _add_http_header(doc.get(), root, xaddrs, device_service);

    raii_ptr<xmlDoc> reply(_send_command_to_camera(cmd, xaddrs), xmlFreeDoc);

    if (reply.get() != NULL) {
        auto hour_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Time//tt:Hour");
        auto min_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Time//tt:Minute");
        auto sec_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Time//tt:Second");
        auto year_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Date//tt:Year");
        auto month_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Date//tt:Month");
        auto day_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Date//tt:Day");
        auto dst_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:DaylightSavings");

        auto iso8601 = year_buf + "-" + month_buf + "-" + day_buf + "T" + hour_buf + ":" + min_buf + ":" + sec_buf + "Z";

        auto there_tp = r_time_utils::iso_8601_to_tp(iso8601);

        time_t there_ts = std::chrono::duration_cast<std::chrono::seconds>(there_tp.time_since_epoch()).count();

        time_t here_ts = time(NULL);

        if(there_ts > here_ts)
            result = (int)(there_ts - here_ts);
        else result = -(int)(here_ts - there_ts);

        _check_for_xml_error_msg(reply.get(), xaddrs);
    }
    else R_THROW(("Unable to fetch device time."));

    return result;
}
#endif
#if 1
int r_onvif_session::_get_time_offset(
    const string& device_service,
    const string& xaddrs
) const
{
    int result = 0;

    raii_ptr<xmlDoc> doc(xmlNewDoc((xmlChar*)"1.0"), xmlFreeDoc);
    xmlNodePtr root = xmlNewDocNode(doc.get(), NULL, (xmlChar*)"Envelope", NULL);
    xmlDocSetRootElement(doc.get(), root);
    xmlNsPtr ns_env = xmlNewNs(root, (xmlChar*)"http://www.w3.org/2003/05/soap-envelope", (xmlChar*)"SOAP-ENV");
    xmlNsPtr ns_tds = xmlNewNs(root, (xmlChar*)"http://www.onvif.org/ver10/device/wsdl", (xmlChar*)"tds");
    xmlSetNs(root, ns_env);
    xmlNodePtr body = xmlNewTextChild(root, ns_env, (xmlChar*)"Body", NULL);
    xmlNewTextChild(body, ns_tds, (xmlChar*)"GetSystemDateAndTime", NULL);
    auto cmd = _add_http_header(doc.get(), root, xaddrs, device_service);

    raii_ptr<xmlDoc> reply(_send_command_to_camera(cmd, xaddrs), xmlFreeDoc);

    // If the response has a time, use it
    //     if the time is utc, use it as is
    //     if the time is local, convert it to utc

    // Only parse UTCDateTime if it is present
    //   <tt:UTCDateTime>
    //     <tt:Time>
    //       <tt:Hour>15</tt:Hour>
    //       <tt:Minute>52</tt:Minute>
    //       <tt:Second>25</tt:Second>
    //     </tt:Time>
    //     <tt:Date>
    //       <tt:Year>2010</tt:Year>
    //       <tt:Month>10</tt:Month>
    //       <tt:Day>29</tt:Day>
    //     </tt:Date>
    //   </tt:UTCDateTime>

    // It might also be LocalDataTime
    //  <tt:LocalDateTime>
    //     <tt:Time>
    //       <tt:Hour>15</tt:Hour>
    //       <tt:Minute>52</tt:Minute>
    //       <tt:Second>25</tt:Second>
    //     </tt:Time>
    //     <tt:Date>
    //       <tt:Year>2010</tt:Year>
    //       <tt:Month>10</tt:Month>
    //       <tt:Day>29</tt:Day>
    //     </tt:Date>
    //  </tt:LocalDateTime>

    if (reply.get() != NULL) {
        if (!_has_xml_node(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime"))
            return 0;
        if (!_has_xml_node(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime"))
            return 0;

        auto hour_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Time//tt:Hour", xaddrs);
        auto min_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Time//tt:Minute", xaddrs);
        auto sec_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Time//tt:Second", xaddrs);
        auto year_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Date//tt:Year", xaddrs);
        auto month_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Date//tt:Month", xaddrs);
        auto day_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:UTCDateTime//tt:Date//tt:Day", xaddrs);
        auto dst_buf = _get_xml_value(reply.get(), "//s:Body//tds:GetSystemDateAndTimeResponse//tds:SystemDateAndTime//tt:DaylightSavings", xaddrs);

        int is_dst = (dst_buf == "true") ? 1 : 0;

        time_t now = time(NULL);
#ifdef IS_WINDOWS
        struct tm utc_storage;
        auto err = gmtime_s(&utc_storage, &now);
        if(err != 0)
            R_THROW(("Unable to get UTC time."));
        struct tm* utc_here = &utc_storage;
#endif
#ifdef IS_LINUX
        struct tm *utc_here = gmtime(&now);
        if(utc_here == NULL)
            R_THROW(("Unable to get UTC time."));
#endif
        utc_here->tm_isdst = is_dst;
        time_t utc_time_here = mktime(utc_here);

#ifdef IS_WINDOWS
        err = localtime_s(&utc_storage, &now);
        if(err != 0)
            R_THROW(("Unable to get UTC time."));
        struct tm* utc_there = &utc_storage;
#endif
#ifdef IS_LINUX
        struct tm *utc_there = localtime(&now);
        if(utc_there == NULL)
            R_THROW(("Unable to get UTC time."));
#endif
        utc_there->tm_year = stoi(year_buf) - 1900;
        utc_there->tm_mon = stoi(month_buf) - 1;
        utc_there->tm_mday = stoi(day_buf);
        utc_there->tm_hour = stoi(hour_buf);
        utc_there->tm_min = stoi(min_buf);
        utc_there->tm_sec = stoi(sec_buf);
        utc_there->tm_isdst = is_dst;
        time_t utc_time_there = mktime(utc_there);
        // if utc_time_there > utc_time_here then the camera is in the future so the offset
        // is utc_time_there - utc_time_here
        // if utc_time_there < utc_time_here then the camera is in the past so the offset
        // is utc_time_here - utc_time_there
        int64_t tmp = (int64_t)utc_time_there - (int64_t)utc_time_here;
        
        result = (int)tmp;

        _check_for_xml_error_msg(reply.get(), xaddrs);
    }
    else R_THROW(("Unable to fetch device time."));

    return result;
}
#endif
xmlDocPtr r_onvif_session::_send_command_to_camera(
    const string& cmd,
    const string& xaddrs,
    bool throw_on_unauthorized
) const
{
    string host, protocol, uri;
    int port;
    r_http::parse_url_parts(xaddrs, host, port, protocol, uri);

    r_socket sok;
    sok.connect(host, port);
    sok.set_io_timeout(10000);

    sok.send(cmd.c_str(), cmd.length());

    r_http::r_client_response response;
    response.read_response(sok);

    auto status = response.get_status();
    if(status == r_http::response_unauthorized)
        R_STHROW(r_unauthorized_exception, ("Unauthorized from: %s", xaddrs.c_str()));

    auto maybe_response_body = response.get_body_as_string();

    // if its is_failure() && contains "NotAuthorized" then throw unauthorized!
    if(response.is_failure())
    {
        if(!maybe_response_body.is_null())
        {
            auto response_body = maybe_response_body.value();

            if(r_string_utils::contains(response_body, "NotAuthorized"))
                R_STHROW(r_unauthorized_exception, ("Unauthorized from: %s", xaddrs.c_str()));
        }

        R_THROW(("Error returned from camera: %s", xaddrs.c_str()));
    }

    auto response_body = maybe_response_body.value();
 
    return xmlParseMemory(response_body.c_str(), (int)response_body.size());
}

string r_onvif_session::_add_http_header(
    xmlDocPtr doc,
    xmlNodePtr root,
    const string& xaddrs,
    const string& post_type
) const
{
    xmlOutputBufferPtr outputbuffer = xmlAllocOutputBuffer(NULL);
    xmlNodeDumpOutput(outputbuffer, doc, root, 0, 0, NULL);
    int size = (int)xmlOutputBufferGetSize(outputbuffer);

    char xml[8192] = {0};
    if (size > 8191) {
        fprintf(stderr, "xmlOutputBufferGetSize too big %d\n", size);
#ifdef IS_WINDOWS
        strncat_s(xml, 8192, (char*)xmlOutputBufferGetContent(outputbuffer), 8191);
#endif
#ifdef IS_LINUX
        strncat(xml, (char*)xmlOutputBufferGetContent(outputbuffer), 8191);
#endif
    }
    else {
#ifdef IS_WINDOWS
        strcpy_s(xml, 8192, (char*)xmlOutputBufferGetContent(outputbuffer));
#endif
#ifdef IS_LINUX
        strcpy(xml, (char*)xmlOutputBufferGetContent(outputbuffer));
#endif
    }

    xmlOutputBufferFlush(outputbuffer);
    xmlOutputBufferClose(outputbuffer);

    char c_xml_size[6] = {0, 0, 0, 0, 0, 0};
#ifdef IS_WINDOWS
    sprintf_s(c_xml_size, 6, "%d", size);
#endif
#ifdef IS_LINUX
    sprintf(c_xml_size, "%d", size);
#endif
    int xml_size_length = (int)strlen(c_xml_size)+1;

    string host, protocol, uri;
    int port;
    r_http::parse_url_parts(xaddrs, host, port, protocol, uri);

    char content[] =
    "User-Agent: Generic\r\n"
    "Connection: Close\r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Content-Type: application/soap+xml; charset=utf-8;\r\n"
    "Host: ";
    char content_length[] = "\r\nContent-Length: ";

    char http_terminate[5];
    http_terminate[0] = '\r';
    http_terminate[1] = '\n';
    http_terminate[2] = '\r';
    http_terminate[3] = '\n';
    http_terminate[4] = '\0';

    int p = (int)(post_type.size() + 1);
    int h = (int)(host.size() + 1);
    int c = sizeof(content);
    int cl = sizeof(content_length);
    int cmd_size = p + c + h + cl + xml_size_length + size + 1;
    int i;
    int s;
    char cmd[4096];
    memset(cmd, 0, sizeof(cmd));
    for (i=0; i<p-1; i++)
        cmd[i] = post_type[i];
    s = i;
    for (i=0; i<c-1; i++)
        cmd[s+i] = content[i];
    s = s+i;
    for (i=0; i<h-1; i++)
        cmd[s+i] = host[i];
    s = s+i;
    for (i=0; i<cl-1; i++)
        cmd[s+i] = content_length[i];
    s = s+i;
    for (i=0; i<xml_size_length-1; i++)
        cmd[s+i] = c_xml_size[i];
    s = s+i;
    for (i=0; i<5-1; i++)
        cmd[s+i] = http_terminate[i];
    s = s+i;
    for (i=0; i<size; i++)
        cmd[s+i] = xml[i];
    cmd[cmd_size] = '\0';

    return string(cmd);
}

xmlDocPtr r_onvif_session::_send_get_capabilities(
    const r_utils::r_nullable<std::string> username,
    const r_utils::r_nullable<std::string> password,
    const string& xaddrs,
    int time_offset
) const
{
    raii_ptr<xmlDoc> doc(xmlNewDoc((xmlChar*)"1.0"), xmlFreeDoc);
    xmlNodePtr root = xmlNewDocNode(doc.get(), NULL, (xmlChar*)"Envelope", NULL);
    xmlDocSetRootElement(doc.get(), root);
    xmlNsPtr ns_env = xmlNewNs(root, (xmlChar*)"http://www.w3.org/2003/05/soap-envelope", (xmlChar*)"SOAP-ENV");
    xmlNsPtr ns_tds = xmlNewNs(root, (xmlChar*)"http://www.onvif.org/ver10/device/wsdl", (xmlChar*)"tds");
    xmlSetNs(root, ns_env);
    if(!username.is_null())
        add_username_digest_header(root, ns_env, (char*)username.value().c_str(), (char*)password.value().c_str(), time_offset);
    xmlNodePtr body = xmlNewTextChild(root, ns_env, (xmlChar*)"Body", NULL);
    xmlNodePtr capabilities = xmlNewTextChild(body, ns_tds, (xmlChar*)"GetCapabilities", NULL);
    xmlNewTextChild(capabilities, ns_tds, (xmlChar*)"Category", (const xmlChar *)"All");

    auto onvif_service = _extract_onvif_service(xaddrs, true);

    auto cmd = _add_http_header(doc.get(), root, xaddrs, onvif_service);

    return _send_command_to_camera(cmd, xaddrs);
}

void r_onvif_session::_check_for_xml_error_msg(
    xmlDocPtr doc,
    const std::string& xaddr
) const
{
    auto err = _maybe_get_xml_value(doc, "//s:Body//s:Fault//s:Code//s:Subcode//s:Value");
    if(!err.is_null())
        R_THROW(("XML Parser Error: %s %s", xaddr.c_str(), err.value().c_str()));

    err = _maybe_get_xml_value(doc, "//s:Body//s:Fault//s:Reason//s:Text");
    if(!err.is_null())
        R_THROW(("XML Parser Error: %s %s", xaddr.c_str(), err.value().c_str()));
}

string r_onvif_session::_get_first_profile_token(
    const r_nullable<string>& username,
    const r_nullable<string>& password,
    const string& xaddrs,
    const string& media_service,
    int time_offset
) const
{
    int result = 0;
    raii_ptr<xmlDoc> doc(xmlNewDoc((xmlChar*)"1.0"), xmlFreeDoc);
    xmlNodePtr root = xmlNewDocNode(doc.get(), NULL, (xmlChar*)"Envelope", NULL);
    xmlDocSetRootElement(doc.get(), root);
    xmlNsPtr ns_env = xmlNewNs(root, (xmlChar*)"http://www.w3.org/2003/05/soap-envelope", (xmlChar*)"SOAP-ENV");
    xmlNsPtr ns_trt = xmlNewNs(root, (xmlChar*)"http://www.onvif.org/ver10/media/wsdl", (xmlChar*)"trt");
    xmlSetNs(root, ns_env);
    if(!username.is_null())
        add_username_digest_header(root, ns_env, username.value().c_str(), password.value().c_str(), time_offset);
    xmlNodePtr body = xmlNewTextChild(root, ns_env, (xmlChar*)"Body", NULL);
    xmlNewTextChild(body, ns_trt, (xmlChar*)"GetProfiles", NULL);

    auto cmd = _add_http_header(doc.get(), root, xaddrs, media_service);

    raii_ptr<xmlDoc> reply(_send_command_to_camera(cmd, xaddrs), xmlFreeDoc);

    if(!reply.get())
        R_THROW(("Unable to read reply from camera"));

    _check_for_xml_error_msg(reply.get(), xaddrs);

    return _get_node_attribute(reply.get(), "//s:Body//trt:GetProfilesResponse//trt:Profiles", "token");
}

string r_onvif_session::_get_stream_uri(
    const r_nullable<string>& username,
    const r_nullable<string>& password,
    int timeOffset,
    string& profileToken,
    const string& xaddrs,
    const string& mediaService
) const
{
    int result = 0;
    raii_ptr<xmlDoc> doc(xmlNewDoc((xmlChar*)"1.0"), xmlFreeDoc);
    xmlNodePtr root = xmlNewDocNode(doc.get(), NULL, (xmlChar*)"Envelope", NULL);
    xmlDocSetRootElement(doc.get(), root);
    xmlNsPtr ns_env = xmlNewNs(root, (xmlChar*)"http://www.w3.org/2003/05/soap-envelope", (xmlChar*)"SOAP-ENV");
    xmlNsPtr ns_trt = xmlNewNs(root, (xmlChar*)"http://www.onvif.org/ver10/media/wsdl", (xmlChar*)"trt");
    xmlNsPtr ns_tt = xmlNewNs(root, (xmlChar*)"http://www.onvif.org/ver10/schema", (xmlChar*)"tt");
    xmlSetNs(root, ns_env);
    if(!username.is_null())
        add_username_digest_header(root, ns_env, (char*)username.value().c_str(), (char*)password.value().c_str(), timeOffset);
    xmlNodePtr body = xmlNewTextChild(root, ns_env, (xmlChar*)"Body", NULL);
    xmlNodePtr getStreamUri = xmlNewTextChild(body, ns_trt, (xmlChar*)"GetStreamUri", NULL);
    xmlNodePtr streamSetup = xmlNewTextChild(getStreamUri, ns_trt, (xmlChar*)"StreamSetup", NULL);
    xmlNewTextChild(streamSetup, ns_tt, (xmlChar*)"Stream", (xmlChar*)"RTP-Unicast");
    xmlNodePtr transport = xmlNewTextChild(streamSetup, ns_tt, (xmlChar*)"Transport", NULL);
    xmlNewTextChild(transport, ns_tt, (xmlChar*)"Protocol", (xmlChar*)"RTSP");
    xmlNewTextChild(getStreamUri, ns_trt, (xmlChar*)"ProfileToken", (xmlChar*)profileToken.c_str());

    auto cmd = _add_http_header(doc.get(), root, xaddrs, mediaService);
    raii_ptr<xmlDoc> reply(_send_command_to_camera(cmd, xaddrs), xmlFreeDoc);

    if(!reply.get())
        R_THROW(("Unable to read reply from camera"));
    
    _check_for_xml_error_msg(reply.get(), xaddrs);

    return _get_xml_value(reply.get(), "//s:Body//trt:GetStreamUriResponse//trt:MediaUri//tt:Uri", xaddrs);
}

xmlDocPtr r_onvif_session::_send_get_device_information(
    const r_nullable<string>& username,
    const r_nullable<string>& password,
    int timeOffset,
    const string& xaddrs,
    const string& device_service
) const
{
    int result = 0;
    raii_ptr<xmlDoc> doc(xmlNewDoc((xmlChar*)"1.0"), xmlFreeDoc);
    xmlNodePtr root = xmlNewDocNode(doc.get(), NULL, (xmlChar*)"Envelope", NULL);
    xmlDocSetRootElement(doc.get(), root);
    xmlNsPtr ns_env = xmlNewNs(root, (xmlChar*)"http://www.w3.org/2003/05/soap-envelope", (xmlChar*)"SOAP-ENV");
    xmlNsPtr ns_tds = xmlNewNs(root, (xmlChar*)"http://www.onvif.org/ver10/device/wsdl", (xmlChar*)"tds");
    xmlSetNs(root, ns_env);
    if(!username.is_null())
        add_username_digest_header(root, ns_env, (char*)username.value().c_str(), (char*)password.value().c_str(), timeOffset);
    xmlNodePtr body = xmlNewTextChild(root, ns_env, (xmlChar*)"Body", NULL);
    xmlNewTextChild(body, ns_tds, (xmlChar*)"GetDeviceInformation", NULL);

    return _send_command_to_camera(_add_http_header(doc.get(), root, xaddrs, device_service), xaddrs);
}

void r_onvif_session::add_username_digest_header(
    xmlNodePtr root,
    xmlNsPtr ns_env,
    const char *user,
    const char *password,
    time_t offset
) const
{
    srand((unsigned int)time(NULL));

#ifdef _WIN32
    _setmode(0, O_BINARY);
#endif

    unsigned int nonce_chunk_size = 20;
    unsigned char nonce_buffer[20];
    char nonce_base64[1024] = {0};
    char time_holder[1024] = {0};
    char digest_base64[1024] = {0};

    for (unsigned int i=0; i<nonce_chunk_size; i++)
        nonce_buffer[i] = (unsigned char)rand();

    unsigned char nonce_result[30];
    memset(nonce_result, 0, 30);

    auto b64_encoded = r_string_utils::to_base64(nonce_buffer, nonce_chunk_size);
    memcpy(nonce_result, b64_encoded.c_str(), b64_encoded.length());

#ifdef IS_WINDOWS
    strcpy_s(nonce_base64, 1024, (char*)nonce_result);
#endif
#ifdef IS_LINUX
    strcpy(nonce_base64, (char*)nonce_result);
#endif

    auto now = chrono::system_clock::now();
    auto delta = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch());

    struct timeval tv;
    tv.tv_sec = (long)(delta.count() / 1000);
    tv.tv_usec = (delta.count() % 1000) * 1000;

    int millisec = tv.tv_usec / 1000;

    char time_buffer[1024];
#ifdef IS_WINDOWS
    struct tm tm_storage;
    time_t then = tv.tv_sec + offset;
    auto err = gmtime_s(&tm_storage, &then);
    if(err != 0)
        R_THROW(("gmtime_s failed"));
    struct tm* this_tm = &tm_storage;
#endif
#ifdef IS_LINUX
    time_t then = tv.tv_sec + offset;
    struct tm* this_tm = gmtime((time_t*)&then);
#endif
    size_t time_buffer_length = strftime(time_buffer, 1024, "%Y-%m-%dT%H:%M:%S.", this_tm);
    time_buffer[time_buffer_length] = '\0';

    char milli_buf[16] = {0};
#ifdef IS_WINDOWS
    sprintf_s(milli_buf, 16, "%03dZ", millisec);
#endif
#ifdef IS_LINUX
    sprintf(milli_buf, "%03dZ", millisec);
#endif

#ifdef IS_WINDOWS
    strcat_s(time_buffer, 1024, milli_buf);
#endif
#ifdef IS_LINUX
    strcat(time_buffer, milli_buf);
#endif

    r_sha1 ctx;
    ctx.update(nonce_buffer, nonce_chunk_size);
    ctx.update((const unsigned char*)time_buffer, strlen(time_buffer));
    ctx.update((const unsigned char*)password, strlen(password));
    ctx.finalize();

    unsigned char hash[20];
    ctx.get(&hash[0]);

    unsigned int digest_chunk_size = 20;
    unsigned char digest_result[128];
    b64_encoded = r_string_utils::to_base64(&hash[0], digest_chunk_size);
    memset(digest_result, 0, 128);
    memcpy(digest_result, b64_encoded.c_str(), b64_encoded.length());

#ifdef IS_WINDOWS
    strcpy_s(time_holder, 1024, time_buffer);
    strcpy_s(digest_base64, 1024, (char*)digest_result);
#endif
#ifdef IS_LINUX
    strcpy(time_holder, time_buffer);
    strcpy(digest_base64, (const char *)digest_result);
#endif

    xmlNsPtr ns_wsse = xmlNewNs(root, (xmlChar*)"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", (xmlChar*)"wsse");
    xmlNsPtr ns_wsu = xmlNewNs(root, (xmlChar*)"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", (xmlChar*)"wsu");
    xmlNodePtr header = xmlNewTextChild(root, ns_env, (xmlChar*)"Header", NULL);
    xmlNodePtr security = xmlNewTextChild(header, ns_wsse, (xmlChar*)"Security", NULL);
    xmlNewProp(security, (xmlChar*)"SOAP-ENV:mustUnderstand", (xmlChar*)"1");
    xmlNodePtr username_token = xmlNewTextChild(security, ns_wsse, (xmlChar*)"UsernameToken", NULL);
    xmlNewTextChild(username_token, ns_wsse, (xmlChar*)"Username", (xmlChar*)user);
    xmlNodePtr pwd = xmlNewTextChild(username_token, ns_wsse, (xmlChar*)"Password", (xmlChar*)digest_base64);
    xmlNewProp(pwd, (xmlChar*)"Type", (xmlChar*)"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest");
    xmlNodePtr nonce = xmlNewTextChild(username_token, ns_wsse, (xmlChar*)"Nonce", (xmlChar*)nonce_base64);
    xmlNewProp(nonce, (xmlChar*)"EncodingType", (xmlChar*)"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
    xmlNewTextChild(username_token, ns_wsu, (xmlChar*)"Created", (xmlChar*)time_holder);
}
