
#include "test_r_onvif.h"
#include "r_onvif/r_onvif_session.h"
#include "r_utils/r_string_utils.h"
#include "r_utils/r_sha1.h"
#include <string.h>
#include <map>

using namespace std;
using namespace r_onvif;
using namespace r_utils;

REGISTER_TEST_FIXTURE(test_r_onvif);

void test_r_onvif::setup()
{
}

void test_r_onvif::teardown()
{
}

void test_r_onvif::test_r_onvif_session_basic()
{
#if 0
    struct keys
    {
        string username;
        string password;
    };

    map<string, keys> key_map;

    {
        // reolink rlc810a
        keys k;
        k.username = "login";
        k.password = "password";
        key_map.insert(make_pair("urn:uuid:2419d68a-2dd2-21b2-a205-ec:71:db:16:b1:12",k));
    }

    {
        // axis m-3075
        keys k;
        k.username = "login";
        k.password = "password";
        key_map.insert(make_pair("urn:uuid:e58f6613-b3bf-4aa0-90da-250d77bb2fda",k));
    }

    r_onvif_session session;

    auto discovered = session.discover();

    bool foundSomething = false;
    for(auto& di : discovered)
    {
        if(key_map.find(di.address) != key_map.end())
        {
            auto keys = key_map.at(di.address);

            auto rdi = session.get_rtsp_url(
                di.camera_name,
                di.ipv4,
                di.xaddrs,
                di.address,
                keys.username,
                keys.password
            );

            if(!rdi.is_null())
            {
                foundSomething = true;
                RTF_ASSERT(rdi.value().rtsp_url.find("rtsp://") != string::npos);
                printf("camera_name=%s, rtsp_url=%s\n", di.camera_name.c_str(), rdi.value().rtsp_url.c_str());
                fflush(stdout);
            }
        }
    }

    RTF_ASSERT(foundSomething);
#endif
}
