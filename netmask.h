#pragma once
#include <WinSock2.h>
#include <in6addr.h>
// ReSharper disable CppUnusedIncludeDirective
#include <ws2ipdef.h>
#include <WS2tcpip.h>
// ReSharper restore CppUnusedIncludeDirective
constexpr auto nm_use_dns{ 1 };
using nm = struct tag_nm*;
nm nm_new_v4(const in_addr*);
nm nm_new_v6(const in6_addr*);
nm nm_new_ai(const addrinfo*);
nm nm_new_str(const char*, int flags);
nm nm_merge(nm, nm);

union nm_address
{
	in6_addr s6;
	in_addr s;
};

void nm_walk(nm, void(*)(int, const nm_address*, nm_address*));