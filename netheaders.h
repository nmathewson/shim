#ifndef _NETHEADERS_H_
#define _NETHEADERS_H_

#ifndef WIN32
#include <netinet/in.h>
#else
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#endif
