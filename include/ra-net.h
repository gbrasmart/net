#pragma once

#include <defs.h>

#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <map>

#include <macro.h>
#include <blake2.h>

#ifdef _WIN32
/* See http://stackoverflow.com/questions/12765743/getaddrinfo-on-win32 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501  /* Windows XP. */
#endif
#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#else
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
/* Assume that any non-Windows platform uses POSIX-style sockets instead. */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>  /* Needed for getaddrinfo() and freeaddrinfo() */
#include <unistd.h> /* Needed for close() */
#endif

#include "proto.h"
#include "ra_log.h"
#include "ra_hosts.h"
#include "ra_types.h"

bool ra_sendto(char *host, unsigned short port,
               unsigned char *Data, size_t DataSz,
               char *Status = nullptr, size_t StatusSz = 0);
bool ra_recv(unsigned char *Buffer,
             size_t &BufferSz,
             char *Status = nullptr, size_t StatusSz = 0);

bool ra_net_launch(const public_type &ownPub,
                   const private_type &ownPriv,
                   const char *host = nullptr, unsigned short port = UDP_PORT);
void ra_net_stop();
bool ra_net_available();

bool ra_command_iam(const char *host, unsigned short port,
                    char *Status = nullptr, size_t StatusSz = 0);
bool ra_command_heis(const char *host, unsigned short port,
                     public_type &his_pub,
                     const char *his_host,
                     unsigned short his_port,
                     char *Status = nullptr, size_t StatusSz = 0);
bool ra_command_get_entity(const char *host, unsigned short port, hash_type &entity_hash,
                           char *Status = nullptr, size_t StatusSz = 0);

bool ra_present_me();

sockaddr_in get_self_sin();

int ra_net_synclasthash();

