#include "ra-net.h"
#include "proto.h"
#include "blocks_thread.h"
//------------------------------------------------------------------------------
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#ifdef _WIN32
#pragma comment(lib, "../contrib/event2/libevent.lib")
#endif
//------------------------------------------------------------------------------
void on_read(evutil_socket_t fd, short flags, void *arg);
void on_write(evutil_socket_t fd, short flags, void *arg);
void on_timer(evutil_socket_t fd, short kind, void *arg);

typedef struct RA_NET_CTX {
    RA_NET_CTX(const public_type &ownPub,
               const private_type &ownPriv,
               const char *host = nullptr,
               const unsigned short port = UDP_PORT) : fd(-1),
        base(nullptr),
        write_event(nullptr),
        read_event(nullptr),
        timer_event(nullptr)
    {
        ctxPubkey = ownPub;
        ctxPrivKey = ownPriv;

#ifdef _WIN32
        WORD wVersionRequested = MAKEWORD(2, 2);
        WSADATA wsaData;
        if (WSAStartup(wVersionRequested, &wsaData)) {
            ra_log.err("Networking initialization error 0x%08X", WSAGetLastError());
            throw std::runtime_error("Network initialization error");
        }
        else {
            ra_log.dbg("WSAStartup initialization success");
        }
#endif

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            fd = -1;
#ifdef _WIN32
            ra_log.err("Socket initialization error 0x%08X", WSAGetLastError());
#else
            ra_log.err("Socket initialization error 0x%08X", errno);
#endif
            throw std::runtime_error("Socket initialization error");
        }
        if (evutil_make_socket_nonblocking(fd) < 0) {
            CLOSESOCKET(fd);
            fd = -1;
            throw std::runtime_error("Socket evutil initialization error");
        }
        ZEROIZE(&ctxSin);
        ctxSin.sin_family = AF_INET;
        ctxSin.sin_port = htons(port ? port : UDP_PORT);
        ctxSin.sin_addr.s_addr = (host && strlen(host)) ? inet_addr(host) : INADDR_ANY;

#ifndef _WIN32
        {
            int one = 1;
            if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
                ra_log.err("setsockopt error 0x%08X", errno);
                CLOSESOCKET(fd);
                fd = -1;
                throw std::runtime_error("Socket flags error");
            }
            else {
                ra_log.dbg("setsockopt success");
            }
        }
#endif
#ifdef TARGET_OS_MAC
        if (::bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
#else
        if (bind(fd, (struct sockaddr*)&ctxSin, sizeof(ctxSin)) < 0) {
#endif
#ifdef _WIN32
            ra_log.err("Bind error 0x%08X", WSAGetLastError());
#else
            ra_log.err("Bind error 0x%08X (%s)", errno, strerror(errno));
#endif
            CLOSESOCKET(fd);
            fd = -1;
            throw std::runtime_error("Socket bind error");
        }
        else {
            ra_log.dbg("bind success");
        }


        base = event_base_new();
        if (base) {
            read_event = event_new(base, fd, EV_READ | EV_PERSIST,
                                   on_read, (void *)this);
            if (read_event) {
                write_event = event_new(base, fd, EV_WRITE | EV_PERSIST,
                                        on_write, (void *)this);
                if (write_event) {
                    timer_event = evtimer_new(base, on_timer, (void *)this);
                    if (timer_event) {
                        if (!event_add(read_event, nullptr)) {
                            return;
                        }
                        event_free(timer_event);
                        timer_event = nullptr;
                    }
                    event_free(write_event);
                    write_event = nullptr;
                }
                event_free(read_event);
                read_event = nullptr;
            }
            event_base_free(base);
            base = nullptr;
        }
        CLOSESOCKET(fd);
        fd = -1;
        throw std::runtime_error("Socket events initialization error");
    }

    ~RA_NET_CTX() {
        ra_log.dbg("RA_NET_CTX destroy...");
        try {
            ra_log.dbg("close socket...");
            if (fd >= 0) CLOSESOCKET(fd);
            ra_log.dbg("deleting event_read...");
            if (read_event) {
                event_del(read_event);
                event_free(read_event);
            }
            ra_log.dbg("deleting event_write...");
            if (write_event) {
                event_del(write_event);
                event_free(write_event);
            }
            ra_log.dbg("deleting event_timer...");
            if (timer_event) {
                evtimer_del(timer_event);
                event_free(timer_event);
            }
            ra_log.dbg("deleting base event...");
            if (base) event_base_free(base);
        }
        catch (const std::exception &e) {
            ra_log.exc("network context destructor: %s", e.what());
        }
#ifdef _WIN32
        if (WSACleanup() == SOCKET_ERROR) {
            ra_log.err("WSACLeanup error 0x%08X", WSAGetLastError());
        }
#endif
    }
    struct sockaddr_in sin;
    public_type ctxPubkey;
    private_type ctxPrivKey;
    struct sockaddr_in ctxSin = { 0 };

    evutil_socket_t fd;

    struct event_base* base;
    struct event* read_event;
    struct event* write_event;
    struct event *timer_event;

    bool launch_timer();
    bool SendTo(unsigned char *Data, size_t DataSz, sockaddr_in &addr);
} *PRA_NET_CTX, *HRA_NET_CTX;
//------------------------------------------------------------------------------
#define RECV_LOCK rm.lock()
#define RECV_UNLOCK rm.unlock()
#define SEND_LOCK sm.lock()
#define SEND_UNLOCK sm.unlock()

#define BUF_PTR(ptr, sz)    std::shared_ptr<unsigned char> ptr(new unsigned char[sz], std::default_delete<unsigned char[]>())
//------------------------------------------------------------------------------
void on_close(PRA_NET_CTX pctx);

void ra_net_proc(const public_type &ownPub,
                 const private_type &ownPriv,
                 const char *host = nullptr, unsigned short port = UDP_PORT);
bool prepare_to_send(unsigned char *Data, size_t DataSz, char *host, unsigned short port = UDP_PORT);
//------------------------------------------------------------------------------
const struct timeval one_sec = { 1, 0 };
static std::atomic_bool online(false);
PRA_NET_CTX PCtx = nullptr;
//------------------------------------------------------------------------------
static struct {
private:
    std::mutex rm;
    std::mutex sm;
//Data exchange types
    typedef std::tuple<std::shared_ptr<unsigned char>, size_t, sockaddr_in> BufTuple;
    typedef std::deque<BufTuple> BufDeque;
    typedef std::map<hash_type, std::shared_ptr<PACKAGE_BUFFER>> PkgBufMap;
//Data exchange buffers
    BufDeque to_send;
    PkgBufMap package_buffers;
//Commands exchange types
    //NOTE: data fields are commented due to current commands set does not require additional data
    typedef std::tuple<ProtoCommands, CmdStruct, /* std::shared_ptr<unsigned char>, size_t ,*/ sockaddr_in> CmdBufTuple;
    typedef std::deque<CmdBufTuple> CmdBufDeque;
//Commands exchange buffers
    CmdBufDeque commands_to_send;
    CmdBufDeque commands_received;
public:
    bool init_pkg_buffer(PACKAGE_HEADER &header) {
        bool result = false;
        RECV_LOCK;
        try {
            auto it = package_buffers.find(header.cmd_data.total_hash);
            if (it == package_buffers.end()) {
                package_buffers.insert(std::pair<hash_type,
                                       std::shared_ptr<PACKAGE_BUFFER>>(header.cmd_data.total_hash,
                                               new PACKAGE_BUFFER(header)));
            } else {
                ra_log.warn("buffer already exists");
            }
            result =
                (package_buffers.find(header.cmd_data.total_hash) !=
                 package_buffers.end());
        } catch(const std::exception &e) {
            ra_log.exc("init_pkg_buffer: %s", e.what());
            result = false;
        }
        RECV_UNLOCK;
        return result;
    }
    appendResult append_pkg_part(PACKAGE_PART &part) {
        auto result = arUndefined;
        RECV_LOCK;
        try {
            ra_log.dbg("append_pkg_part: Package buffers %lu", package_buffers.size());
            auto it = package_buffers.find(part.header.total_hash);
            if (it != package_buffers.end()) {
                HPACKAGE_BUFFER hBuffer = it->second.get();
                if (hBuffer->completed()) {
                    ra_log.dbg("Buffer already completed\n");
                    result = arAlreadyExists;
                } else {
                    result = hBuffer->appendPart(part) ? arAppended : arNotAppended;
                }
            } else {
                ra_log.err("append_pkg_part: part buffer not found");
                result = arNotAppended;
            }
        } catch(const std::exception &e) {
            ra_log.exc("append_pkg_part: %s", e.what());
            result = arNotAppended;
        }
        RECV_UNLOCK;
        return result;
    }
    std::shared_ptr<unsigned char> extract_received(size_t &sz) {
        RECV_LOCK;
        try {
            ra_log.dbg("extract_received");
            for (auto &package_buffer : package_buffers) {
                auto &pkg_buffer = *package_buffer.second.get();
                auto total_hash = pkg_buffer.getHeader()->cmd_data.total_hash;
                ra_log.dbg("Extracting data");
                auto data = pkg_buffer.getData(sz);
                if (data && sz) {
                    ra_log.dbg("Data extracted");
                    ra_log.dbg("Package buffers before erase %lu", package_buffers.size());
                    package_buffers.erase(total_hash);
                    ra_log.dbg("Package buffers after erase %lu", package_buffers.size());
                    RECV_UNLOCK;
                    return data;
                }
            }
        } catch(const std::exception &e) {
            ra_log.exc("extract_received: %s", e.what());
        }
        RECV_UNLOCK;
        return nullptr;
    }
//Data send implementation
    size_t append_to_send(const unsigned char *Data, const size_t DataSz, sockaddr_in &addr) {
        size_t result = 0;
        SEND_LOCK;
        try {
            BUF_PTR(Ptr, DataSz);
            memcpy(Ptr.get(), Data, DataSz);
            /*
             * b_empty flags defines activity of on_write event;
             * it checks both data and command buffers for empty
             */
            bool b_empty = to_send.empty() &&
                           commands_to_send.empty();
            to_send.emplace_back(BufTuple(Ptr, DataSz, addr));
            result = to_send.size();
#ifdef MAX_DEQUE
            if (result > MAX_DEQUE) {
                to_send.pop_front();
                result--;
            }
#endif
            if (result && b_empty) {
                //If on_write was inactive and there is new data to send then activate on_write
                event_add(PCtx->write_event, nullptr);
            }
        } catch(const std::exception &e) {
            ra_log.exc("append_to_send: %s", e.what());
        }

        SEND_UNLOCK;
        return result;
    }

    std::shared_ptr<unsigned char> extract_to_send(size_t &sz, sockaddr_in &addr) {
        std::shared_ptr<unsigned char> ptr = nullptr;
        SEND_LOCK;
        try {
            if (to_send.empty()) {
                SEND_UNLOCK;
                sz = 0;
                return nullptr;
            }
            auto result = to_send.front();
            to_send.pop_front();
            ptr = std::get<0>(result);
            sz = std::get<1>(result);
            addr = std::get<2>(result);
        } catch(const std::exception &e) {
            ra_log.exc("extract_to_send: %s", e.what());
        }
        SEND_UNLOCK;
        return ptr;
    }
//Commands send implementation
    //NOTE: data args are commented due to current commands set does not require additional data
    size_t append_command_to_send(ProtoCommands cmd, CmdStruct &cmd_data, /*const unsigned char *Data, const size_t DataSz,*/ sockaddr_in &addr) {
        size_t result = 0;
        SEND_LOCK;
        try {
            switch(cmd)
            {
            case protoIam:
            case protoHeIs:
            case protoGetEntity:
            case protoLastHash:
            {
                //BUF_PTR(Ptr, DataSz);
                //memcpy(Ptr.get(), Data, DataSz);
                /*
                 * b_empty flags defines activity of on_write event;
                 * it checks both data and command buffers for empty
                 */
                bool b_empty = to_send.empty() &&
                               commands_to_send.empty();
                commands_to_send.emplace_back(CmdBufTuple(cmd, cmd_data,/* Ptr, DataSz, */ addr));
                result = commands_to_send.size();
#ifdef MAX_CMD_DEQUE
                if (result > MAX_CMD_DEQUE) {
                    commands_to_send.pop_front();
                    result--;
                }
#endif
                if (result && b_empty) {
                    //If on_write was inactive and there is new command to send then activate on_write
                    event_add(PCtx->write_event, nullptr);
                }
                break;
            }
            default:
                break;
            }
        } catch(const std::exception &e) {
            ra_log.exc("append_command_to_send: %s", e.what());
        }
        SEND_UNLOCK;
        return result;
    }
    ProtoCommands extract_command_to_send(CmdStruct &cmd_data, sockaddr_in &addr) {
        ProtoCommands cmd = protoNoCommand;
        SEND_LOCK;
        try {
            if (commands_to_send.empty()) {
                SEND_UNLOCK;
                return protoNoCommand;
            }
            auto result = commands_to_send.front();
            commands_to_send.pop_front();
            cmd = std::get<0>(result);
            cmd_data = std::get<1>(result);
            addr = std::get<2>(result);
        } catch(const std::exception &e) {
            ra_log.exc("extract_command_to_send: %s", e.what());
            cmd = protoUndefined;
        }
        SEND_UNLOCK;
        return cmd;
    }
    size_t append_command_received(const ProtoCommands cmd, CmdStruct &cmd_data, sockaddr_in &addr) {
        size_t result = 0;
        RECV_LOCK;
        try {
            commands_received.emplace_back(CmdBufTuple(cmd, cmd_data, addr));
            result = commands_received.size();
#ifdef MAX_CMD_DEQUE
            if (result > MAX_CMD_DEQUE) {
                commands_received.pop_front();
                result--;
            }
#endif
        } catch(const std::exception &e) {
            ra_log.exc("append_command_received: %s", e.what());
        }
        RECV_UNLOCK;
        ra_log.dbg("append_command_received: received commands deque size %d", result);
        return result;
    }
    ProtoCommands extract_command_received(CmdStruct &cmd_data, sockaddr_in &addr) {
        ProtoCommands result = protoNoCommand;
        RECV_LOCK;
        try {
            if (commands_received.empty()) {
                RECV_UNLOCK;
                return result;
            }
            auto command_received = commands_received.front();
            result = std::get<0>(command_received);
            cmd_data = std::get<1>(command_received);
            addr = std::get<2>(command_received);
            commands_received.pop_front();
        } catch(const std::exception &e) {
            ra_log.exc("extract_command_received: %s", e.what());
            result = protoInvalid;
        }
        RECV_UNLOCK;
        return result;
    }
} SendRecvDeques;
//------------------------------------------------------------------------------
bool RA_NET_CTX::launch_timer() {
    if (evtimer_add(timer_event, &one_sec) < 0) {
        ra_log.err("RA_NET_CTX::launch_timer: evtimer_add error 0x%08X", errno);
        return false;
    }
    else {
        ra_log.dbg("RA_NET_CTX::launch_timer: evtimer_add success");
        return true;
    }
}

bool RA_NET_CTX::SendTo(unsigned char *Data, size_t DataSz, sockaddr_in &addr) {
    try {
        socklen_t serverlen = sizeof(addr);
        size_t sent = 0;
        while (sent < DataSz) {
            auto n = sendto(fd, (const char *)(Data + sent), (int)(DataSz - sent), 0, (const sockaddr *) &addr, serverlen);
            if (n < 0) {
                ra_log.err("RA_NET_CTX::SendTo error %d", errno);
                //if(errno == EAGAIN) continue;
                //CLOSESOCKET(fd);
                //return false;
                break;
            }
            if (n == 0) break;
            ra_log.dbg("RA_NET_CTX::SendTo sent %d bytes to %s:%d",
                       n, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            sent += n;
        }
        ra_log.dbg("RA_NET_CTX::SendTo sent %d total bytes to %s:%d",
                   sent, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        return true;
    } catch(const std::exception &e) {
        ra_log.exc("RA_NET_CTX::SendTo: %s", e.what());
        return false;
    }
}
//------------------------------------------------------------------------------
bool prepare_to_send(unsigned char *Data, size_t DataSz, char *host, unsigned short port) {
    try {
        if (!Data) {
            ra_log.err("prepare_to_send: no data");
            return false;
        }
        if (!DataSz) {
            ra_log.err("prepare_to_send: zero size data");
            return false;
        }
        if (!host) {
            ra_log.err("prepare_to_send: no host");
            return false;
        }
        if (!port) {
            //ra_log.err("prepare_to_send: no port");
            //return false;
            port = UDP_PORT;
        }
        struct sockaddr_in sin;
        ZEROIZE(&sin);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        sin.sin_addr.s_addr = inet_addr(host);
        if (sin.sin_addr.s_addr == INADDR_NONE) return false;

        SendRecvDeques.append_to_send(Data, DataSz, sin);
//        hosts.appendHost(sin);
        return true;
    } catch(const std::exception &e) {
        ra_log.exc("prepare_to_send: %s", e.what());
    }
    return false;
}

bool ra_recv(unsigned char *Buffer,
             size_t &BufferSz,
             char *Status, const size_t StatusSz)
{
    SILENCE
    try {
        size_t data_sz = 0;
        auto data = SendRecvDeques.extract_received(data_sz);
        if (data && data_sz) {
            if (data_sz <= BufferSz) {
                BufferSz = data_sz;
                memcpy(Buffer, data.get(), data_sz);

                return true;
            } else {
                SPRINTF(Status, "Insufficient buffer size to get received data; 64K buffer recommended; data lost");
                return false;
            }
        } else {
            SPRINTF(Status, "No received data available");
            return false;
        }
    } catch(const std::exception &e) {
        ra_log.exc("ra_recv: %s", e.what());
        return false;
    }
}

bool ra_sendto(char *host, unsigned short port,
               unsigned char *Data, size_t DataSz,
               char *Status, const size_t StatusSz)
{
    SILENCE

    try {
        if (PCtx) {
            return prepare_to_send(Data, DataSz, host, port);
        } else {
            SPRINTF(Status, "ra_sendto: Networking context is not initialized");
            return false;
        }
    } catch(const std::exception &e) {
        ra_log.exc("ra_sendto: %s", e.what());
        return false;
    }
}

/*
 * Узел представляется другому узлу, отправляя ему свой идентификатор и публичный ключ.
 * Получив такой пакет узел ответит вопрошающему свой iam и перешлёт его запрос по своей подсети.
 * В результате, новому узлу представится вся подсеть, а он из них соберёт свою подсеть.
 */
bool ra_command_iam(const char *host, const unsigned short port,
                    char *Status, const size_t StatusSz)
{
    SILENCE

    //ra_log.dbg("ra_command_iam");
    try {
        if (PCtx) {
            if (!host) {
                ra_log.err("prepare_command_to_send: no host");
                return false;
            }
            ra_log.dbg("Got basic command 'I am'");
            struct sockaddr_in sin;
            ZEROIZE(&sin);
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port ? port : UDP_PORT);
            sin.sin_addr.s_addr = inet_addr(host);
            if (sin.sin_addr.s_addr == INADDR_NONE) return false;

            CmdStruct cmd_data;
            cmd_data.my_data.my_public = PCtx->ctxPubkey;
            cmd_data.my_data.random_data = seed_type();
            //ed25519_create_seed(cmd_data.my_data.random_data.data, seed_type::get_sz());//Seed size is 0x20 bytes
            return SendRecvDeques.append_command_to_send(protoIam, cmd_data, sin) > 0;
        } else {
            SPRINTF(Status, "ra_command_iam: Networking context is not initialized");
            return false;
        }
    } catch(const std::exception &e) {
        ra_log.exc("ra_command_iam: %s", e.what());
        return false;
    }
}

bool ra_command_heis(const char *host, const unsigned short port,
                     public_type &his_pub,
                     const char *his_host,
                     const unsigned short his_port,
                     char *Status, const size_t StatusSz)
{
    SILENCE

    //ra_log.dbg("ra_command_heis");
    try {
        if (PCtx) {
            if (!host) {
                ra_log.err("ra_command_heis: no host");
                return false;
            }
            ra_log.dbg("Got basic command 'He is'");
            struct sockaddr_in sin;
            ZEROIZE(&sin);
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port ? port : UDP_PORT);
            sin.sin_addr.s_addr = inet_addr(host);
            if (sin.sin_addr.s_addr == INADDR_NONE) return false;

            CmdStruct cmd_data;
            cmd_data.his_data.his_public = his_pub;
            cmd_data.his_data.addr_type = atUnknown;//TODO: fix
            cmd_data.his_data.his_addr.in.sin_family = AF_INET;
            cmd_data.his_data.his_addr.in.sin_addr.s_addr = inet_addr(his_host);//TODO: use inet_aton with linux
            cmd_data.his_data.his_addr.in.sin_port = htons(his_port);
            return SendRecvDeques.append_command_to_send(protoHeIs, cmd_data, sin) > 0;
        } else {
            SPRINTF(Status, "ra_command_iam: Networking context is not initialized");
            return false;
        }
    } catch(const std::exception &e) {
        ra_log.exc("ra_command_heis: %s", e.what());
        return false;
    }
}

/*
 * Пакет содержит ключ (хэш) сущности базы данных и отправляется узлам подсети.
 * Получившие этот запрос проверяют, если у них эта сущность отсутствует -- передает запрос
 * своей подсети, исключая того, от кого этот запрос пришёл.
 */
bool ra_command_get_entity(const char *host, const unsigned short port, hash_type &entity_hash,
                           char *Status, const size_t StatusSz)
{
    SILENCE

    //ra_log.dbg("ra_command_get_entity");
    try {
        if (PCtx) {
            if (!host) {
                ra_log.err("ra_command_get_entity: no host");
                return false;
            }
            ra_log.dbg("Got basic command 'Get Entity'");
            struct sockaddr_in sin;
            ZEROIZE(&sin);
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port ? port : UDP_PORT);
            sin.sin_addr.s_addr = inet_addr(host);
            if (sin.sin_addr.s_addr == INADDR_NONE) return false;

            CmdStruct cmd_data;
            cmd_data.entity_hash = entity_hash;
            return SendRecvDeques.append_command_to_send(protoGetEntity, cmd_data, sin) > 0;
        } else {
            SPRINTF(Status, "ra_command_iam: Networking context is not initialized");
            return false;
        }
    } catch(const std::exception &e) {
        ra_log.exc("ra_command_get_entity: %s", e.what());
        return false;
    }
}

bool ra_command_lasthash(const char *host, const unsigned short port, char *Status, const size_t StatusSz) {
    /**/
    ra_log.dbg("Got basic command 'last hash'");
    hash_type lh = db_singleton.GetLastHash();
    struct sockaddr_in sin;
    ZEROIZE(&sin);
    sin.sin_family = AF_INET;
    sin.sin_port = port;
    sin.sin_addr.s_addr = inet_addr(host);
    if (sin.sin_addr.s_addr == INADDR_NONE) return false;
    CmdStruct cmd_data;
    cmd_data.total_hash = lh;
    return SendRecvDeques.append_command_to_send(protoLastHash, cmd_data, sin);
}

/*
 * Представление со всем списком своих хостов.
 * Отправляет команду iam своему списку хостов.
 * От каждого хоста ожидается такая же команда в ответ.
 */
bool ra_present_me() {
    char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
    size_t SizeT = 0;
    auto hosts_sz = hosts.getHostsCount();
    if (hosts_sz != 0) {
        for(auto i = 0; i < hosts_sz; ++i) {
            sockaddr_in sin;
            public_type key;
            ADDR_TYPE type;
            auto result = hosts.getHost(i, sin, key, type);
            if(result) {
                auto addr = inet_ntoa(sin.sin_addr);
                if (!ra_command_iam(addr, ntohs(sin.sin_port), Status, SizeT)) {
                    ra_log.err("Not add 'I am' command for host %s, port %d : %s", addr, ntohs(sin.sin_port), Status);
                    return false;
                }
            }
        }
        return true;
    }
    else {
        ra_log.err("No defined hosts in hosts list");
        return false;
    }
}

//Event handlers----------------------------------------------------------------
void on_close(PRA_NET_CTX pctx) {
    try {
        online = false;
        delete pctx;
        ra_log.dbg("on_stop: context destroyed");
    } catch(const std::exception &e) {
        ra_log.exc("on_stop: %s", e.what());
    }
}

void on_read(evutil_socket_t fd, short flags, void* arg) {
    try {
        auto pctx = (PRA_NET_CTX) arg;

        struct sockaddr_in clientaddr;
        ZEROIZE(&clientaddr);
        socklen_t clientlen = sizeof(clientaddr);

        unsigned char buf[0x10000];
        ZEROARR(buf);
        for (;;) {
            auto n = recvfrom(fd, (char *)buf,
                              COUNT(buf), 0,
                              (sockaddr *) &clientaddr, &clientlen);
            //clientaddr.sin_port = ntohs(clientaddr.sin_port); // add 10.12.2018 обратная перекодировка порта
            if (n == sizeof(PACKAGE_HEADER)) {
//                hosts.appendHost(clientaddr);
                auto hPkgHeader = (HPACKAGE_HEADER) buf;
                if (hPkgHeader->valid()) {
                    switch(hPkgHeader->command)
                    {
                    case protoSendEntity:
                        if (SendRecvDeques.init_pkg_buffer(*hPkgHeader)) {
                            continue;
                        }
                        break;
                    case protoIam:
                        ra_log.log("Command 'I am' received from %s:%d",
                                   inet_ntoa(clientaddr.sin_addr),
                                   ntohs(clientaddr.sin_port));

                        SendRecvDeques.append_command_received(hPkgHeader->command,
                                                               hPkgHeader->cmd_data,
                                                               clientaddr);
                        break;
                    case protoHeIs:
                        ra_log.log("Command 'He is' received from %s:%d",
                                   inet_ntoa(clientaddr.sin_addr),
                                   ntohs(clientaddr.sin_port));

                        SendRecvDeques.append_command_received(hPkgHeader->command,
                                                               hPkgHeader->cmd_data,
                                                               clientaddr);
                        break;
                    case protoGetEntity:
                        ra_log.log("Command 'Get Entity' received from %s:%d",
                                   inet_ntoa(clientaddr.sin_addr),
                                   ntohs(clientaddr.sin_port));
                        SendRecvDeques.append_command_received(hPkgHeader->command,
                                                               hPkgHeader->cmd_data,
                                                               clientaddr);
                        break;
                    case protoLastHash:
                        ra_log.log("Command 'Sync LastHash' received from %s:%d",
                                   inet_ntoa(clientaddr.sin_addr),
                                   ntohs(clientaddr.sin_port));
                        SendRecvDeques.append_command_received(hPkgHeader->command,
                                                               hPkgHeader->cmd_data,
                                                               clientaddr);
                        break;
                    default:
                        ra_log.err("Unknown command %d received from %s:%d",
                                   hPkgHeader->command,
                                   inet_ntoa(clientaddr.sin_addr),
                                   ntohs(clientaddr.sin_port));
                        break;
                    }
                } else {
                    ra_log.err("Broken package header received from %s:%d",
                               inet_ntoa(clientaddr.sin_addr),
                               ntohs(clientaddr.sin_port));
                }
            } else {
                if (n == sizeof(PACKAGE_PART)) {
                    auto hPkgPart = (HPACKAGE_PART) buf;
                    switch (SendRecvDeques.append_pkg_part(*hPkgPart)) {
                    case arAppended:
                        continue;
                    case arAlreadyExists:
                    case arNotAppended:
                    default:
                        break;
                    }
                }
            }
            if (n <= 0) break;
        }
    } catch(const std::exception &e) {
        ra_log.exc("on_read: %s", e.what());
    }
}

void on_write(evutil_socket_t fd, short flags, void *arg) {
    try {
        auto pctx = (PRA_NET_CTX) arg;
        size_t DataSz;
        sockaddr_in addr;
        ZEROIZE(&addr);
        auto Data = SendRecvDeques.extract_to_send(DataSz, addr);
        if (Data && DataSz) {
            PACKAGE_BUFFER package_buffer(Data, DataSz,
                                          pctx->ctxPubkey, pctx->ctxPrivKey);
            auto hHeader = package_buffer.getHeader();
            if (pctx->SendTo((unsigned char *) hHeader, sizeof(*hHeader), addr)) {
                const size_t c_parts_count = hHeader->parts_count();
                for (size_t i = 0; i < c_parts_count; ++i) {
                    auto part_ptr = package_buffer.getPart(i);
                    pctx->SendTo((unsigned char *) part_ptr.get(), sizeof(PACKAGE_PART), addr);
                }
            }
        } else {
            CmdStruct cmd_data;
            auto cmd = SendRecvDeques.extract_command_to_send(cmd_data, addr);
            switch(cmd)
            {
            case protoIam:
            case protoHeIs:
            case protoGetEntity:
            case protoLastHash:
            {
                PACKAGE_HEADER header(cmd, cmd_data, pctx->ctxPubkey, pctx->ctxPrivKey);
                if (pctx->SendTo((unsigned char *) &header, sizeof(header), addr)) {
                    //
                } else {
                    //
                }
                break;
            }
            case protoNoCommand:
            case protoUndefined:
            default:
                event_del(pctx->write_event);
                break;
            }
        }
    } catch(const std::exception &e) {
        ra_log.exc("on_write: %s", e.what());
    }
}

void on_timer(evutil_socket_t fd, short kind, void *arg) {
    try {
        auto pctx = (PRA_NET_CTX) arg;
        if (!online) {
            ra_log.dbg("networking stop");
            event_base_loopbreak(pctx->base);
        } else {
//            ra_log.dbg("networking timer reset");
            if (!evtimer_pending(pctx->timer_event, nullptr)) {
#ifdef _WIN32
                ra_log.err("evtimer_pending error 0x%08X", WSAGetLastError());
#else
                ra_log.err("evtimer_pending error 0x%08X", errno);
#endif
                if (evtimer_del(pctx->timer_event) < 0) {
#ifdef _WIN32
                    ra_log.err("evtimer_del error 0x%08X", WSAGetLastError());
#else
                    ra_log.err("evtimer_del error 0x%08X", errno);
#endif
                }
                else {
                    //ra_log.dbg("networking timer disable");
                }
                if (evtimer_add(pctx->timer_event, &one_sec) < 0) {
#ifdef _WIN32
                    ra_log.err("evtimer_add error 0x%08X", WSAGetLastError());
#else
                    ra_log.err("evtimer_add error 0x%08X", errno);
#endif
                }
                else {
                    //ra_log.dbg("networking timer readd");
                }
            }
            else {
                ra_log.dbg("evtimer_pending success");
            }
        }
    } catch(const std::exception &e) {
        ra_log.exc("on_timer: %s", e.what());
    }
}
//------------------------------------------------------------------------------
void ra_net_cmd_proc() {
    for(;;) {
        if(!online) {
            ra_log.dbg("network command thread stop");
            break;
        }
        CmdStruct cmd_data;
        sockaddr_in addr;
        ZEROIZE(&addr);
        ProtoCommands cmd = SendRecvDeques.extract_command_received(cmd_data, addr);
        switch(cmd)
        {
        case protoInvalid:
        {
            ra_log.err("Commands deque failure, networking stop");
            online = false;
            return;
        }
        case protoNoCommand:
        {
#ifdef _WIN32
            Sleep(1000);
#else
            sleep(1);
#endif
            break;
        }
        default:
        {
            ra_log.dbg("Got command %d from deque", cmd);
            if(handlers_pool.try_command(cmd, cmd_data, addr)) {
                //ra_log.log("Command treatment success, next to try");
            } else {
                ra_log.err("Command treatment failure, next to try");
            }
            break;
        }
        }
    }
    ra_log.dbg("network command thread end");
}

void ra_net_proc(const public_type &ownPub,
                 const private_type &ownPriv,
                 const char *host,
                 const unsigned short port)
{
    if(!PCtx) {
        ra_log.dbg("initializing network context");
        try {
            PCtx = new RA_NET_CTX(ownPub, ownPriv, host, port);
        } catch (std::exception &e) {
            ra_log.exc("Network context initialization failure: %s", e.what());
            PCtx = nullptr;
            return;
        }
    }

    if(PCtx) {
        ra_log.dbg("network context initialized");
        online = true;

        CMD_HANDLERS_POOL::COMMAND_EMITS emits = {
            ra_command_iam,
            ra_command_heis,
            ra_command_get_entity,
            ra_command_lasthash
        };
        if(handlers_pool.init_emits(emits)) {
            ra_log.log("Command Handlers pool initialized successfully");
        } else {
            ra_log.err("Command Handlers pool initialization error");
        }
        std::thread cmd_th(ra_net_cmd_proc);
        cmd_th.detach();
        if(cmd_th.joinable()) {
            ra_log.err("Command thread launch failure, deinitializing network...");
            delete PCtx;
            online = false;
            PCtx = nullptr;
            return;
        } else {
            //
        }

        PCtx->launch_timer();
        if(event_base_dispatch(PCtx->base) < 0) {
            ra_log.err("event_base_dispatch error 0x%08X", errno);
        } else {
            ra_log.err("event_base_dispatch deblocked");
        }
        on_close(PCtx);
        PCtx = nullptr;
    }
    ra_log.dbg("network thread end");
}

bool ra_net_launch(const public_type &ownPub,
                   const private_type &ownPriv,
                   const char *host,
                   const unsigned short port)
{
    ra_log.dbg("network start");
    ra_log.dbg("Public key:");
    ownPub.print();
    ra_log.dbg("Private key:");
    ownPriv.print();
    std::thread th(ra_net_proc,
                   ownPub,
                   ownPriv,
                   host,
                   port);
    th.detach();
    return !th.joinable();
}

void ra_net_stop() {
    ra_log.dbg(online ? "network stopping" : "network stopped already");
    online = false;
}

bool ra_net_available() {
    return online;
}

sockaddr_in get_self_sin() {
    return PCtx->ctxSin;
}
//------------------------------------------------------------------------------
int ra_net_synclasthash() {
    if (!online || !PCtx) {
        ra_log.err("Network not available");
        return -1;
    }
    else {
        sockaddr_in hst;
        public_type pkey;
        ADDR_TYPE atype = ADDR_TYPE::atUnknown;
        char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
        char *hme = inet_ntoa(PCtx->sin.sin_addr);
        unsigned int portme = PCtx->sin.sin_port;
        for (int i = 0; i < hosts.getHostsCount(); i++) {
            hosts.getHost(i, hst, pkey, atype);
            auto ihost = inet_ntoa(hst.sin_addr);
            if ((hme != ihost) || ( portme!= hst.sin_port)) {
                return !ra_command_lasthash(inet_ntoa(hst.sin_addr), hst.sin_port,Status,0);
                //TODO:2: организовать перебор по хостам ??
                break;
            }
            else
                ZEROIZE(&hst);
        }
        return 0;
    }


}
