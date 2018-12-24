#include "proto.h"
#include "blocks_thread.h"
#include "ra-net.h"


CMD_HANDLERS_POOL handlers_pool;
//------------------------------------------------------------------------------
PACKAGE_HEADER::PACKAGE_HEADER() : dwsz(0), command(protoNoCommand) {
    ZEROARR(header_signature.data);
    ZEROARR(cmd_data.total_hash.data);
}

PACKAGE_HEADER::PACKAGE_HEADER(size_t _sz, hash_type &hash, public_type &pub, private_type &priv) : dwsz(_sz), command(protoSendEntity) {
    const size_t c_signed_sz = sizeof(PACKAGE_HEADER) - FIELD_OFFS(PACKAGE_HEADER, pubkey);
    memcpy(cmd_data.total_hash.data, hash.data, sizeof(hash_type));
    memcpy(pubkey.data, pub.data, public_type::get_sz());
    if(!sign(pubkey.data,
             c_signed_sz,
             pub.data,
             public_type::get_sz(),
             priv.data,
             private_type::get_sz(),
             header_signature.data,
             sign_type::get_sz()))

    {
        throw std::runtime_error("Package header: sign failure");
    }
}

PACKAGE_HEADER::PACKAGE_HEADER(ProtoCommands cmd,
                               CmdStruct &_cmd_data,
                               public_type &pub,
                               private_type &priv,
                               unsigned char *ext_data,
                               size_t ext_data_sz) : command(cmd), dwsz(ext_data_sz)
{
    switch(command) {
    case protoIam:
    {
        ra_log.dbg("'I am' command PACKAGE_HEADER");
        if(dwsz)
            throw std::runtime_error("Package header: invalid length");
        if(pub != _cmd_data.my_data.my_public)
            throw std::runtime_error("Package header: public keys mismatch");
        cmd_data = _cmd_data;
        break;
    }
    case protoHeIs:
    {
        ra_log.dbg("'He is' command PACKAGE_HEADER");
        if(dwsz)
            throw std::runtime_error("Package header: invalid length");
        cmd_data = _cmd_data;
        break;
    }
    case protoGetEntity:
    {
        ra_log.dbg("'Get entity' command PACKAGE_HEADER");
        if(dwsz)
            throw std::runtime_error("Package header: invalid length");
        cmd_data = _cmd_data;
        break;
    }
    case protoLastHash:
    {
        ra_log.dbg("'Last Hash' command PACKAGE_HEADER");
        if (dwsz)
            throw std::runtime_error("Package header: invalid length");
        cmd_data = _cmd_data;
        break;
    }
    default:
        throw std::runtime_error("Package header: invalid command");
    }
    ra_log.dbg("Command PACKAGE_HEADER creation for %d cmd code", command);
    const size_t c_signed_sz = sizeof(PACKAGE_HEADER) - FIELD_OFFS(PACKAGE_HEADER, pubkey);
    pubkey = pub;
    if(!sign(pubkey.data,
             c_signed_sz,
             pub.data,
             public_type::get_sz(),
             priv.data,
             private_type::get_sz(),
             header_signature.data,
             sign_type::get_sz()))

    {
        throw std::runtime_error("Package header: sign failure");
    }
}

bool PACKAGE_HEADER::valid() {
    const size_t c_signed_sz = sizeof(PACKAGE_HEADER) - FIELD_OFFS(PACKAGE_HEADER, pubkey);
    switch(command)
    {
    case protoSendEntity:
    {
        if(!dwsz) {
            ra_log.err("Data buffer is empty for PACKAGE_HEADER command %d", command);
            return false;
        }
        break;
    }
    case protoIam:
    case protoHeIs:
    case protoGetEntity:
    case protoLastHash:
    {
        if(dwsz) {
            ra_log.err("Data buffer is not empty for PACKAGE_HEADER command %d", command);
            return false;
        }
        break;
    }
    default:
        ra_log.err("Unknown PACKAGE_HEADER command %d", command);
        return false;
    }
    if(!verify(pubkey.data,
               c_signed_sz,
               pubkey.data,
               public_type::get_sz(),
               header_signature.data,
               sign_type::get_sz()))
    {
        ra_log.err("PACKAGE_HEADER signature mismatch");
        return false;
    }
    return true;
}

bool PACKAGE_HEADER::init(size_t _sz, hash_type &hash, public_type &pub, private_type &priv) {
    const size_t c_signed_sz = sizeof(PACKAGE_HEADER) - FIELD_OFFS(PACKAGE_HEADER, pubkey);
    dwsz = _sz;
    command = protoSendEntity;
    cmd_data.total_hash = hash;
    pubkey = pub;
    return sign(pubkey.data,
                c_signed_sz,
                pub.data,
                public_type::get_sz(),
                priv.data,
                private_type::get_sz(),
                header_signature.data,
                sign_type::get_sz());
}

size_t PACKAGE_HEADER::parts_count() const {
    //return (dwsz / MAX_PART_SIZE) + (dwsz % MAX_PART_SIZE != 0);
    return (dwsz >> 0x0A) + ((PRED(MAX_PART_SIZE) & dwsz) != 0);
}
//------------------------------------------------------------------------------
bool PACKAGE_PART::check_hash() const {
    const size_t c_hashed_sz = sizeof(PACKAGE_PART_HEADER) -
                               FIELD_OFFS(PACKAGE_PART_HEADER, total_hash) +
                               header.sz;
    hash_type hash;
    if(blake2(hash.data, sizeof(hash_type), &header.total_hash, c_hashed_sz, nullptr, 0) < 0) {
        return false;
    }
    return header.part_hash == hash;
}

bool PACKAGE_PART::calc_hash() {
    const size_t c_hashed_sz = sizeof(PACKAGE_PART_HEADER) -
                               FIELD_OFFS(PACKAGE_PART_HEADER, total_hash) +
                               header.sz;
    if(blake2(header.part_hash.data, sizeof(hash_type), &header.total_hash, c_hashed_sz, nullptr, 0) < 0) {
        return false;
    }
    return true;
}

PP_VALID_ERR PACKAGE_PART::valid(const PACKAGE_HEADER &package_header) const {
    if(header.sz > MAX_PART_SIZE) {
        return ppveSzError;
    }
    if(package_header.parts_count() <= header.N) {
        return ppveNumberError;
    }
    if(package_header.cmd_data.total_hash !=
            header.total_hash)
    {
        return ppveTotalHashError;
    }
    if(!check_hash()) {
        return ppveHashError;
    }
    return ppveNoError;
}
//------------------------------------------------------------------------------
bool PACKAGE_PART_PTR::calc_hash() {
    const size_t c_header_hashed_sz =
        sizeof(PACKAGE_PART_HEADER) -
        FIELD_OFFS(PACKAGE_PART_HEADER, total_hash);
    blake2b_state S[1];
    if( blake2b_init( S, sizeof(header.part_hash) ) < 0 ) return false;
    blake2b_update( S, &header.total_hash, c_header_hashed_sz );
    blake2b_update( S, ptr, header.sz );
    blake2b_final( S, header.part_hash.data, sizeof(header.part_hash));
    return true;
}

bool PACKAGE_PART_PTR::valid() {
    if(!ptr) return false;
    hash_type hash;
    const size_t c_header_hashed_sz =
        sizeof(PACKAGE_PART_HEADER) -
        FIELD_OFFS(PACKAGE_PART_HEADER, total_hash);
    blake2b_state S[1];
    if( blake2b_init( S, sizeof(hash) ) < 0 ) return false;
    blake2b_update( S, &header.total_hash, c_header_hashed_sz );
    blake2b_update( S, ptr, header.sz );
    blake2b_final( S, hash.data, sizeof(header.part_hash));
    return (hash == header.part_hash);
}
//------------------------------------------------------------------------------
PACKAGE_BUFFER::PACKAGE_BUFFER(const PACKAGE_HEADER &init_header) : buffer(new unsigned char[init_header.dwsz],
            std::default_delete<unsigned char[]>()),
    header(init_header),
    b_completed(false)
{
    parts.resize(header.parts_count());
}

PACKAGE_BUFFER::PACKAGE_BUFFER(std::shared_ptr<unsigned char> data,
                               size_t data_sz,
                               public_type &pub,
                               private_type &priv) : buffer(data),
    b_completed(false)
{
    hash_type total_hash;
    if(blake2(total_hash.data,
              sizeof(hash_type),
              data.get(),
              data_sz,
              nullptr,
              0) < 0)
    {
        throw std::runtime_error("Package buffer: hash failure");
    }
    if(!header.init(data_sz, total_hash, pub, priv)) {
        throw std::runtime_error("Package header: hash failure");
    }

    const size_t c_parts_count = header.parts_count();
    parts.resize(c_parts_count);
    for(size_t i = 0; i < c_parts_count; ++i) {
        auto &Ptr = parts[i];
        Ptr.ptr = data.get() + i * MAX_PART_SIZE;
        Ptr.header.total_hash = total_hash;
        Ptr.header.N = i;
        if(i == PRED(c_parts_count)) {
            Ptr.header.sz = data_sz & PRED(MAX_PART_SIZE);//data_sz % MAX_PART_SIZE;
            if(!Ptr.header.sz) Ptr.header.sz = MAX_PART_SIZE;
        } else {
            Ptr.header.sz = MAX_PART_SIZE;
        }
        if(!Ptr.calc_hash()) {
            parts.resize(0);
            throw std::runtime_error("Part hash failure");
        } else {
            PACKAGE_PART part;
            memcpy(part.data, Ptr.ptr, Ptr.header.sz);
            part.header = Ptr.header;
            part.calc_hash();
        }
    }
}

std::shared_ptr<PACKAGE_PART> PACKAGE_BUFFER::getPart(size_t N) {
    if(N >= header.parts_count())
        return nullptr;
    auto &part_ptr = parts[N];
    if(!part_ptr.valid())
        return nullptr;
    if(part_ptr.header.total_hash !=
            header.cmd_data.total_hash)
        return nullptr;
    std::shared_ptr<PACKAGE_PART> ppart(new PACKAGE_PART());
    ppart.get()->header = part_ptr.header;
    memcpy(ppart.get()->data,
           part_ptr.ptr,
           part_ptr.header.sz);
    return ppart;
}

bool PACKAGE_BUFFER::appendPart(const unsigned char *data, size_t data_sz) {
    if(!data) return false;
    if(data_sz < sizeof(PACKAGE_PART)) return false;
    if(!valid()) return false;

    auto hPackagePart = (HPACKAGE_PART)data;
    if(hPackagePart->valid(header) != ppveNoError) return false;
    const size_t c_N = hPackagePart->header.N;
    const size_t c_sz = hPackagePart->header.sz;

    auto &part_ptr = parts[c_N];
    //TODO: check for already filled
    unsigned char *ptr = &buffer.get()[c_N * MAX_PART_SIZE];
    part_ptr.ptr = ptr;
    part_ptr.header.N = c_N;
    part_ptr.header.sz = c_sz;
    part_ptr.header.total_hash = header.cmd_data.total_hash;
    part_ptr.header.part_hash = hPackagePart->header.part_hash;
    memcpy(ptr, hPackagePart->data, c_sz);
    return true;
}

bool PACKAGE_BUFFER::appendPart(const PACKAGE_PART &part) {
    if(!valid()) {
        return false;
    }
    PP_VALID_ERR ppve = part.valid(header);
    if(ppve != ppveNoError) {
        return false;
    }
    const size_t c_N =
        part.header.N;
    const size_t c_sz =
        part.header.sz;

    auto &part_ptr = parts[c_N];
    //TODO: check for already filled
    unsigned char *ptr = &buffer.get()[c_N * MAX_PART_SIZE];
    part_ptr.ptr = ptr;
    part_ptr.header.N = c_N;
    part_ptr.header.sz = c_sz;
    part_ptr.header.total_hash = header.cmd_data.total_hash;
    part_ptr.header.part_hash = part.header.part_hash;
    memcpy(ptr, part.data, c_sz);
    return true;
}

bool PACKAGE_BUFFER::valid() {
    if(buffer == nullptr) return false;
    if(!header.valid()) {
        return false;
    }
    const size_t c_parts_count = header.parts_count();
    if(c_parts_count != parts.size()) {
        return false;
    }
    for(size_t i = 0; i < c_parts_count; ++i) {
        auto part = parts[i];
        if(((i > 0) && (!part.header.N)) || (!part.ptr)) continue;//Incompleted
        if(part.header.N != i) {
            return false;//Check for index
        }
        if(part.ptr != &buffer.get()[i * MAX_PART_SIZE]) {
            return false;//Check for pointer
        }
        if((i != PRED(c_parts_count)) && (part.header.sz != MAX_PART_SIZE)) {
            return false;
        }
        if(!part.valid()) {
            return false;//Check for hash
        }
    }
    return true;
}

bool PACKAGE_BUFFER::completed() {
    if(b_completed) {
        return true;
    }
    ra_log.dbg("PACKAGE_BUFFER::completed");
    //for(size_t i = 0; i < parts.size(); ++i) {
    for(auto &part : parts) {
        //auto &part = parts[i];
        //if((i > 0) && (!part.header.N)) return false;
        if(!part.ptr) return false;
    }
    b_completed = true;
    return true;
}

std::shared_ptr<unsigned char> PACKAGE_BUFFER::getData(size_t &data_sz) {
    if(!valid()) {
        ra_log.err("PACKAGE_BUFFER::getData: buffer invalid");
        data_sz = 0;
        return nullptr;
    }
    if(!completed()) {
        ra_log.warn("PACKAGE_BUFFER::getData: buffer incompleted");
        data_sz = 0;
        return nullptr;
    }
    data_sz = header.dwsz;
    return buffer;
}
//------------------------------------------------------------------------------
bool parse_package_header(const unsigned char *data,
                          const size_t data_sz,
                          hash_type &total_hash,
                          size_t &length,
                          char *Status,
                          size_t StatusSz)
{
    SILENCE

    ZEROIZE(&total_hash);
    length = 0;

    CHECK_SZ_LESS(data_sz, sizeof(PACKAGE_HEADER), "Data")
    CHECK_NULL("Data", data)

    auto hPackageHeader = (HPACKAGE_HEADER)data;
    if(hPackageHeader->valid()) {
        length = hPackageHeader->dwsz;
        total_hash = hPackageHeader->cmd_data.total_hash;
        SPRINTF(Status,
                length ? "Data contains valid header" :
                "Data contains valid header, package is empty");
        return true;
    } else {
        SPRINTF(Status, "Hash inconsistency");
        return false;
    }
}

bool parse_package_part_header(const PACKAGE_HEADER &package_header,
                               const unsigned char *data,
                               const size_t data_sz,
                               hash_type &hash,
                               size_t &sz,
                               size_t &N,
                               char *Status,
                               size_t StatusSz)
{
    SILENCE

    CHECK_SZ_LESS(data_sz, sizeof(PACKAGE_PART), "Data")
    CHECK_NULL("Data", data)

    ZEROARR(hash.data);
    sz = 0;
    N = 0;

    auto hPackagePart = (HPACKAGE_PART)data;
    PP_VALID_ERR ppve = hPackagePart->valid(package_header);
    switch(ppve)
    {
    case ppveNoError:
    {
        hash = hPackagePart->header.part_hash;
        sz = hPackagePart->header.sz;
        N = hPackagePart->header.N;
        SPRINTF(Status, "Found package part %lu of %lu", hPackagePart->header.N, package_header.parts_count());
        return true;
    }
    case ppveSzError:
    {
        SPRINTF(Status, "Invalid part size");
        break;
    }
    case ppveNumberError:
    {
        SPRINTF(Status,
                "Wrong part number %lu of %lu",
                hPackagePart->header.N, package_header.parts_count());
        break;
    }
    case ppveTotalHashError:
    {
        SPRINTF(Status, "Total hash mismatch");
        break;
    }
    case ppveHashError:
    {
        SPRINTF(Status, "Hash inconsistency");
        break;
    }
    default:
    {
        SPRINTF(Status, INTERNAL_ERR, (int)ppve);
        break;
    }
    }
    return false;
}
//------------------------------------------------------------------------------
bool CMD_HANDLERS_POOL::proto_handle_Iam(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
    ra_log.log("proto_handle_Iam");

    const char *his_host = inet_ntoa(addr.sin_addr);
    const unsigned short his_port = ntohs(addr.sin_port);
    if(lua_callback_name) {
        LUA

        lua_State *l = handlers_pool.Lstate;
        lua_settop (l, 0);
        lua_getglobal(l, lua_callback_name);
        // Если в lua прокинут callback -- выполнится его запуск
        if ( lua_isnil(l,-1) ) {
            lua_settop(l, 0);
        } else {
            lua_pushstring(l, his_host);
            lua_pushnumber(l, his_port);
            lua_pushlightuserdata(l, cmd_data.my_data.my_public.data);
            auto lua_res = lua_pcall(l,3,1,0);
            if(lua_res != LUA_OK) {
                ra_log.err("'I am': LUA error: %s", lua_tostring(l, -1));
            } else {
                const auto res = (CALLBACK_RES) lua_tointeger(l, -1);
                lua_settop(l, 0);
                switch (res) {
                case cbresError:
                    ra_log.err("'I am': Lua callback error");
                    return false;
                case cbresPass:
                    break;
                case cbresBreak:
                    return true;
                default:
                    ra_log.err("'I am': Unknown lua callback result %d", res);
                    return false;
                }
            }
        }
    }
    bool result = false;
    const size_t c_hosts_count = hosts.getHostsCount();
    if(!c_hosts_count) {
        ra_log.log("There is no hosts to notify about %s:%d", his_host, his_port);
    }
    auto self_sin = get_self_sin();
    // Для каждого принятого пакета iam отправляем пакет he is по всему списку хостов
    for(size_t i = 0; i < c_hosts_count; ++i) {
        sockaddr_in cur_addr;
        ZEROIZE(&cur_addr);
        ADDR_TYPE addr_type = atUnknown;
        public_type pub;
        // берем очередной хост
        if(hosts.getHost(i, cur_addr, pub, addr_type)) {
            // проверяем совпадение по адресу
            if(!(
                        (self_sin.sin_addr.s_addr == cur_addr.sin_addr.s_addr) &&
                        (self_sin.sin_port == cur_addr.sin_port)
                    )) {
                char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
                const char *cur_host = inet_ntoa(cur_addr.sin_addr);
                const unsigned short cur_port = ntohs(cur_addr.sin_port);
                if(handlers_pool.hEmits->heis(cur_host,
                                              cur_port,
                                              cmd_data.my_data.my_public,
                                              inet_ntoa(addr.sin_addr),
                                              ntohs(addr.sin_port),
                                              Status,
                                              COUNT(Status)))
                {
                    result = true;
                    ra_log.log("Authentic data of %s:%d sent to %s:%d",
                               his_host, his_port, cur_host, cur_port);
                } else {
                    ra_log.err("proto_handle_Iam 'He is' send error %s", Status);
                }
                // хост-отправитель iam команды добавляется в список хостов
                db_singleton.insert_host(his_host, his_port);
            }
        }
    }
    return result;
}

bool CMD_HANDLERS_POOL::proto_handle_HeIs(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
    ra_log.log("proto_handle_HeIs");

    const char *his_host = inet_ntoa(addr.sin_addr);
    const unsigned short his_port = ntohs(addr.sin_port);

    if(lua_callback_name) {
        LUA

        lua_State *l = handlers_pool.Lstate;
        lua_settop (l, 0);
        lua_getglobal(l, lua_callback_name);
        if ( lua_isnil(l,-1) ) {
            lua_settop(l, 0);
        } else {
            lua_pushstring(l, inet_ntoa(addr.sin_addr));
            lua_pushnumber(l, htons(addr.sin_port));
            lua_pushstring(l, inet_ntoa(cmd_data.his_data.his_addr.in.sin_addr));
            lua_pushnumber(l, htons(cmd_data.his_data.his_addr.in.sin_port));
            lua_pushlightuserdata(l, cmd_data.his_data.his_public.data);
            auto lua_res = lua_pcall(l,5,1,0);
            if(lua_res != LUA_OK) {
                ra_log.err("'He is': LUA error: %s", lua_tostring(l, -1));
            } else {
                const auto res = (CALLBACK_RES) lua_tointeger(l, -1);
                lua_settop(l, 0);
                switch (res) {
                case cbresError:
                    ra_log.err("'He is': Lua callback error");
                    return false;
                case cbresPass:
                    break;
                case cbresBreak:
                    return true;
                default:
                    ra_log.err("'He is': Unknown lua callback result %d", res);
                    return false;
                }
            }
        }
    }

    RA_HOST host{addr, ADDR_TYPE::atUnknown};
    public_type key;
    if(hosts.getHost(key, host.address, host.addr_type)) {
        ;
    }
    else {
        db_singleton.insert_host(his_host, his_port);
    }

    return true;
}

bool CMD_HANDLERS_POOL::proto_handle_GetEntity(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
    if(lua_callback_name) {
        LUA

        lua_State *l = handlers_pool.Lstate;
        lua_settop (l, 0);
        lua_getglobal(l, lua_callback_name);
        if ( lua_isnil(l,-1) ) {
            lua_settop(l, 0);
        } else {
            lua_pushstring(l, inet_ntoa(addr.sin_addr));
            lua_pushnumber(l, htons(addr.sin_port));
            lua_pushlightuserdata(l, cmd_data.entity_hash.data);
            auto lua_res = lua_pcall(l,3,1,0);
            if(lua_res != LUA_OK) {
                ra_log.err("'Get Entity': LUA error: %s", lua_tostring(l, -1));
            } else {
                const auto res = (CALLBACK_RES) lua_tointeger(l, -1);
                lua_settop(l, 0);
                switch (res) {
                case cbresError:
                    ra_log.err("'Get Entity': Lua callback error");
                    return false;
                case cbresPass:
                    break;
                case cbresBreak:
                    return true;
                default:
                    ra_log.err("'Get Entity': Unknown lua callback result %d", res);
                    return false;
                }
            }
        }
    }

    ra_log.log("proto_handle_GetEntity");
    return true;
}

bool CMD_HANDLERS_POOL::proto_handle_LastHash(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
    if (db_singleton.sync_on && db_singleton.sync_addr.sin_port == addr.sin_port && db_singleton.sync_addr.sin_addr.s_addr==addr.sin_addr.s_addr )
        return true; // если запущена синхронизация и адреса совпадают - никаких действий не производится
    //TODO: (??) действия callback НЕ ДОЛЖНЫ (или ДОЛЖНЫ??) перекрывать действия кода:: перенести вызов callback ниже
    if (lua_callback_name) {
        LUA

        lua_State *l = handlers_pool.Lstate;
        lua_settop(l, 0);
        lua_getglobal(l, lua_callback_name);
        if (lua_isnil(l, -1)) {
            lua_settop(l, 0);
        }
        else {
            lua_pushstring(l, inet_ntoa(addr.sin_addr));
            lua_pushnumber(l, htons(addr.sin_port));
            lua_pushlightuserdata(l, cmd_data.entity_hash.data);
            auto lua_res = lua_pcall(l, 3, 1, 0);
            if (lua_res != LUA_OK) {
                ra_log.err("'Last Hash': LUA error: %s", lua_tostring(l, -1));
            }
            else {
                const auto res = (CALLBACK_RES)lua_tointeger(l, -1);
                lua_settop(l, 0);
                switch (res) {
                case cbresError:
                    ra_log.err("'Last Hash': Lua callback error");
                    return false;
                case cbresPass:
                    break;
                case cbresBreak:
                    return true;
                default:
                    ra_log.err("'Last Hash': Unknown lua callback result %d", res);
                    return false;
                }
            }
        }
    }
    hash_type mylasthash = db_singleton.GetLastHash();
    if (mylasthash != cmd_data.total_hash) {
        if (db_singleton.hashExists(cmd_data.total_hash)) {
            //TODO: generate cmd lasthash
            ra_log.dbg("Last hash HANDLE: need generate 'Last hash' command to %s:%d", inet_ntoa(addr.sin_addr), htons(addr.sin_port));
        }
        else {
            //!! флаг начала синхронизации взводится здесь - сбрасываться должен в handle_GetEntity
            ra_log.dbg("Last hash HANDLE: syncronization requered!");
            ra_log.dbg("Last hash HANDLE: need generate 'Get Entity' command to %s:%d", inet_ntoa(addr.sin_addr), htons(addr.sin_port));
            db_singleton.sync_addr = addr;
            db_singleton.sync_on = true;
            //TODO: generate cmd GetEntity
        }
    }
    else {
        // TODO: send sync ok message
        ra_log.dbg("Last hash HANDLE: nothing do, hashes equal width %s:%d", inet_ntoa(addr.sin_addr), htons(addr.sin_port));
    }
    return true;
}
//------------------------------------------------------------------------------
CMD_HANDLERS_POOL::CMD_HANDLERS_POOL() : hEmits(nullptr), Lstate(luaL_newstate()) {
    if(Lstate) {
        ra_log.log("LUA initialized");
        //Common libraries load for new LUA state instance
        luaL_openlibs(Lstate);
    } else {
        ra_log.err("LUA initialization failure");
    }
}

CMD_HANDLERS_POOL::~CMD_HANDLERS_POOL() {
    delete hEmits;
    if(Lstate) {
        lua_close(Lstate);
        ra_log.log("LUA deinitialized");
    }
}

bool CMD_HANDLERS_POOL::init_lua_src(const char *src) {
    ra_log.dbg("luaL_dofile loads %s", src);
    int res = luaL_dofile(Lstate, src);
    if(res) ra_log.err( "Error loading %s: %s", src, luaL_checkstring (Lstate, -1) );
    bool result = res == LUA_OK;
    ra_log.dbg("luaL_dofile result: %d", res);
    for(auto &handler : handlers) {
        if(handler.handler && handler.callback_name) {
            lua_getglobal(Lstate, handler.callback_name);
            if(lua_isnil(Lstate,-1)) {
                ra_log.log("LUA callback %s not found", handler.callback_name);
                handler.callback_name = nullptr;
            } else {
                ra_log.log("LUA callback %s found", handler.callback_name);
            }
            lua_settop(Lstate, 0);//?
        }
    }
    return result;
}

bool CMD_HANDLERS_POOL::try_command(ProtoCommands cmd, CmdStruct &cmd_data, sockaddr_in &addr) {
    if(cmd < protoNoCommand) return false;
    if(cmd >= protoCount) return false;
    const CmdDesc &Desc = handlers[cmd];
    CmdHandler handler = Desc.handler;
    if(!handler) return false;
    return handler(cmd_data, addr, Desc.callback_name);
}
//------------------------------------------------------------------------------
