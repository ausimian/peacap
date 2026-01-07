#include <erl_nif.h>
#include <erl_driver.h>
#include <pcap/pcap.h>
#include <string.h>
#include <errno.h>

// Resource type for pcap handles
static ErlNifResourceType *pcap_resource_type = NULL;

// Atoms
static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_select;
static ERL_NIF_TERM atom_nowait;
static ERL_NIF_TERM atom_undefined;
static ERL_NIF_TERM atom_closed;
static ERL_NIF_TERM atom_peacap;
static ERL_NIF_TERM atom_no_selectable_fd;
static ERL_NIF_TERM atom_enomem;
static ERL_NIF_TERM atom_noproc;
static ERL_NIF_TERM atom_select_failed;
static ERL_NIF_TERM atom_break;

// Resource structure
typedef struct {
    pcap_t *handle;
    int fd;
    int closed;
    ErlNifPid owner;
    ErlNifMonitor mon;
} pcap_resource_t;

// Forward declarations
static void pcap_resource_dtor(ErlNifEnv *env, void *obj);
static void pcap_resource_stop(ErlNifEnv *env, void *obj, ErlNifEvent event, int is_direct_call);
static void pcap_resource_down(ErlNifEnv *env, void *obj, ErlNifPid *pid, ErlNifMonitor *mon);

static ErlNifResourceTypeInit pcap_resource_init = {
    .dtor = pcap_resource_dtor,
    .stop = pcap_resource_stop,
    .down = pcap_resource_down,
    .members = 4,
    .dyncall = NULL
};

// Resource destructor - idempotent, safe to call multiple times
static void pcap_resource_dtor(ErlNifEnv *env, void *obj)
{
    (void)env;
    pcap_resource_t *res = (pcap_resource_t *)obj;
    if (res->handle && !res->closed) {
        pcap_close(res->handle);
        res->handle = NULL;
        res->fd = -1;
        res->closed = 1;
    }
}

// Called when enif_select is stopped
static void pcap_resource_stop(ErlNifEnv *env, void *obj, ErlNifEvent event, int is_direct_call)
{
    (void)event;
    (void)is_direct_call;
    pcap_resource_dtor(env, obj);
}

// Called when the monitored owner process dies
static void pcap_resource_down(ErlNifEnv *env, void *obj, ErlNifPid *pid, ErlNifMonitor *mon)
{
    (void)pid;
    (void)mon;
    pcap_resource_t *res = (pcap_resource_t *)obj;

    if (!res->closed && res->fd >= 0) {
        enif_select(env, (ErlNifEvent)(long)res->fd, ERL_NIF_SELECT_STOP, res, NULL, atom_undefined);
    }
}

// NIF: open(interface, snaplen, promisc) -> {:ok, resource} | {:error, reason}
static ERL_NIF_TERM nif_open(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;

    char interface[256];
    int snaplen, promisc;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (enif_get_string(env, argv[0], interface, sizeof(interface), ERL_NIF_LATIN1) <= 0) {
        return enif_make_badarg(env);
    }

    if (!enif_get_int(env, argv[1], &snaplen) ||
        !enif_get_int(env, argv[2], &promisc)) {
        return enif_make_badarg(env);
    }

    // timeout_ms=0 since we use non-blocking mode
    pcap_t *handle = pcap_open_live(interface, snaplen, promisc, 0, errbuf);
    if (!handle) {
        return enif_make_tuple2(env, atom_error, enif_make_string(env, errbuf, ERL_NIF_LATIN1));
    }

    if (pcap_setnonblock(handle, 1, errbuf) < 0) {
        pcap_close(handle);
        return enif_make_tuple2(env, atom_error, enif_make_string(env, errbuf, ERL_NIF_LATIN1));
    }

    int fd = pcap_get_selectable_fd(handle);
    if (fd < 0) {
        pcap_close(handle);
        return enif_make_tuple2(env, atom_error, atom_no_selectable_fd);
    }

    pcap_resource_t *res = enif_alloc_resource(pcap_resource_type, sizeof(pcap_resource_t));
    if (!res) {
        pcap_close(handle);
        return enif_make_tuple2(env, atom_error, atom_enomem);
    }

    res->handle = handle;
    res->fd = fd;
    res->closed = 0;
    enif_self(env, &res->owner);

    if (enif_monitor_process(env, res, &res->owner, &res->mon) != 0) {
        enif_release_resource(res);
        return enif_make_tuple2(env, atom_error, atom_noproc);
    }

    ERL_NIF_TERM res_term = enif_make_resource(env, res);
    enif_release_resource(res);

    return enif_make_tuple2(env, atom_ok, res_term);
}

// NIF: set_filter(resource, bpf_bytes) -> :ok | {:error, reason}
static ERL_NIF_TERM nif_set_filter(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;

    pcap_resource_t *res;
    ErlNifBinary bin;

    if (!enif_get_resource(env, argv[0], pcap_resource_type, (void **)&res)) {
        return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[1], &bin)) {
        return enif_make_badarg(env);
    }

    if (bin.size % 8 != 0) {
        return enif_make_badarg(env);
    }

    if (res->closed) {
        return enif_make_tuple2(env, atom_error, atom_closed);
    }

    struct bpf_program fp;
    fp.bf_len = bin.size / 8;
    fp.bf_insns = (struct bpf_insn *)bin.data;

    if (pcap_setfilter(res->handle, &fp) < 0) {
        return enif_make_tuple2(env, atom_error,
            enif_make_string(env, pcap_geterr(res->handle), ERL_NIF_LATIN1));
    }

    return atom_ok;
}

// NIF: recv(resource, :nowait) -> {:ok, packet} | {:select, ref} | {:error, reason}
static ERL_NIF_TERM nif_recv(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;

    pcap_resource_t *res;

    if (!enif_get_resource(env, argv[0], pcap_resource_type, (void **)&res)) {
        return enif_make_badarg(env);
    }

    if (!enif_is_identical(argv[1], atom_nowait)) {
        return enif_make_badarg(env);
    }

    if (res->closed) {
        return enif_make_tuple2(env, atom_error, atom_closed);
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    int result = pcap_next_ex(res->handle, &header, &data);

    if (result == 1) {
        ERL_NIF_TERM bin_term;
        unsigned char *bin_data = enif_make_new_binary(env, header->caplen, &bin_term);
        memcpy(bin_data, data, header->caplen);
        return enif_make_tuple2(env, atom_ok, bin_term);
    } else if (result == 0) {
        ERL_NIF_TERM ref = enif_make_ref(env);
        ERL_NIF_TERM msg = enif_make_tuple4(env, atom_peacap, argv[0], atom_select, ref);

        if (enif_select_read(env, (ErlNifEvent)(long)res->fd, res, NULL, msg, NULL) < 0) {
            return enif_make_tuple2(env, atom_error, atom_select_failed);
        }

        return enif_make_tuple2(env, atom_select, ref);
    } else if (result == PCAP_ERROR_BREAK) {
        return enif_make_tuple2(env, atom_error, atom_break);
    } else {
        return enif_make_tuple2(env, atom_error,
            enif_make_string(env, pcap_geterr(res->handle), ERL_NIF_LATIN1));
    }
}

// NIF: close(resource) -> :ok
static ERL_NIF_TERM nif_close(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;

    pcap_resource_t *res;

    if (!enif_get_resource(env, argv[0], pcap_resource_type, (void **)&res)) {
        return enif_make_badarg(env);
    }

    if (res->closed) {
        return atom_ok;
    }

    enif_demonitor_process(env, res, &res->mon);

    // ERL_NIF_SELECT_STOP triggers pcap_resource_stop which calls pcap_resource_dtor
    // The dtor handles closing the pcap handle, so we don't need to do it here
    enif_select(env, (ErlNifEvent)(long)res->fd, ERL_NIF_SELECT_STOP, res, NULL, atom_undefined);

    return atom_ok;
}

// NIF initialization
static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    (void)priv_data;
    (void)load_info;

    pcap_resource_type = enif_open_resource_type_x(
        env,
        "pcap_resource",
        &pcap_resource_init,
        ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
        NULL
    );

    if (!pcap_resource_type) {
        return -1;
    }

    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_select = enif_make_atom(env, "select");
    atom_nowait = enif_make_atom(env, "nowait");
    atom_undefined = enif_make_atom(env, "undefined");
    atom_closed = enif_make_atom(env, "closed");
    atom_peacap = enif_make_atom(env, "$peacap");
    atom_no_selectable_fd = enif_make_atom(env, "no_selectable_fd");
    atom_enomem = enif_make_atom(env, erl_errno_id(ENOMEM));
    atom_noproc = enif_make_atom(env, "noproc");
    atom_select_failed = enif_make_atom(env, "select_failed");
    atom_break = enif_make_atom(env, "break");

    return 0;
}

static ErlNifFunc nif_funcs[] = {
    {"nif_open", 3, nif_open, 0},
    {"set_filter", 2, nif_set_filter, 0},
    {"recv", 2, nif_recv, 0},
    {"close", 1, nif_close, 0}
};

ERL_NIF_INIT(Elixir.Peacap.NIF, nif_funcs, load, NULL, NULL, NULL)
