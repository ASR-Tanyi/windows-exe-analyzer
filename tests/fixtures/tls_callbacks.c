/* Source-known loader metadata; tests link but never execute these images. */
typedef void (__stdcall *TlsCallback)(void*, unsigned, void*);
struct TlsDirectory {
    const char *start, *end;
    unsigned *index;
    TlsCallback const *callbacks;
    unsigned zero_fill, characteristics;
};
static char tls_template[1];
static unsigned tls_index;
volatile unsigned tls_result;
__declspec(noinline) void __stdcall tls_callback(void *module, unsigned reason, void *reserved) {
    (void)module; (void)reserved;
    tls_result += reason;
}
static TlsCallback const tls_callbacks[] = {tls_callback, 0};
__declspec(allocate(".rdata$T")) const struct TlsDirectory _tls_used = {
    tls_template, tls_template + 1, &tls_index, tls_callbacks, 0, 0
};
int entry_point(void) { return 0; }
