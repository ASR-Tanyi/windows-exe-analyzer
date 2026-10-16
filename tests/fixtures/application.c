/* Source-known, no-CRT test program. Not an example of MSVC CRT startup. */
__declspec(dllimport) int transform_score(int value);
volatile int last_result;

__declspec(noinline) unsigned int checksum_bytes(const unsigned char* bytes, int count) {
    unsigned int value = 7;
    if (!bytes || count <= 0) return 0;
    for (int i = 0; i < count; ++i) {
        value = (value * 33u) ^ bytes[i];
    }
    return value;
}

__declspec(noinline) int main(void) {
    static const unsigned char payload[] = "Follow the code. Name the blocks.";
    int value = (int)(checksum_bytes(payload, (int)sizeof(payload) - 1) & 2047u);
    if (value == 0) return -1;
    int result = transform_score(value);
    last_result = result;
    return result;
}

/* Deliberately custom PE entry: keep entry separate from main. */
int entry_point(void) {
    int result = main();
    last_result = result;
    return result;
}
