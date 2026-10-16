/* Exported function used by application.c. No CRT and no DLL entry point. */
__declspec(dllexport) int transform_score(int value) {
    if (value < 0) return 0;
    if (value > 100) return 100;
    return value;
}
