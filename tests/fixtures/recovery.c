/* Source-known recovery ladder. No CRT, no files, no console, no external API.
   Unsigned arithmetic deliberately defines wraparound. The analyzer receives
   only the PE; this source is an evaluation oracle, never a recovery input. */
#define DEMO __declspec(dllexport) __declspec(noinline)

DEMO unsigned scalar_ops(unsigned x, unsigned y) {
    unsigned value = x;
    value += y;
    value ^= 0x35u;
    value = (value << 2) | (value >> 3);
    return value - 7u;
}

DEMO int choose_value(int x, int y) {
    int value;
    if (x < y) value = 11;
    else value = 29;
    return value;
}

DEMO unsigned array_read_write(unsigned *values, unsigned index, unsigned value) {
    index &= 7u;
    unsigned previous = values[index];
    values[index] = previous + value;
    return values[index];
}

DEMO unsigned sum_for(const unsigned *values, unsigned count) {
    unsigned sum = 0;
    for (unsigned i = 0; i < count; ++i) sum += values[i];
    return sum;
}

DEMO unsigned sum_while(const unsigned *values, unsigned count) {
    unsigned sum = 0;
    while (count != 0) {
        --count;
        sum ^= values[count];
    }
    return sum;
}

/* A deliberately larger case: local variables, indexed loads/stores, a for
   loop, if/else, a nested while, arithmetic, bit operations and a return. */
DEMO unsigned transform_demo(unsigned *out, const unsigned *in, unsigned count, unsigned threshold) {
    unsigned checksum = 7;
    if (count > 8u) count = 8u;
    for (unsigned i = 0; i < count; ++i) {
        unsigned value = in[i] + i * 3u;
        if (value > threshold) value = (value ^ 0x55u) + 9u;
        else value = value * 5u + 1u;
        unsigned rounds = 2;
        while (rounds != 0) {
            value = (value << 1) ^ (value >> 3);
            --rounds;
        }
        out[i] = value;
        checksum = (checksum * 33u) ^ value;
    }
    return checksum;
}

volatile unsigned recovery_result;
unsigned recovery_input[8] = {0, 1, 2, 7, 31, 63, 255, 0xffffffffu};
unsigned recovery_output[8];

int entry_point(void) {
    unsigned value = scalar_ops(4, 5);
    value += (unsigned)choose_value(-3, 5);
    value += array_read_write(recovery_output, 3, 10);
    value += sum_for(recovery_input, 8);
    value += sum_while(recovery_input, 8);
    value += transform_demo(recovery_output, recovery_input, 8, 30);
    recovery_result = value;
    return (int)(value & 0x7fffffffu);
}
