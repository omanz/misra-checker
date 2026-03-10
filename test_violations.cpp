// test_violations.cpp
// Sample file with deliberate MISRA C++ 2023 violations for testing

#include <stdio.h>        // VIOLATION 13.1.1 — use <iostream>
#include <string.h>       // VIOLATION 13.2.1 — C string header
#include <stdlib.h>       // VIOLATION 15.3.1 — has exit/abort

#define MAX_SIZE 100      // VIOLATION 19.2.1 — use constexpr
#define SQUARE(x) ((x)*(x))  // VIOLATION 19.2.1 — use inline function

int global_counter = 0;

class Sensor {
public:
    virtual void read() {}
};

class PressureSensor : public Sensor {
public:
    void read() {}        // ADVISORY — should use 'override'
};

// VIOLATION 8.4.2 — variadic function
void log_message(const char* fmt, ...) {
    printf(fmt);          // VIOLATION 13.1.1 — C I/O
}

int divide(int a, int b) {
    if (b == 0)           // VIOLATION 9.3.1 — missing braces
        goto error;       // VIOLATION 8.1.1 — goto

    return a / b;

error:
    return -1;
}

void process_buffer(char* src, char* dst, int len) {
    memcpy(dst, src, len);           // VIOLATION 13.2.1 — use std::copy
    memset(dst + len, 0, 10);        // VIOLATION 13.2.1 — use std::fill

    char* buf = (char*)malloc(256);  // VIOLATION 7.2.1 — C-style cast
                                     // VIOLATION 11.5.1 — malloc
    if (buf == NULL)                 // VIOLATION 7.0.2 — use nullptr
        return;

    free(buf);                       // VIOLATION 11.5.1 — free
}

void risky_exit(int code) {
    if (code < 0)
        exit(1);          // VIOLATION 15.3.1 — use exception or return
}

int main() {
    int* ptr = new int(0x1aff);  // VIOLATION 11.5.1 — dynamic alloc
                                 // VIOLATION 6.5.2 — lowercase hex 'a','f'

    int octal_val = 0755;        // VIOLATION 6.5.1 — octal literal

    volatile int sensor = 42;    // ADVISORY 6.2.1 — needs justification

    register int fast = 0;       // VIOLATION 6.3.1 — deprecated keyword

    switch (octal_val) {
        case 1:
            global_counter++;    // VIOLATION 9.4.1 — no break/fallthrough
        case 2:
            global_counter--;
            break;
        default:
            break;
    }

    delete ptr;                  // VIOLATION 11.5.1 — delete

    return 0;
}
