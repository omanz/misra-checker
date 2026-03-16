// test_violations.cpp
// Sample file with deliberate MISRA C++ 2023 violations for testing

#include <stdio.h>        // VIOLATION 30.0.1 — use <iostream>
#include <string.h>       // VIOLATION 21.2.2 — C string header
#include <stdlib.h>       // VIOLATION 18.5.2 — has exit/abort

#define MAX_SIZE 100      // VIOLATION 19.0.2 — use constexpr
#define SQUARE(x) ((x)*(x))  // VIOLATION 19.0.2 — use inline function

int global_counter = 0;

class Sensor {
public:
    virtual void read() {}
    int getId() const { return id_; }    // OK — protected accessor is fine
protected:
    void helper() {}                     // OK — protected method is fine
    int raw_value_;                      // VIOLATION 14.1.1 — protected data member
    float calibration_;                  // VIOLATION 14.1.1 — protected data member
private:
    int id_ = 0;                         // OK — private data
};

class PressureSensor : public Sensor {
public:
    void read() {}        // ADVISORY — should use 'override'
};

// VIOLATION 8.2.11 — variadic function
void log_message(const char* fmt, ...) {
    printf(fmt);          // VIOLATION 30.0.1 — C I/O
}

int divide(int a, int b) {
    if (b == 0)           // VIOLATION 9.3.1 — missing braces
        goto error;       // VIOLATION 9.6.1 — goto

    return a / b;

error:
    return -1;
}

void process_buffer(char* src, char* dst, int len) {
    memcpy(dst, src, len);           // VIOLATION 21.2.2 — use std::copy
    memset(dst + len, 0, 10);        // VIOLATION 21.2.2 — use std::fill

    char* buf = (char*)malloc(256);  // VIOLATION 8.2.2 — C-style cast
                                     // VIOLATION 21.6.1 — malloc
    if (buf == NULL)                 // VIOLATION 7.0.2 — use nullptr
        return;

    free(buf);                       // VIOLATION 21.6.1 — free
}

void risky_exit(int code) {
    if (code < 0)
        exit(1);          // VIOLATION 18.5.2 — use exception or return
}

int main() {
    int* ptr = new int(0x1aff);  // VIOLATION 21.6.1 — dynamic alloc
                                 // VIOLATION 6.5.2 — lowercase hex 'a','f'

    int octal_val = 0755;        // VIOLATION 6.5.1 — octal literal

    volatile int sensor = 42;    // ADVISORY 10.1.2 — needs justification

    register int fast = 0;       // VIOLATION 6.3.1 — deprecated keyword

    switch (octal_val) {
        case 1:
            global_counter++;    // VIOLATION 9.4.2 — no break/fallthrough
        case 2:
            global_counter--;
            break;
        default:
            break;
    }

    delete ptr;                  // VIOLATION 21.6.1 — delete

    return 0;
}
