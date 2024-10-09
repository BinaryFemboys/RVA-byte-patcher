#pragma once
#include <windows.h>
#include <cstdint> // Include this header for uintptr_t definition

class binfb_t
{
    uintptr_t base;
    uintptr_t size;
    uintptr_t resource;
public:
    binfb_t(HMODULE mod);

    void patches();
};