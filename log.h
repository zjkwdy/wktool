#pragma once
#include <cstdio>

#define CLR_GREEN  "\x1b[32m"
#define CLR_RED    "\x1b[31m"
#define CLR_CYAN   "\x1b[36m"
#define CLR_RESET  "\x1b[0m"

#define LOG_OK(fmt, ...)       printf(CLR_GREEN  "[+] " fmt CLR_RESET "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)      printf(CLR_RED    "[-] " fmt CLR_RESET "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)     printf(CLR_CYAN   "[*] " fmt CLR_RESET "\n", ##__VA_ARGS__)
#define LOG_PROGRESS(fmt, ...) fprintf(stderr, "\r" CLR_CYAN "[*] " fmt CLR_RESET, ##__VA_ARGS__)
