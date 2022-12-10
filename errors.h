#pragma once
int init_errors(char* pn, int type, int stat);
int status(const char* fmt, ...);
int warn(const char* fmt, ...);
int panic(const char* fmt, ...);
