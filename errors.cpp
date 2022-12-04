#include "errors.h"
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define SYSLOG(x, y, z)
#define LOG_DEBUG 7
#define LOG_WARNING 4
#define LOG_ERROR 3
#define STRERROR(x) "system error"

static char* program_name{};
static int show_status{};
static int use_syslog{};

static int message(int, const char*);

int init_errors(char* pn, int type, const int stat)
{
	if (pn != nullptr) program_name = pn;
	if (stat == 0 || stat == 1) show_status = stat;
	return 0;
}

int status(const char* fmt, ...)
{
	static char buf[1024]{};
	va_list args{};
	va_start(args, fmt);
	int result{ vsnprintf_s(buf, sizeof buf, fmt, args) };
	va_end(args);
	return message(LOG_DEBUG, buf);
}

int warn(const char* fmt, ...)
{
	static char buf[1024]{};
	va_list args{};
	va_start(args, fmt);
	int result{ vsnprintf_s(buf, sizeof buf, fmt, args) };
	va_end(args);
	return message(LOG_WARNING, buf);
}

int panic(const char* fmt, ...)
{
	static char buf[1024];
	va_list args;
	va_start(args, fmt);
	int result{ vsnprintf_s(buf, sizeof buf, fmt, args) };
	va_end(args);
	message(LOG_ERROR, buf);
	exit(1);  // NOLINT(concurrency-mt-unsafe)
}

int message(const int priority, const char* message)
{
	char buf[1024];
	if (errno && priority < 5)
	{
		char err[1024];
		errno_t result{ strerror_s(err, errno) };
		_snprintf_s(buf, sizeof buf, "%s: %s", message, err);
		errno = 0;
	}
	else
		strcpy_s(buf, message);
	if (use_syslog)
		SYSLOG(priority, "%s", buf);
	else
		int result{ fprintf_s(stderr, "%s: %s\n", program_name, buf) };
	return 0;
}
