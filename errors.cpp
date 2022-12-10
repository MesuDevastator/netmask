#include "errors.h"
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define SYSLOG(x, y, z)

enum
{
	log_debug = 7,
	log_warning = 4,
	log_error = 3
};

#define SYSERROR(x) "system error"  // NOLINT(clang-diagnostic-unused-macros)

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
	va_list args;
	va_start(args, fmt);
	[[maybe_unused]] int result{ vsnprintf_s(buf, sizeof buf, fmt, args) };
	va_end(args);
	return message(log_debug, buf);
}

int warn(const char* fmt, ...)
{
	static char buf[1024]{};
	va_list args;
	va_start(args, fmt);
	[[maybe_unused]] int result{ vsnprintf_s(buf, sizeof buf, fmt, args) };
	va_end(args);
	return message(log_warning, buf);
}

int panic(const char* fmt, ...)
{
	static char buf[1024];
	va_list args;
	va_start(args, fmt);
	[[maybe_unused]] int result{ vsnprintf_s(buf, sizeof buf, fmt, args) };
	va_end(args);
	message(log_error, buf);
	exit(1);  // NOLINT(concurrency-mt-unsafe)
}

int message(const int priority, const char* message)
{
	char buf[1024];
	if (errno && priority < 5)
	{
		char err[1024];
		[[maybe_unused]] errno_t result{ strerror_s(err, errno) };
		_snprintf_s(buf, sizeof buf, "%s: %s", message, err);
		errno = 0;
	}
	else
		strcpy_s(buf, message);
	if (use_syslog)
		SYSLOG(priority, "%s", buf);
	else
		[[maybe_unused]] int result{ fprintf_s(stderr, "%s: %s\n", program_name, buf) };
	return 0;
}
