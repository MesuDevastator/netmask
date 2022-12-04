#define VERSION "2.4.4"

#include <cerrno>
#include <cmath>
#include <iostream>
#include <Windows.h>
#include "errors.h"
#include "getopt.h"
#include "netmask.h"

struct address_mask
{
	unsigned net_address;
	unsigned mask;
	address_mask* next;
	address_mask* prev;
};

option long_options[] =
{
	{ "version", 0, nullptr, 'v' },
	{ "help", 0, nullptr, 'h' },
	{ "debug", 0, nullptr, 'd' },
	{ "standard", 0, nullptr, 's' },
	{ "cidr", 0, nullptr, 'c' },
	{ "cisco", 0, nullptr, 'i' },
	{ "range", 0, nullptr, 'r' },
	{ "hex", 0, nullptr, 'x' },
	{ "octal", 0, nullptr, 'o' },
	{ "binary", 0, nullptr, 'b' },
	{ "nodns", 0, nullptr, 'n' },
	{ "files", 0, nullptr, 'f' },
	// { "max", 1, nullptr, 'M' },
	// { "min", 1, nullptr, 'm' },
	{ nullptr, 0, nullptr, 0 }
};

enum output
{
	out_std,
	out_cidr,
	out_cisco,
	out_range,
	out_hex,
	out_octal,
	out_binary
};

const char* version{ "netmask, version " VERSION };
const char* v_version{ __DATE__ " " __TIME__ };
const char* usage{ "Try '%s --help' for more information." };
char* program_name{};

void display_std(const int domain, const nm_address* n, nm_address* m)
{
	char nb[INET6_ADDRSTRLEN + 1]{}, mb[INET6_ADDRSTRLEN + 1]{};
	inet_ntop(domain, n, nb, INET6_ADDRSTRLEN);
	inet_ntop(domain, m, mb, INET6_ADDRSTRLEN);
	int result{ printf_s("%15s/%-15s\n", nb, mb) };
}

static void display_cidr(const int domain, const nm_address* n, nm_address* m)
{
	char nb[INET6_ADDRSTRLEN + 1]{};
	int cidr{};
	inet_ntop(domain, n, nb, INET6_ADDRSTRLEN);
	if (domain == AF_INET)
	{
		unsigned mask{};
		for (mask = ntohl(m->s.s_addr); mask; mask <<= 1)
			cidr++;
	}
	else
	{
		for (unsigned char i{}; i < 16; i++)
			for (unsigned char c{ m->s6.s6_addr[i]}; c; c <<= 1)
				cidr++;
	}
	int result{ printf_s("%15s/%d\n", nb, cidr) };
}

static void display_cisco(const int domain, const nm_address* n, nm_address* m)
{
	char nb[INET6_ADDRSTRLEN + 1]{}, mb[INET6_ADDRSTRLEN + 1]{};
	if (domain == AF_INET6)
		for (int i{}; i < 16; i++)
			m->s6.s6_addr[i] = ~m->s6.s6_addr[i];
	else
		m->s.s_addr = ~m->s.s_addr;
	inet_ntop(domain, n, nb, INET6_ADDRSTRLEN);
	inet_ntop(domain, m, mb, INET6_ADDRSTRLEN);
	int result{ printf_s("%15s %-15s\n", nb, mb) };
}

static void range_number(char* destination, const unsigned char* source)
{
	char digits[41]{};
	int z{};
	bool overflow{};
	for (int i{}; i < 17; i++)
	{
		overflow = false;
		for (int j{ sizeof digits - 1 }; j >= 0; j--)
		{
			const char temp{ static_cast<char>(digits[j] * 256 + overflow) };
			digits[j] = static_cast<char>(temp % 10);
			overflow = temp / 10;
		}
		overflow = source[i];
		for (int j{ sizeof digits - 1 }; j >= 0; j--)
		{
			if (!overflow)
				break;
			const char sum{ static_cast<char>(digits[j] + overflow) };
			digits[j] = static_cast<char>(sum % 10);
			overflow = sum / 10;
		}
	}
	z = 1;
	for (int i{}; static_cast<unsigned long long>(i) < sizeof digits; i++)
	{
		if (z && digits[i] == 0)
			continue;
		z = 0;
		*destination++ = static_cast<char>('0' + digits[i]);
	}
	if (z)
		*destination++ = '0';
	*destination++ = '\0';
}

static void display_range(const int domain, const nm_address* n, nm_address* m)
{
	char nb[INET6_ADDRSTRLEN + 1]{}, mb[INET6_ADDRSTRLEN + 1]{}, ns[42]{};
	unsigned long long over{ 1 };
	unsigned char ra[17]{};
	if (domain == AF_INET6)
	{
		for (int i{ 15 }; i >= 0; i--)
		{
			m->s6.s6_addr[i] = ~m->s6.s6_addr[i];
			over += m->s6.s6_addr[i];
			m->s6.s6_addr[i] |= n->s6.s6_addr[i];
			ra[i + 1] = over & 0xff;
			over >>= 8;
		}
		ra[0] = static_cast<unsigned char>(over);
	}
	else
	{
		over += htonl(~m->s.s_addr);
		for (int i{ 16 }; i > 11; i--)
		{
			ra[i] = over & 0xff;
			over >>= 8;
		}
		m->s.s_addr = n->s.s_addr | ~m->s.s_addr;
	}
	range_number(ns, ra);
	inet_ntop(domain, n, nb, INET6_ADDRSTRLEN);
	inet_ntop(domain, m, mb, INET6_ADDRSTRLEN);
	int result{ printf_s("%15s-%-15s (%s)\n", nb, mb, ns) };
}

static void display_hex(const int domain, const nm_address* n, nm_address* m)
{
	if (domain == AF_INET)
		int result{ printf_s("0x%08lx/0x%08lx\n", htonl(n->s.s_addr), htonl(m->s.s_addr)) };
	else
		int result{ printf_s("0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x/0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", n->s6.s6_addr[0], n->s6.s6_addr[1], n->s6.s6_addr[2], n->s6.s6_addr[3], n->s6.s6_addr[4], n->s6.s6_addr[5], n->s6.s6_addr[6], n->s6.s6_addr[7], n->s6.s6_addr[8], n->s6.s6_addr[9], n->s6.s6_addr[10], n->s6.s6_addr[11], n->s6.s6_addr[12], n->s6.s6_addr[13], n->s6.s6_addr[14], n->s6.s6_addr[15], m->s6.s6_addr[0], m->s6.s6_addr[1], m->s6.s6_addr[2], m->s6.s6_addr[3], m->s6.s6_addr[4], m->s6.s6_addr[5], m->s6.s6_addr[6], m->s6.s6_addr[7], m->s6.s6_addr[8], m->s6.s6_addr[9], m->s6.s6_addr[10], m->s6.s6_addr[11], m->s6.s6_addr[12], m->s6.s6_addr[13], m->s6.s6_addr[14], m->s6.s6_addr[15]) };
}

static void display_octal(const int domain, const nm_address* n, nm_address* m)
{
	if (domain == AF_INET)
		int result{ printf_s("0x%10lo/0x%10lo\n", htonl(n->s.s_addr), htonl(m->s.s_addr)) };
	else
		int result{ printf_s("0x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x/0x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x%03x\n", n->s6.s6_addr[0], n->s6.s6_addr[1], n->s6.s6_addr[2], n->s6.s6_addr[3], n->s6.s6_addr[4], n->s6.s6_addr[5], n->s6.s6_addr[6], n->s6.s6_addr[7], n->s6.s6_addr[8], n->s6.s6_addr[9], n->s6.s6_addr[10], n->s6.s6_addr[11], n->s6.s6_addr[12], n->s6.s6_addr[13], n->s6.s6_addr[14], n->s6.s6_addr[15], m->s6.s6_addr[0], m->s6.s6_addr[1], m->s6.s6_addr[2], m->s6.s6_addr[3], m->s6.s6_addr[4], m->s6.s6_addr[5], m->s6.s6_addr[6], m->s6.s6_addr[7], m->s6.s6_addr[8], m->s6.s6_addr[9], m->s6.s6_addr[10], m->s6.s6_addr[11], m->s6.s6_addr[12], m->s6.s6_addr[13], m->s6.s6_addr[14], m->s6.s6_addr[15]) };
}

static void binary_string(char* destination, const unsigned char* source, const int length)
{
	for (int i{}; i < length; i++)
	{
		for (int j{ 7 }; j >= 0; j--)
			*destination++ = source[i] & 1 << j ? '1' : '0';
		*destination++ = ' ';
	}
	destination[-1] = '\0';
}

static void display_binary(const int domain, const nm_address* n, nm_address* m)
{
	char ns[144]{}, ms[144]{};
	unsigned char bits[16]{};
	if (domain == AF_INET)
	{
		unsigned long l{ htonl(n->s.s_addr) };
		bits[0] = 0xff & l >> 24;
		bits[1] = 0xff & l >> 16;
		bits[2] = 0xff & l >> 8;
		bits[3] = 0xff & l >> 0;
		binary_string(ns, bits, 4);
		l = htonl(m->s.s_addr);
		bits[0] = 0xff & l >> 24;
		bits[1] = 0xff & l >> 16;
		bits[2] = 0xff & l >> 8;
		bits[3] = 0xff & l >> 0;
		binary_string(ms, bits, 4);
	}
	else
	{
		binary_string(ns, n->s6.s6_addr, 16);
		binary_string(ms, m->s6.s6_addr, 16);
	}
	int result{ printf_s("%s / %s\n", ns, ms) };
}

void display(const nm nm, const output style)
{
	void (*display_p)(int, const nm_address*, nm_address*) {};
	switch (style)
	{
	case out_std:
		display_p = &display_std;
		break;
	case out_cidr:
		display_p = &display_cidr;
		break;
	case out_cisco:
		display_p = &display_cisco;
		break;
	case out_range:
		display_p = &display_range;
		break;
	case out_hex:
		display_p = &display_hex;
		break;
	case out_octal:
		display_p = &display_octal;
		break;
	case out_binary:
		display_p = &display_binary;
		break;
	}
	nm_walk(nm, display_p);
}

static void add_entry(nm* pnm, const char* string, const int dns)
{
	if (const nm n{ nm_new_str(string, dns) })
		*pnm = nm_merge(*pnm, n);
	else
		warn("parse error \"%s\"", string);
}

int main(const int argc, char* argv[])
{
	int opt_count{}, h{}, v{}, f{}, dns{ NM_USE_DNS }, lose{};
	output output{ out_cidr };
	program_name = argv[0];
	init_errors(program_name, 0, 0);
	// ReSharper disable once StringLiteralTypo
	while ((opt_count = getopt_long(argc, argv, "shoxdrvbincM:m:f", long_options, nullptr)) != EOF)  // NOLINT(concurrency-mt-unsafe)
		switch (opt_count)
		{
		case 'h':
			h = 1;
			break;
		case 'v':
			v++;
			break;
		case 'n':
			dns = 0;
			break;
		case 'f':
			f = 1;
			break;
		case 'd':
			init_errors(nullptr, -1, 1);
			break;
		case 's':
			output = out_std;
			break;
		case 'c':
			output = out_cidr;
			break;
		case 'i':
			output = out_cisco;
			break;
		case 'r':
			output = out_range;
			break;
		case 'x':
			output = out_hex;
			break;
		case 'o':
			output = out_octal;
			break;
		case 'b':
			output = out_binary;
			break;
		default:
			lose = 1;
			break;
		}
	if (v)
	{
		if (v == 1)
			std::cerr << version << std::endl;
		else
			std::cerr << version << ", " << v_version << std::endl;
		if (!h)
			return 0;
	}
	if (h)
	{
		std::cerr
			<< "This is netmask, an address netmask generation utility" << std::endl
			<< "Usage: " << program_name << " spec [spec ...]" << std::endl
			<< "  -h, --help\t\t\tPrint a summary of the options" << std::endl
			<< "  -v, --version\t\t\tPrint the version number" << std::endl
			<< "  -d, --debug\t\t\tPrint status/progress information" << std::endl
			<< "  -s, --standard\t\tOutput address/netmask pairs" << std::endl
			<< "  -c, --cidr\t\t\tOutput CIDR format address lists" << std::endl
			<< "  -i, --cisco\t\t\tOutput Cisco style address lists" << std::endl
			<< "  -r, --range\t\t\tOutput ip address ranges" << std::endl
			<< "  -x, --hex\t\t\tOutput address/netmask pairs in hex" << std::endl
			<< "  -o, --octal\t\t\tOutput address/netmask pairs in octal" << std::endl
			<< "  -b, --binary\t\t\tOutput address/netmask pairs in binary" << std::endl
			<< "  -n, --nodns\t\t\tDisable DNS lookups for addresses" << std::endl
			<< "  -f, --files\t\t\tTreat arguments as input files" << std::endl
			<< "Definitions:" << std::endl
			<< "  a spec can be any of:" << std::endl
			<< "    address" << std::endl
			<< "    address:address" << std::endl
			<< "    address:+address" << std::endl
			<< "    address/mask" << std::endl
			<< "  an address can be any of:" << std::endl
			<< "    N\t\tdecimal number" << std::endl
			<< "    0N\t\toctal number" << std::endl
			<< "    0xN\t\thex number" << std::endl
			<< "    N.N.N.N\tdotted quad" << std::endl
			<< "    hostname\tdns domain name" << std::endl
			<< "  a mask is the number of bits set to one from the left" << std::endl;
		return 0;
	}
	if (lose || optind == argc)
	{
		char buf[1024]{};
		_snprintf_s(buf, sizeof buf, usage, program_name);
		std::cerr << buf << std::endl;
	}
	nm nm{};
	for (; optind < argc; optind++)
	{
		if (f)
		{
			char buf[1024]{};
			FILE* fp{};
			if (strncmp(argv[optind], "-", 1) != 0)
				errno_t result{ fopen_s(&fp, argv[optind], "r") };
			else
				fp = stdin;
			if (!fp)
			{
				char err[1024]{};
				errno_t result{ strerror_s(err, errno) };
				std::cerr << "Failed to open file: " << argv[optind] << ": " << err << std::endl;
				continue;
			}
			while (fscanf_s(fp, "%1023s", buf) != EOF)
				add_entry(&nm, buf, dns);
		}
		else
			add_entry(&nm, argv[optind], dns);
	}
	display(nm, output);
	return 0;
}
