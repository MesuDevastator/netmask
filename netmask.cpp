#include <cstdlib>
#include <cstring>
#include "errors.h"
#include "netmask.h"

struct uint128
{
	unsigned long long h;
	unsigned long long l;
};

static uint128 uint128_add(const uint128& x, const uint128& y, bool* carry)
{
	uint128 rv{ .l = x.l + y.l };
	if (rv.l < x.l || rv.l < y.l)
		rv.h = 1;
	else
		rv.h = 0;
	rv.h += x.h + y.h;
	if (carry)
	{
		if (rv.h < x.h || rv.h < y.h)
			*carry = true;
		else
			*carry = false;
	}
	return rv;
}

static uint128 uint128_and(const uint128& x, const uint128& y)
{
	return uint128{ x.h & y.h, x.l & y.l };
}

static uint128 uint128_or(const uint128& x, const uint128& y)
{
	return uint128{ x.h | y.h, x.l | y.l };
}

static uint128 uint128_xor(const uint128& x, const uint128& y)
{
	return uint128{ x.h ^ y.h, x.l ^ y.l };
}

static uint128 uint128_neg(const uint128& v)
{
	return uint128{ ~v.h, ~v.l };
}

static uint128 uint128_lsh(const uint128& v)
{
	return uint128{ v.h << 1 | v.l >> 63, v.l << 1 };
}

static int uint128_cmp(const uint128& x, const uint128& y)
{
	if (x.h < y.h)
		return -1;
	if (x.h > y.h)
		return 1;
	if (x.l < y.l)
		return -1;
	if (x.l > y.l)
		return 1;
	return 0;
}

static uint128 uint128_of_s6(const in6_addr* s6)
{
	return uint128{
		static_cast<unsigned long long>(s6->s6_addr[0]) << 56 |
		static_cast<unsigned long long>(s6->s6_addr[1]) << 48 |
		static_cast<unsigned long long>(s6->s6_addr[2]) << 40 |
		static_cast<unsigned long long>(s6->s6_addr[3]) << 32 |
		static_cast<unsigned long long>(s6->s6_addr[4]) << 24 |
		static_cast<unsigned long long>(s6->s6_addr[5]) << 16 |
		static_cast<unsigned long long>(s6->s6_addr[6]) << 8 |
		static_cast<unsigned long long>(s6->s6_addr[7]) << 0,
		static_cast<unsigned long long>(s6->s6_addr[8]) << 56 |
		static_cast<unsigned long long>(s6->s6_addr[9]) << 48 |
		static_cast<unsigned long long>(s6->s6_addr[10]) << 40 |
		static_cast<unsigned long long>(s6->s6_addr[11]) << 32 |
		static_cast<unsigned long long>(s6->s6_addr[12]) << 24 |
		static_cast<unsigned long long>(s6->s6_addr[13]) << 16 |
		static_cast<unsigned long long>(s6->s6_addr[14]) << 8 |
		static_cast<unsigned long long>(s6->s6_addr[15]) << 0
	};
}

static in6_addr s6_of_u128(const uint128& v)
{
	in6_addr s6{};
	s6.s6_addr[0] = 0xff & v.h >> 56;
	s6.s6_addr[1] = 0xff & v.h >> 48;
	s6.s6_addr[2] = 0xff & v.h >> 40;
	s6.s6_addr[3] = 0xff & v.h >> 32;
	s6.s6_addr[4] = 0xff & v.h >> 24;
	s6.s6_addr[5] = 0xff & v.h >> 16;
	s6.s6_addr[6] = 0xff & v.h >> 8;
	s6.s6_addr[7] = 0xff & v.h >> 0;
	s6.s6_addr[8] = 0xff & v.l >> 56;
	s6.s6_addr[9] = 0xff & v.l >> 48;
	s6.s6_addr[10] = 0xff & v.l >> 40;
	s6.s6_addr[11] = 0xff & v.l >> 32;
	s6.s6_addr[12] = 0xff & v.l >> 24;
	s6.s6_addr[13] = 0xff & v.l >> 16;
	s6.s6_addr[14] = 0xff & v.l >> 8;
	s6.s6_addr[15] = 0xff & v.l >> 0;
	return s6;
}

static uint128 uint128_lit(const unsigned long long h, const unsigned long long l)
{
	return uint128{ h, l };
}

static uint128 uint128_cidr(const unsigned char n)
{
	// ReSharper disable once CppInitializedValueIsAlwaysRewritten
	uint128 rv{};
	if (n <= 0) {
		rv.h = 0;
		rv.l = 0;
	}
	else if (n <= 64)
	{
		// ReSharper disable CppRedundantParentheses
		rv.h = ~0ULL << (64 - n);
		rv.l = 0;
	}
	else if (n <= 128)
	{
		rv.h = ~0ULL;
		rv.l = ~0ULL << (128 - n);
		// ReSharper restore CppRedundantParentheses
	}
	else
	{
		rv.h = ~0ULL;
		rv.l = ~0ULL;
	}
	return rv;
}

static int cidr(const uint128& u)
{
	int n{};
	for (unsigned long long v{ u.l }; v > 0; v <<= 1)
		n++;
	for (unsigned long long v{ u.h }; v > 0; v <<= 1)
		n++;
	return n;
}

static int check_mask(const uint128& v)
{
	uint128 m{ uint128_lit(~0ULL, ~0ULL) };
	for (int i = 0; i < 129; i++)
	{
		if (uint128_cmp(v, m) == 0)
			return 1;
		m = uint128_lsh(m);
	}
	return 0;
}

struct tag_nm
{
	uint128 net_address;
	uint128 mask;
	int domain;
	nm next;
};

nm nm_new_v4(const in_addr* s)
{
	const union
	{
		in6_addr s6;
		unsigned u32[4]{};
	} v{ .u32 = { 0, 0, htonl(0x0000ffff), s->s_addr } };
	const nm self{ nm_new_v6(&v.s6) };
	self->domain = AF_INET;
	return self;
}

nm nm_new_v6(const in6_addr* s6)
{
	return new tag_nm{ uint128_of_s6(s6), uint128_cidr(128), AF_INET6, nullptr };
}

static int subset_of(const nm a, const nm b)
{
	return uint128_cmp(a->mask, b->mask) >= 0 && uint128_cmp(b->net_address, uint128_and(a->net_address, b->mask)) == 0;
}

static int joinable_pair(const nm a, const nm b)
{
	return uint128_cmp(a->mask, b->mask) == 0 && uint128_cmp(a->net_address, b->net_address) != 0 && uint128_cmp(uint128_lit(0, 0), uint128_and(uint128_xor(a->net_address, b->net_address), uint128_lsh(a->mask))) == 0;
}

static int is_v4(const nm self)
{
	tag_nm v4_map{ uint128_lit(0, 0x0000ffff00000000ULL), uint128_cidr(96), {}, {} };
	return self->domain == AF_INET && subset_of(self, &v4_map);
}

nm nm_new_ai(const addrinfo* ai)
{
	nm self{};
	for (const addrinfo* cur{ ai }; cur; cur = cur->ai_next)
	{
		switch (cur->ai_family)
		{
		case AF_INET:
			self = nm_merge(self, nm_new_v4(&reinterpret_cast<sockaddr_in*>(cur->ai_addr)->sin_addr));
			break;
		case AF_INET6:
			self = nm_merge(self, nm_new_v6(&reinterpret_cast<sockaddr_in6*>(cur->ai_addr)->sin6_addr));
			break;
		default:
			panic("unknown ai_family %d in struct addrinfo", cur->ai_family);
		}
	}
	return self;
}

static nm parse_address(const char* str, const int flags)
{
	in6_addr s6{};
	in_addr s{};
	if (inet_pton(AF_INET6, str, &s6))
		return nm_new_v6(&s6);
	if (inet_pton(AF_INET, str, &s))
		return nm_new_v4(&s);
	if (nm_use_dns & flags)
	{
		constexpr addrinfo in{ .ai_family = AF_UNSPEC };
		addrinfo* out{};
		if (getaddrinfo(str, nullptr, &in, &out) == 0)
		{
			const nm self{ nm_new_ai(out) };
			freeaddrinfo(out);
			return self;
		}
	}
	return nullptr;
}

static int parse_mask(const nm self, const char* str, const int flags)
{
	char* p{};
	unsigned v{ strtoul(str, &p, 0) };
	in6_addr s6{};
	in_addr s{};
	if (*p == '\0')
	{
		if (is_v4(self))
		{
			if (v > 32)
				return 0;
			v += 96;
		}
		else if (v > 128)
			return 0;
		self->mask = uint128_cidr(static_cast<unsigned char>(v));
	}
	else if (inet_pton(AF_INET6, str, &s6))
	{
		self->mask = uint128_of_s6(&s6);
		if (uint128_cmp(uint128_lit(0, 0), uint128_and(uint128_lit(1ULL << 63, 1), uint128_xor(uint128_lit(0, 1), self->mask))) == 0)
			self->mask = uint128_neg(self->mask);
		self->domain = AF_INET6;
	}
	else if (self->domain == AF_INET && inet_pton(AF_INET, str, &s))
	{
		v = htonl(s.s_addr);
		if (v & 1 && ~v >> 31)
			v = ~v;
		self->mask = uint128_xor(self->mask, uint128_lit(0, ~v));
	}
	else
		return 0;
	if (!check_mask(self->mask))
		return 0;
	self->net_address = uint128_and(self->net_address, self->mask);
	return 1;
}

static int nm_widen(const nm self, const uint128& max, uint128* last)
{
	uint128 mask{}, net_address{}, broadcast{};
	int cmp{ uint128_cmp(self->net_address, max) };
	while (cmp < 0)
	{
		mask = uint128_lsh(self->mask);
		net_address = uint128_and(self->net_address, mask);
		broadcast = uint128_or(self->net_address, uint128_neg(mask));
		if (uint128_cmp(net_address, self->net_address) < 0)
			break;
		cmp = uint128_cmp(broadcast, max);
		if (cmp > 0)
			break;
		self->mask = mask;
		*last = broadcast;
		status("widen %016llx %016llx/%d", self->net_address.h, self->net_address.l, cidr(self->mask));
		if (cmp == 0)
			break;
	}
	return cmp;
}

static void nm_order(nm* low, nm* high)
{
	if (uint128_cmp((*low)->net_address, (*high)->net_address) > 0)
	{
		const nm t{ *low };
		*low = *high;
		*high = t;
	}
}

static nm nm_seq(nm first, nm last)
{
	nm_order(&first, &last);
	nm cur{ first };
	uint128 pos{ cur->net_address };
	const uint128 max{ last->net_address };
	const uint128 one{ uint128_lit(0, 1) };
	const int domain{ is_v4(first) && is_v4(last) ? AF_INET : AF_INET6 };
	delete last;
	while (nm_widen(cur, max, &pos))
	{
		cur->next = new tag_nm{ uint128_add(pos, one, nullptr), uint128_cidr(128), domain, nullptr };
		cur = cur->next;
	}
	return first;
}

nm nm_new_str(const char* str, const int flags)
{
	const char* p;
	char buf[2048]{};
	nm self;
	if ((p = strchr(str, '/')))
	{
		strncpy_s(buf, str, p - str);
		buf[p - str] = '\0';
		self = parse_address(buf, flags);
		if (!self)
			return nullptr;
		if (!parse_mask(self, p + 1, flags))
		{
			delete self;
			return nullptr;
		}
		return self;
	}
	if ((p = strchr(str, ',')))
	{
		int add;
		strncpy_s(buf, str, p - str);
		buf[p - str] = '\0';
		self = parse_address(buf, flags);
		if (!self)
			return nullptr;
		if (p[1] == '+')
			add = 1;
		else
			add = 0;
		const nm top{ parse_address(p + add + 1, flags) };
		if (!top)
		{
			delete self;
			return nullptr;
		}
		if (add)
		{
			bool carry{};
			if (is_v4(top))
				top->net_address.l &= 0xffffffffULL;
			top->net_address = uint128_add(self->net_address, top->net_address, &carry);
			if (carry)
			{
				delete self;
				delete top;
				return nullptr;
			}
		}
		return nm_seq(self, top);
	}
	if ((self = parse_address(str, flags)))
		return self;
	if ((p = strchr(str, ':')))
	{
		nm top;
		int add;
		strncpy_s(buf, str, p - str);
		buf[p - str] = '\0';
		self = parse_address(buf, flags);
		if (!self)
			return nullptr;
		if (p[1] == '+')
		{
			add = 1;
			if (p[2] == '-')
			{
				// ReSharper disable once CppInitializedValueIsAlwaysRewritten
				in_addr s{};
				char* end{};
				const unsigned long long v{ self->net_address.l + strtoull(p + 2, &end, 0) };
				if (*end == '\0')
				{
					s.s_addr = htonl(static_cast<unsigned long>(v));
					top = nm_new_v4(&s);
					if (!top)
					{
						delete self;
						return nullptr;
					}
					return nm_seq(self, top);
				}
			}
		}
		else
			add = 0;
		top = parse_address(p + add + 1, flags);
		if (!top)
		{
			delete self;
			return nullptr;
		}
		if (add)
		{
			bool carry{};
			if (is_v4(top))
				top->net_address.l &= 0xffffffffULL;
			top->net_address = uint128_add(self->net_address, top->net_address, &carry);
			if (carry)
			{
				delete self;
				delete top;
				return nullptr;
			}
		}
		return nm_seq(self, top);
	}
	return nullptr;
}

nm nm_merge(nm dst, nm src) {
	nm tmp;
	nm* pos{ &dst };
	while (src) {
		if (*pos == nullptr) {  // NOLINT(bugprone-branch-clone)
			tmp = src;
			src = *pos;
			*pos = tmp;
		}
		else if (subset_of(src, *pos)) {
			status("found %016llx %016llx/%d a subset of %016llx %016llx/%d", src->net_address.h, src->net_address.l, cidr(src->mask), (*pos)->net_address.h, (*pos)->net_address.l, cidr((*pos)->mask));
			if (src->domain != AF_INET)
				(*pos)->domain = src->domain;
			tmp = src;
			src = src->next;
			free(tmp);
		}
		else if (subset_of(*pos, src)) {
			tmp = src;
			src = *pos;
			*pos = tmp;
		}
		else if (joinable_pair(src, *pos)) {
			status("joinable %016llx %016llx/%d and %016llx %016llx/%d", src->net_address.h, src->net_address.l, cidr(src->mask), (*pos)->net_address.h, (*pos)->net_address.l, cidr((*pos)->mask));
			tmp = *pos;
			*pos = (*pos)->next;
			if (src->domain == AF_INET)
				src->domain = tmp->domain;
			free(tmp);
			src->mask = uint128_lsh(src->mask);
			src->net_address = uint128_and(src->net_address, src->mask);
			tmp = src->next;
			src->next = nullptr;
			src = nm_merge(src, tmp);
			pos = &dst;
		}
		else if (uint128_cmp(src->net_address, (*pos)->net_address) < 0) {
			tmp = src;
			src = *pos;
			*pos = tmp;
		}
		else
			pos = &(*pos)->next;
	}
	return dst;
}

void nm_walk(nm self, void (*cb)(int, const nm_address*, nm_address*)) {
	int domain;
	nm_address net_address{}, mask{};
	while (self) {
		net_address.s6 = s6_of_u128(self->net_address);
		mask.s6 = s6_of_u128(self->mask);
		if (is_v4(self)) {
			domain = AF_INET;
			net_address.s.s_addr = htonl(net_address.s6.s6_addr[12] << 24 | net_address.s6.s6_addr[13] << 16 | net_address.s6.s6_addr[14] << 8 | net_address.s6.s6_addr[15] << 0);
			mask.s.s_addr = htonl(mask.s6.s6_addr[12] << 24 | mask.s6.s6_addr[13] << 16 | mask.s6.s6_addr[14] << 8 | mask.s6.s6_addr[15] << 0);
		}
		else
			domain = AF_INET6;
		cb(domain, &net_address, &mask);
		self = self->next;
	}
}
