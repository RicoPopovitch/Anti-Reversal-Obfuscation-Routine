#pragma once
#include "protecteduint.hpp"
#include <cstring>
#include <cstdint>
#include <utility>

template<typename T> struct UnsignedType;
template<> struct UnsignedType<int8_t> { using type = uint8_t; };
template<> struct UnsignedType<int16_t> { using type = uint16_t; };
template<> struct UnsignedType<int32_t> { using type = uint32_t; };
template<> struct UnsignedType<int64_t> { using type = uint64_t; };

template<typename SignedT>
class ProtectedInt {
private:
	using UnsignedT = typename UnsignedType<SignedT>::type;
	ProtectedUint<UnsignedT> inner;

	static UnsignedT to(SignedT i) {
		UnsignedT u;
		std::memcpy(&u, &i, sizeof(SignedT));
		return u;
	}

	static SignedT from(UnsignedT u) {
		SignedT i;
		std::memcpy(&i, &u, sizeof(SignedT));
		return i;
	}

public:
	ProtectedInt(SignedT value) : inner(to(value)) {}
	
	ProtectedInt(const ProtectedInt& other) : inner(other.inner) {}
	
	ProtectedInt& operator=(const ProtectedInt& other) {
		if (this != &other) {
			inner = other.inner;
		}
		return *this;
	}
	
	ProtectedInt(ProtectedInt&& other) noexcept : inner(std::move(other.inner)) {}
	
	ProtectedInt& operator=(ProtectedInt&& other) noexcept {
		if (this != &other) {
			inner = std::move(other.inner);
		}
		return *this;
	}

	SignedT Get() const { return from(inner.Get()); }
	SignedT Decrypt() const { return from(inner.Decrypt()); }

	ProtectedInt operator+(const ProtectedInt& o) const { return ProtectedInt(Decrypt() + o.Decrypt()); }
	ProtectedInt operator+(SignedT o) const { return ProtectedInt(Decrypt() + o); }
	ProtectedInt operator-(const ProtectedInt& o) const { return ProtectedInt(Decrypt() - o.Decrypt()); }
	ProtectedInt operator-(SignedT o) const { return ProtectedInt(Decrypt() - o); }
	ProtectedInt operator*(const ProtectedInt& o) const { return ProtectedInt(Decrypt() * o.Decrypt()); }
	ProtectedInt operator*(SignedT o) const { return ProtectedInt(Decrypt() * o); }
	ProtectedInt operator/(const ProtectedInt& o) const { return ProtectedInt(Decrypt() / o.Decrypt()); }
	ProtectedInt operator/(SignedT o) const { return ProtectedInt(Decrypt() / o); }
	ProtectedInt operator%(const ProtectedInt& o) const { return ProtectedInt(Decrypt() % o.Decrypt()); }
	ProtectedInt operator%(SignedT o) const { return ProtectedInt(Decrypt() % o); }

	ProtectedInt& operator+=(const ProtectedInt& o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() + o.Decrypt())); return *this; }
	ProtectedInt& operator+=(SignedT o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() + o)); return *this; }
	ProtectedInt& operator-=(const ProtectedInt& o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() - o.Decrypt())); return *this; }
	ProtectedInt& operator-=(SignedT o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() - o)); return *this; }
	ProtectedInt& operator*=(const ProtectedInt& o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() * o.Decrypt())); return *this; }
	ProtectedInt& operator*=(SignedT o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() * o)); return *this; }
	ProtectedInt& operator/=(const ProtectedInt& o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() / o.Decrypt())); return *this; }
	ProtectedInt& operator/=(SignedT o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() / o)); return *this; }
	ProtectedInt& operator%=(const ProtectedInt& o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() % o.Decrypt())); return *this; }
	ProtectedInt& operator%=(SignedT o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() % o)); return *this; }

	bool operator==(const ProtectedInt& o) const { return Decrypt() == o.Decrypt(); }
	bool operator==(SignedT o) const { return Decrypt() == o; }
	bool operator!=(const ProtectedInt& o) const { return Decrypt() != o.Decrypt(); }
	bool operator!=(SignedT o) const { return Decrypt() != o; }
	bool operator<(const ProtectedInt& o) const { return Decrypt() < o.Decrypt(); }
	bool operator<(SignedT o) const { return Decrypt() < o; }
	bool operator>(const ProtectedInt& o) const { return Decrypt() > o.Decrypt(); }
	bool operator>(SignedT o) const { return Decrypt() > o; }
	bool operator<=(const ProtectedInt& o) const { return Decrypt() <= o.Decrypt(); }
	bool operator<=(SignedT o) const { return Decrypt() <= o; }
	bool operator>=(const ProtectedInt& o) const { return Decrypt() >= o.Decrypt(); }
	bool operator>=(SignedT o) const { return Decrypt() >= o; }

	ProtectedInt operator&(const ProtectedInt& o) const { return ProtectedInt(Decrypt() & o.Decrypt()); }
	ProtectedInt operator&(SignedT o) const { return ProtectedInt(Decrypt() & o); }
	ProtectedInt operator|(const ProtectedInt& o) const { return ProtectedInt(Decrypt() | o.Decrypt()); }
	ProtectedInt operator|(SignedT o) const { return ProtectedInt(Decrypt() | o); }
	ProtectedInt operator^(const ProtectedInt& o) const { return ProtectedInt(Decrypt() ^ o.Decrypt()); }
	ProtectedInt operator^(SignedT o) const { return ProtectedInt(Decrypt() ^ o); }
	ProtectedInt operator~() const { return ProtectedInt(~Decrypt()); }
	ProtectedInt operator<<(int shift) const { return ProtectedInt(Decrypt() << shift); }
	ProtectedInt operator>>(int shift) const { return ProtectedInt(Decrypt() >> shift); }

	ProtectedInt& operator&=(const ProtectedInt& o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() & o.Decrypt())); return *this; }
	ProtectedInt& operator&=(SignedT o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() & o)); return *this; }
	ProtectedInt& operator|=(const ProtectedInt& o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() | o.Decrypt())); return *this; }
	ProtectedInt& operator|=(SignedT o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() | o)); return *this; }
	ProtectedInt& operator^=(const ProtectedInt& o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() ^ o.Decrypt())); return *this; }
	ProtectedInt& operator^=(SignedT o) { inner = ProtectedUint<UnsignedT>(to(Decrypt() ^ o)); return *this; }
	ProtectedInt& operator<<=(int shift) { inner = ProtectedUint<UnsignedT>(to(Decrypt() << shift)); return *this; }
	ProtectedInt& operator>>=(int shift) { inner = ProtectedUint<UnsignedT>(to(Decrypt() >> shift)); return *this; }

	ProtectedInt& operator++() { inner = ProtectedUint<UnsignedT>(to(Decrypt() + 1)); return *this; }
	ProtectedInt operator++(int) { ProtectedInt temp(*this); inner = ProtectedUint<UnsignedT>(to(Decrypt() + 1)); return temp; }
	ProtectedInt& operator--() { inner = ProtectedUint<UnsignedT>(to(Decrypt() - 1)); return *this; }
	ProtectedInt operator--(int) { ProtectedInt temp(*this); inner = ProtectedUint<UnsignedT>(to(Decrypt() - 1)); return temp; }
};

using ProtectedInt8 = ProtectedInt<int8_t>;
using ProtectedInt16 = ProtectedInt<int16_t>;
using ProtectedInt32 = ProtectedInt<int32_t>;
using ProtectedInt64 = ProtectedInt<int64_t>;
