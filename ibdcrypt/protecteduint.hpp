#pragma once
#include "keygen.hpp"

template<typename T>
inline T rotl(T x, int s) {
	const int bits = (int)(sizeof(T) * 8);
	return (x << s) | (x >> (bits - s));
}
template<typename T>
inline T rotr(T x, int s) {
	const int bits = (int)(sizeof(T) * 8);
	return (x >> s) | (x << (bits - s));
}

template<typename T> struct KT {
    static T Key1() { return KEY.GenKey1<T>(); }
    static T Key2() { return KEY.GenKey2<T>(); }
    static T Key3() { return KEY.GenKey3<T>(); }
    static T Key4() { return KEY.GenKey4<T>(); }
    static T Key5() { return KEY.GenKey5<T>(); }
    static T Key6() { return KEY.GenKey6<T>(); }
};

template<typename T>
class ProtectedUint {
private:
	T data;

	inline int GetOp() const {
		uintptr_t addr = reinterpret_cast<uintptr_t>(this);
		uint32_t mixed = (uint32_t)(addr ^ (addr >> 32)) ^ KEY.GenKey6<uint32_t>();
		mixed ^= (mixed >> 16);
		mixed ^= (mixed >> 8);
		return (int)(mixed % 10);
	}

public:
	ProtectedUint(T value) : data(0) { Encrypt(value); }
	
	ProtectedUint(const ProtectedUint& other) : data(0) {
		Encrypt(other.Decrypt());
	}
	
	ProtectedUint& operator=(const ProtectedUint& other) {
		if (this != &other) {
			Encrypt(other.Decrypt());
		}
		return *this;
	}
	
	ProtectedUint(ProtectedUint&& other) noexcept : data(0) {
		Encrypt(other.Decrypt());
	}
	
	ProtectedUint& operator=(ProtectedUint&& other) noexcept {
		if (this != &other) {
			Encrypt(other.Decrypt());
		}
		return *this;
	}

	T Get() const { return data; }
	
	T Encrypt(T x) {
		int a = GetOp();
		using Keys = KT<T>;
		
		switch (a) {
		case 0:
			x ^= Keys::Key1();
			x = rotl(x, 3);
			x ^= Keys::Key2();
			x = (x + Keys::Key3());
			x ^= Keys::Key4();
			x = rotr(x, 2);
			x ^= Keys::Key5();
			x = (x - Keys::Key6());
			x ^= Keys::Key6();
			x = ~x;
			this->data = x;
			return x;

		case 1:
			x ^= Keys::Key1();
			x = rotr(x, 5);
			x ^= Keys::Key2();
			x = (x - Keys::Key3());
			x ^= Keys::Key4();
			x = rotl(x, 4);
			x ^= Keys::Key5();
			x = (x + Keys::Key6());
			x ^= Keys::Key6();
			x = ~x;
			this->data = x;
			return x;

		case 2:
			x = (x + Keys::Key1());
			x ^= Keys::Key2();
			x = rotl(x, 7);
			x ^= Keys::Key3();
			x = rotr(x, 1);
			x ^= Keys::Key4();
			x = (x - Keys::Key5());
			x ^= Keys::Key6();
			x = rotl(x, 2);
			x ^= Keys::Key6();
			this->data = x;
			return x;

		case 3:
			x ^= Keys::Key1();
			x = (x + Keys::Key2());
			x = rotl(x, 5);
			x ^= Keys::Key3();
			x = rotr(x, 3);
			x = (x - Keys::Key4());
			x ^= Keys::Key5();
			x = rotl(x, 1);
			x ^= Keys::Key6();
			x = ~x;
			this->data = x;
			return x;

		case 4:
			x = rotr(x, 4);
			x ^= Keys::Key1();
			x = (x + Keys::Key2());
			x ^= Keys::Key3();
			x = rotl(x, 6);
			x = (x - Keys::Key4());
			x ^= Keys::Key5();
			x = rotr(x, 2);
			x ^= Keys::Key6();
			x = ~x;
			this->data = x;
			return x;

		case 5:
			x = rotr(x, 3);
			x ^= Keys::Key1();
			x = (x + Keys::Key2());
			x ^= Keys::Key3();
			x = rotl(x, 5);
			x = (x - Keys::Key4());
			x ^= Keys::Key5();
			x = rotr(x, 1);
			x ^= Keys::Key6();
			x = ~x;
			this->data = x;
			return x;

		case 6:
			x = (x + Keys::Key1());
			x ^= Keys::Key2();
			x = rotr(x, 6);
			x ^= Keys::Key3();
			x = rotl(x, 2);
			x = (x - Keys::Key4());
			x ^= Keys::Key5();
			x = rotl(x, 5);
			x ^= Keys::Key6();
			x = ~x;
			this->data = x;
			return x;

		case 7:
			x = ~x;
			x ^= Keys::Key1();
			x = (x + Keys::Key2());
			x = rotl(x, 4);
			x ^= Keys::Key3();
			x = rotr(x, 3);
			x ^= Keys::Key4();
			x = (x - Keys::Key5());
			x ^= Keys::Key6();
			x = rotl(x, 1);
			this->data = x;
			return x;

		case 8:
			x = rotr(x, 5);
			x ^= Keys::Key1();
			x = (x - Keys::Key2());
			x ^= Keys::Key3();
			x = rotl(x, 2);
			x ^= Keys::Key4();
			x = (x + Keys::Key5());
			x ^= Keys::Key6();
			x = rotr(x, 1);
			x = ~x;
			this->data = x;
			return x;

		case 9:
			x ^= Keys::Key1();
			x = rotl(x, 6);
			x ^= Keys::Key2();
			x = (x - Keys::Key3());
			x ^= Keys::Key4();
			x = rotr(x, 4);
			x = (x + Keys::Key5());
			x ^= Keys::Key6();
			x = rotl(x, 3);
			x = ~x;
			this->data = x;
			return x;

		default:
			return 0;
		}
	}
	
	T Decrypt() const {
		T x = this->data;
		int a = GetOp();
		using Keys = KT<T>;
		
		switch (a) {
		case 0:
			x = ~x;
			x ^= Keys::Key6();
			x = (x + Keys::Key6());
			x ^= Keys::Key5();
			x = rotl(x, 2);
			x ^= Keys::Key4();
			x = (x - Keys::Key3());
			x ^= Keys::Key2();
			x = rotr(x, 3);
			x ^= Keys::Key1();
			return x;

		case 1:
			x = ~x;
			x ^= Keys::Key6();
			x = (x - Keys::Key6());
			x ^= Keys::Key5();
			x = rotr(x, 4);
			x ^= Keys::Key4();
			x = (x + Keys::Key3());
			x ^= Keys::Key2();
			x = rotl(x, 5);
			x ^= Keys::Key1();
			return x;

		case 2:
			x ^= Keys::Key6();
			x = rotr(x, 2);
			x ^= Keys::Key6();
			x = (x + Keys::Key5());
			x ^= Keys::Key4();
			x = rotl(x, 1);
			x ^= Keys::Key3();
			x = rotr(x, 7);
			x ^= Keys::Key2();
			x = (x - Keys::Key1());
			return x;

		case 3:
			x = ~x;
			x ^= Keys::Key6();
			x = rotr(x, 1);
			x ^= Keys::Key5();
			x = (x + Keys::Key4());
			x = rotl(x, 3);
			x ^= Keys::Key3();
			x = rotr(x, 5);
			x = (x - Keys::Key2());
			x ^= Keys::Key1();
			return x;

		case 4:
			x = ~x;
			x ^= Keys::Key6();
			x = rotl(x, 2);
			x ^= Keys::Key5();
			x = (x + Keys::Key4());
			x = rotr(x, 6);
			x ^= Keys::Key3();
			x = (x - Keys::Key2());
			x ^= Keys::Key1();
			x = rotl(x, 4);
			return x;

		case 5:
			x = ~x;
			x ^= Keys::Key6();
			x = rotl(x, 1);
			x ^= Keys::Key5();
			x = (x + Keys::Key4());
			x = rotr(x, 5);
			x ^= Keys::Key3();
			x = (x - Keys::Key2());
			x ^= Keys::Key1();
			x = rotl(x, 3);
			return x;

		case 6:
			x = ~x;
			x ^= Keys::Key6();
			x = rotr(x, 5);
			x ^= Keys::Key5();
			x = (x + Keys::Key4());
			x = rotr(x, 2);
			x ^= Keys::Key3();
			x = rotl(x, 6);
			x ^= Keys::Key2();
			x = (x - Keys::Key1());
			return x;

		case 7:
			x = rotr(x, 1);
			x ^= Keys::Key6();
			x = (x + Keys::Key5());
			x ^= Keys::Key4();
			x = rotl(x, 3);
			x ^= Keys::Key3();
			x = rotr(x, 4);
			x = (x - Keys::Key2());
			x ^= Keys::Key1();
			x = ~x;
			return x;

		case 8:
			x = ~x;
			x = rotl(x, 1);
			x ^= Keys::Key6();
			x = (x - Keys::Key5());
			x ^= Keys::Key4();
			x = rotr(x, 2);
			x ^= Keys::Key3();
			x = (x + Keys::Key2());
			x ^= Keys::Key1();
			x = rotl(x, 5);
			return x;

	case 9:
		x = ~x;
		x = rotr(x, 3);
		x ^= Keys::Key6();
		x = (x - Keys::Key5());
		x = rotl(x, 4);
		x ^= Keys::Key4();
		x = (x + Keys::Key3());
		x ^= Keys::Key2();
		x = rotr(x, 6);
		x ^= Keys::Key1();
		return x;

		default:
			return 0;
		}
	}

	ProtectedUint operator+(const ProtectedUint& o) const { return ProtectedUint(Decrypt() + o.Decrypt()); }
	ProtectedUint operator+(T o) const { return ProtectedUint(Decrypt() + o); }
	ProtectedUint operator-(const ProtectedUint& o) const { return ProtectedUint(Decrypt() - o.Decrypt()); }
	ProtectedUint operator-(T o) const { return ProtectedUint(Decrypt() - o); }
	ProtectedUint operator*(const ProtectedUint& o) const { return ProtectedUint(Decrypt() * o.Decrypt()); }
	ProtectedUint operator*(T o) const { return ProtectedUint(Decrypt() * o); }
	ProtectedUint operator/(const ProtectedUint& o) const { return ProtectedUint(Decrypt() / o.Decrypt()); }
	ProtectedUint operator/(T o) const { return ProtectedUint(Decrypt() / o); }
	ProtectedUint operator%(const ProtectedUint& o) const { return ProtectedUint(Decrypt() % o.Decrypt()); }
	ProtectedUint operator%(T o) const { return ProtectedUint(Decrypt() % o); }

	ProtectedUint& operator+=(const ProtectedUint& o) { Encrypt(Decrypt() + o.Decrypt()); return *this; }
	ProtectedUint& operator+=(T o) { Encrypt(Decrypt() + o); return *this; }
	ProtectedUint& operator-=(const ProtectedUint& o) { Encrypt(Decrypt() - o.Decrypt()); return *this; }
	ProtectedUint& operator-=(T o) { Encrypt(Decrypt() - o); return *this; }
	ProtectedUint& operator*=(const ProtectedUint& o) { Encrypt(Decrypt() * o.Decrypt()); return *this; }
	ProtectedUint& operator*=(T o) { Encrypt(Decrypt() * o); return *this; }
	ProtectedUint& operator/=(const ProtectedUint& o) { Encrypt(Decrypt() / o.Decrypt()); return *this; }
	ProtectedUint& operator/=(T o) { Encrypt(Decrypt() / o); return *this; }
	ProtectedUint& operator%=(const ProtectedUint& o) { Encrypt(Decrypt() % o.Decrypt()); return *this; }
	ProtectedUint& operator%=(T o) { Encrypt(Decrypt() % o); return *this; }

	bool operator==(const ProtectedUint& o) const { return Decrypt() == o.Decrypt(); }
	bool operator==(T o) const { return Decrypt() == o; }
	bool operator!=(const ProtectedUint& o) const { return Decrypt() != o.Decrypt(); }
	bool operator!=(T o) const { return Decrypt() != o; }
	bool operator<(const ProtectedUint& o) const { return Decrypt() < o.Decrypt(); }
	bool operator<(T o) const { return Decrypt() < o; }
	bool operator>(const ProtectedUint& o) const { return Decrypt() > o.Decrypt(); }
	bool operator>(T o) const { return Decrypt() > o; }
	bool operator<=(const ProtectedUint& o) const { return Decrypt() <= o.Decrypt(); }
	bool operator<=(T o) const { return Decrypt() <= o; }
	bool operator>=(const ProtectedUint& o) const { return Decrypt() >= o.Decrypt(); }
	bool operator>=(T o) const { return Decrypt() >= o; }

	ProtectedUint operator&(const ProtectedUint& o) const { return ProtectedUint(Decrypt() & o.Decrypt()); }
	ProtectedUint operator&(T o) const { return ProtectedUint(Decrypt() & o); }
	ProtectedUint operator|(const ProtectedUint& o) const { return ProtectedUint(Decrypt() | o.Decrypt()); }
	ProtectedUint operator|(T o) const { return ProtectedUint(Decrypt() | o); }
	ProtectedUint operator^(const ProtectedUint& o) const { return ProtectedUint(Decrypt() ^ o.Decrypt()); }
	ProtectedUint operator^(T o) const { return ProtectedUint(Decrypt() ^ o); }
	ProtectedUint operator~() const { return ProtectedUint(~Decrypt()); }
	ProtectedUint operator<<(int shift) const { return ProtectedUint(Decrypt() << shift); }
	ProtectedUint operator>>(int shift) const { return ProtectedUint(Decrypt() >> shift); }

	ProtectedUint& operator&=(const ProtectedUint& o) { Encrypt(Decrypt() & o.Decrypt()); return *this; }
	ProtectedUint& operator&=(T o) { Encrypt(Decrypt() & o); return *this; }
	ProtectedUint& operator|=(const ProtectedUint& o) { Encrypt(Decrypt() | o.Decrypt()); return *this; }
	ProtectedUint& operator|=(T o) { Encrypt(Decrypt() | o); return *this; }
	ProtectedUint& operator^=(const ProtectedUint& o) { Encrypt(Decrypt() ^ o.Decrypt()); return *this; }
	ProtectedUint& operator^=(T o) { Encrypt(Decrypt() ^ o); return *this; }
	ProtectedUint& operator<<=(int shift) { Encrypt(Decrypt() << shift); return *this; }
	ProtectedUint& operator>>=(int shift) { Encrypt(Decrypt() >> shift); return *this; }

	ProtectedUint& operator++() { Encrypt(Decrypt() + 1); return *this; }
	ProtectedUint operator++(int) { ProtectedUint temp(*this); Encrypt(Decrypt() + 1); return temp; }
	ProtectedUint& operator--() { Encrypt(Decrypt() - 1); return *this; }
	ProtectedUint operator--(int) { ProtectedUint temp(*this); Encrypt(Decrypt() - 1); return temp; }
};

using ProtectedUint8 = ProtectedUint<uint8_t>;
using ProtectedUint16 = ProtectedUint<uint16_t>;
using ProtectedUint32 = ProtectedUint<uint32_t>;
using ProtectedUint64 = ProtectedUint<uint64_t>;
