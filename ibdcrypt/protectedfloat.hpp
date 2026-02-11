#pragma once
#include "protecteduint.hpp"
#include <cstring>
#include <cstdint>
#include <utility>

template<typename T> struct FloatUintType;
template<> struct FloatUintType<float> { using type = uint32_t; };
template<> struct FloatUintType<double> { using type = uint64_t; };

template<typename FloatT>
class ProtectedFloatingPoint {
private:
	using UintT = typename FloatUintType<FloatT>::type;
	ProtectedUint<UintT> inner;

	static UintT to(FloatT f) {
		UintT u;
		std::memcpy(&u, &f, sizeof(FloatT));
		return u;
	}

	static FloatT from(UintT u) {
		FloatT f;
		std::memcpy(&f, &u, sizeof(FloatT));
		return f;
	}

public:
	ProtectedFloatingPoint(FloatT value) : inner(to(value)) {}
	
	ProtectedFloatingPoint(const ProtectedFloatingPoint& other) : inner(other.inner) {}
	
	ProtectedFloatingPoint& operator=(const ProtectedFloatingPoint& other) {
		if (this != &other) {
			inner = other.inner;
		}
		return *this;
	}
	
	ProtectedFloatingPoint(ProtectedFloatingPoint&& other) noexcept : inner(std::move(other.inner)) {}
	
	ProtectedFloatingPoint& operator=(ProtectedFloatingPoint&& other) noexcept {
		if (this != &other) {
			inner = std::move(other.inner);
		}
		return *this;
	}

	FloatT Get() const { return from(inner.Get()); }
	FloatT Decrypt() const { return from(inner.Decrypt()); }

	ProtectedFloatingPoint operator+(const ProtectedFloatingPoint& o) const { return ProtectedFloatingPoint(Decrypt() + o.Decrypt()); }
	ProtectedFloatingPoint operator+(FloatT o) const { return ProtectedFloatingPoint(Decrypt() + o); }
	ProtectedFloatingPoint operator-(const ProtectedFloatingPoint& o) const { return ProtectedFloatingPoint(Decrypt() - o.Decrypt()); }
	ProtectedFloatingPoint operator-(FloatT o) const { return ProtectedFloatingPoint(Decrypt() - o); }
	ProtectedFloatingPoint operator*(const ProtectedFloatingPoint& o) const { return ProtectedFloatingPoint(Decrypt() * o.Decrypt()); }
	ProtectedFloatingPoint operator*(FloatT o) const { return ProtectedFloatingPoint(Decrypt() * o); }
	ProtectedFloatingPoint operator/(const ProtectedFloatingPoint& o) const { return ProtectedFloatingPoint(Decrypt() / o.Decrypt()); }
	ProtectedFloatingPoint operator/(FloatT o) const { return ProtectedFloatingPoint(Decrypt() / o); }

	ProtectedFloatingPoint& operator+=(const ProtectedFloatingPoint& o) { inner = ProtectedUint<UintT>(to(Decrypt() + o.Decrypt())); return *this; }
	ProtectedFloatingPoint& operator+=(FloatT o) { inner = ProtectedUint<UintT>(to(Decrypt() + o)); return *this; }
	ProtectedFloatingPoint& operator-=(const ProtectedFloatingPoint& o) { inner = ProtectedUint<UintT>(to(Decrypt() - o.Decrypt())); return *this; }
	ProtectedFloatingPoint& operator-=(FloatT o) { inner = ProtectedUint<UintT>(to(Decrypt() - o)); return *this; }
	ProtectedFloatingPoint& operator*=(const ProtectedFloatingPoint& o) { inner = ProtectedUint<UintT>(to(Decrypt() * o.Decrypt())); return *this; }
	ProtectedFloatingPoint& operator*=(FloatT o) { inner = ProtectedUint<UintT>(to(Decrypt() * o)); return *this; }
	ProtectedFloatingPoint& operator/=(const ProtectedFloatingPoint& o) { inner = ProtectedUint<UintT>(to(Decrypt() / o.Decrypt())); return *this; }
	ProtectedFloatingPoint& operator/=(FloatT o) { inner = ProtectedUint<UintT>(to(Decrypt() / o)); return *this; }

	bool operator==(const ProtectedFloatingPoint& o) const { return Decrypt() == o.Decrypt(); }
	bool operator==(FloatT o) const { return Decrypt() == o; }
	bool operator!=(const ProtectedFloatingPoint& o) const { return Decrypt() != o.Decrypt(); }
	bool operator!=(FloatT o) const { return Decrypt() != o; }
	bool operator<(const ProtectedFloatingPoint& o) const { return Decrypt() < o.Decrypt(); }
	bool operator<(FloatT o) const { return Decrypt() < o; }
	bool operator>(const ProtectedFloatingPoint& o) const { return Decrypt() > o.Decrypt(); }
	bool operator>(FloatT o) const { return Decrypt() > o; }
	bool operator<=(const ProtectedFloatingPoint& o) const { return Decrypt() <= o.Decrypt(); }
	bool operator<=(FloatT o) const { return Decrypt() <= o; }
	bool operator>=(const ProtectedFloatingPoint& o) const { return Decrypt() >= o.Decrypt(); }
	bool operator>=(FloatT o) const { return Decrypt() >= o; }

	ProtectedFloatingPoint& operator++() { inner = ProtectedUint<UintT>(to(Decrypt() + 1)); return *this; }
	ProtectedFloatingPoint operator++(int) { ProtectedFloatingPoint temp(*this); inner = ProtectedUint<UintT>(to(Decrypt() + 1)); return temp; }
	ProtectedFloatingPoint& operator--() { inner = ProtectedUint<UintT>(to(Decrypt() - 1)); return *this; }
	ProtectedFloatingPoint operator--(int) { ProtectedFloatingPoint temp(*this); inner = ProtectedUint<UintT>(to(Decrypt() - 1)); return temp; }
};

using ProtectedFloat = ProtectedFloatingPoint<float>;
using ProtectedDouble = ProtectedFloatingPoint<double>;
