#pragma once
#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#define R1 0x2876234
#define R2 0x9283473
#define R3 0x1237884
#define R4 0x1289736
#define R5 0x4095855
#define R6 0x8723876

inline const char* GetDate() { return __DATE__; }
inline uint32_t GetProcId() { return GetCurrentProcessId(); }
inline HMODULE GetModule() { return GetModuleHandleA(nullptr); }

#define KEY KeyGen::Get()
class KeyGen {
private:
	KeyGen() = default;
	~KeyGen() = default;

public:
	KeyGen(const KeyGen&) = delete;
	KeyGen& operator=(const KeyGen&) = delete;

	static KeyGen& Get() {
		static KeyGen instance;
		return instance;
	}

private:
	template<typename T>
	static inline T Mix(uint32_t d, uint32_t p, uint32_t m, uint32_t c1, uint32_t c2, uint32_t c3) {
		uint32_t x = d ^ (p + c1);
		x ^= (x << 7) | (x >> 25);
		x += m ^ c2;
		x ^= (x >> 11);
		x += c3;

		if constexpr (sizeof(T) == 1) {
			return (T)(x ^ (x >> 8) ^ (x >> 16) ^ (x >> 24));
		}
		else if constexpr (sizeof(T) == 2) {
			return (T)(x ^ (x >> 16));
		}
		else if constexpr (sizeof(T) == 4) {
			return (T)x;
		}
		else {
			uint32_t z = Mix<uint32_t>(m, d, p, c2, c1, c3);
			return ((uint64_t)z << 32) | x;
		}
	}

public:
	template<typename T> T GenKey1() { return Mix<T>((uint32_t)GetDate(), GetProcId(), (uint32_t)GetModule(), R1, R3, 0xA5C3F1); }
	template<typename T> T GenKey2() { return Mix<T>(GetProcId(), (uint32_t)GetModule(), (uint32_t)GetDate(), R2, R5, 0x1F3D7B); }
	template<typename T> T GenKey3() { return Mix<T>((uint32_t)GetModule(), (uint32_t)GetDate(), GetProcId(), R3, R6, 0x9E3779); }
	template<typename T> T GenKey4() { return Mix<T>((uint32_t)GetDate() ^ R4, GetProcId() + R1, (uint32_t)GetModule() ^ R2, R5, R6, 0xC2B2AE); }
	template<typename T> T GenKey5() { return Mix<T>(GetProcId() * 3, (uint32_t)GetDate() + R3, (uint32_t)GetModule() ^ 0x55AA, R1, R4, 0x165667); }
	template<typename T> T GenKey6() { return Mix<T>((uint32_t)GetModule() + R6, GetProcId() ^ R2, (uint32_t)GetDate() * 7, R3, R5, 0x27D4EB); }
};

