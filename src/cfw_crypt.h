#include "cfw.h"

CFW_NS_BEGIN

class Crypt
{
public:
	void EncBuffer(uint8_t* buf, size_t len) {
		for (size_t n = 0; n < len; ++n)
			buf[n] = EncByte(buf[n]);
	}
	void DecBuffer(uint8_t* buf, size_t len) {
		for (size_t n = 0; n < len; ++n)
			buf[n] = DecByte(buf[n]);
	}
	uint8_t EncByte(uint8_t b) {
		uint8_t v = b ^ mix_ ^ key_;
		mix_ = mix_ ^ b;
		return v;
	}
	uint8_t DecByte(uint8_t b) {
		uint8_t v = b ^ mix_ ^ key_;
		mix_ = mix_ ^ v;
		return v;
	}

private:
	uint8_t mix_ = 0xd1;
	uint8_t key_ = 0x67;
};

CFW_NS_END
