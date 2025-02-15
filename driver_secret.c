// Auto-generated by gen_driver_secrets.py at Wed Jun 21 13:38:28 2023

#include <stddef.h>
#include <stdint.h>

#ifdef __APPLE__
# define SECRET_GLOBAL      __attribute__((section("__DATA,__secret")))
# define SECRET_GLOBAL_RO   __attribute__((section("__TEXT,__secret")))
#else
# define SECRET_GLOBAL      __attribute__((section(".data.secret")))
# define SECRET_GLOBAL_RO   __attribute__((section(".rodata.secret")))
#endif


const uint8_t secret_certificate[512] SECRET_GLOBAL_RO = {
    0x30, 0x82, 0x01, 0xa6, 0x30, 0x82, 0x01, 0x4c, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x1c,
    0x11, 0xd2, 0xa4, 0x43, 0x56, 0x28, 0xff, 0x07, 0xb1, 0x08, 0xbf, 0x76, 0x9c, 0x0c, 0xa4, 0x3d,
    0x9a, 0x47, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x54, 0x45, 0x53, 0x54,
    0x30, 0x1e, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x36, 0x32, 0x31, 0x32, 0x30, 0x32, 0x35, 0x35, 0x31,
    0x5a, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x36, 0x31, 0x35, 0x32, 0x30, 0x32, 0x35, 0x35, 0x31, 0x5a,
    0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x04, 0x54, 0x45, 0x53,
    0x54, 0x30, 0x81, 0x8b, 0x30, 0x65, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x30,
    0x5a, 0x02, 0x01, 0x01, 0x30, 0x0c, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01, 0x02,
    0x01, 0x41, 0x30, 0x1d, 0x04, 0x01, 0x01, 0x04, 0x01, 0x0c, 0x03, 0x15, 0x00, 0xc4, 0x9d, 0x36,
    0x08, 0x86, 0xe7, 0x04, 0x93, 0x6a, 0x66, 0x78, 0xe1, 0x13, 0x9d, 0x26, 0xb7, 0x81, 0x9f, 0x7e,
    0x90, 0x04, 0x02, 0x03, 0x01, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51, 0x02, 0x01, 0x01, 0x03, 0x22, 0x00, 0x02, 0xc9,
    0x0b, 0x35, 0x13, 0xc0, 0x1e, 0x1f, 0x30, 0x5e, 0x3d, 0x0b, 0xef, 0x77, 0xb2, 0x47, 0x3a, 0x08,
    0xa2, 0xb1, 0xd1, 0x37, 0xb8, 0x81, 0x8d, 0x3c, 0xbc, 0xcb, 0x5e, 0x18, 0x6b, 0x80, 0xd8, 0xa3,
    0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x59, 0x11,
    0xae, 0xc9, 0x4e, 0x4f, 0x5d, 0x40, 0xce, 0xdd, 0x0a, 0xf4, 0x14, 0x36, 0x10, 0x2b, 0x9c, 0x46,
    0x5b, 0xa6, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x59,
    0x11, 0xae, 0xc9, 0x4e, 0x4f, 0x5d, 0x40, 0xce, 0xdd, 0x0a, 0xf4, 0x14, 0x36, 0x10, 0x2b, 0x9c,
    0x46, 0x5b, 0xa6, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30,
    0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x41, 0x04, 0x3c, 0x5d, 0x4e, 0x9b, 0x8b, 0x9f, 0x0f,
    0xb1, 0x1b, 0x60, 0x9a, 0xe8, 0x9a, 0x92, 0x9d, 0xd3, 0x9e, 0x3b, 0x30, 0xea, 0x21, 0xdd, 0x54,
    0xd1, 0x76, 0xe5, 0x72, 0xfa, 0xd8, 0x8d, 0x02, 0x21, 0x00, 0xbc, 0x43, 0x2e, 0x4e, 0x0b, 0x51,
    0xb5, 0x89, 0xd9, 0x77, 0x75, 0x16, 0xa2, 0x69, 0x10, 0xce, 0x27, 0x83, 0x60, 0xb8, 0x3d, 0x4d,
    0x7d, 0x78, 0xf2, 0xf2, 0x21, 0xc6, 0x7b, 0xd8, 0x4c, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const size_t secret_certificate_len SECRET_GLOBAL_RO = 426;
