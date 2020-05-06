#ifdef CONFIG_VDFS4_AUTHENTICATION
#ifdef CONFIG_VDFS4_DEBUG_AUTHENTICAION	/* debug,perf version */
uint8_t pubkey_n_2048[256] = {
	0xEA, 0x4A, 0x8E, 0x5C, 0xE2, 0xAB, 0xA5, 0x1D,
	0x4F, 0x1B, 0xD8, 0xBA, 0xAE, 0x1C, 0xBC, 0xCF,
	0xC8, 0xE7, 0x81, 0xD9, 0x26, 0xAC, 0x73, 0x11,
	0x5F, 0x2E, 0x7A, 0xB5, 0xED, 0xDF, 0xAB, 0x15,
	0x68, 0x51, 0xE5, 0x20, 0xDB, 0x04, 0x0E, 0xA2,
	0xE3, 0xAE, 0xF3, 0xBF, 0x16, 0x89, 0x70, 0xF3,
	0xFC, 0x09, 0x23, 0xC6, 0xB8, 0x78, 0xEC, 0x1C,
	0xD4, 0x9C, 0x65, 0x3F, 0x91, 0x7E, 0x02, 0x69,
	0x7D, 0xBF, 0x22, 0xB8, 0x3F, 0xBA, 0xD1, 0x6E,
	0xA8, 0xC5, 0x98, 0x05, 0xEA, 0x17, 0x76, 0xC8,
	0xC8, 0x4B, 0xFC, 0x4F, 0xC6, 0xC8, 0xE3, 0x5F,
	0xA5, 0x13, 0xC7, 0x5F, 0xA7, 0xCC, 0x1F, 0xA0,
	0x3D, 0x0F, 0x1D, 0xE0, 0xA6, 0xD8, 0xA0, 0x49,
	0x2D, 0x32, 0xCE, 0xED, 0x5C, 0x8A, 0xE9, 0x49,
	0x8D, 0xC6, 0xC9, 0xE3, 0x49, 0x9A, 0x2F, 0xCC,
	0x52, 0x30, 0xD6, 0xCF, 0x42, 0x79, 0xA5, 0x01,
	0x68, 0xD4, 0x69, 0x61, 0x4C, 0xA0, 0x74, 0xA3,
	0x2F, 0xA7, 0xEE, 0x0A, 0x89, 0x43, 0x7A, 0x7B,
	0xC4, 0xB9, 0xCD, 0x5F, 0x1C, 0x46, 0x77, 0x1C,
	0x9B, 0x84, 0x97, 0xEC, 0xA7, 0xB1, 0x4C, 0x18,
	0x76, 0xE0, 0xBE, 0xA3, 0xF5, 0x0B, 0x06, 0xBF,
	0x29, 0x9B, 0x18, 0xDB, 0x3E, 0x95, 0x21, 0xA4,
	0x1A, 0x9D, 0xC1, 0xCE, 0x3E, 0x23, 0xFE, 0xE5,
	0x36, 0x23, 0x0F, 0x3F, 0x4F, 0xAF, 0x23, 0x7C,
	0xCC, 0xF6, 0x1D, 0xFF, 0xF3, 0x7E, 0x5B, 0x06,
	0x19, 0x5E, 0x5A, 0xC4, 0xEF, 0xFD, 0xE6, 0xEE,
	0x36, 0x2D, 0x32, 0x4C, 0x58, 0x2D, 0xC1, 0xB7,
	0x55, 0x5B, 0xB5, 0x74, 0xAA, 0x07, 0x1A, 0x6A,
	0x65, 0xC9, 0x53, 0x41, 0x2F, 0xFC, 0xDD, 0x7B,
	0xF3, 0xEC, 0xCC, 0xAD, 0x42, 0xBA, 0x15, 0x58,
	0x6A, 0x77, 0x81, 0xED, 0x3C, 0x18, 0x97, 0x25,
	0x66, 0xD5, 0x59, 0xE5, 0x4D, 0xBE, 0xC1, 0x5B,
};
uint8_t pubkey_n_1024[128] = {
	0xC5, 0xCC, 0x86, 0x83, 0xEC, 0x23, 0xA0, 0x28,
	0x97, 0xAF, 0x0E, 0x16, 0x29, 0x1C, 0xF0, 0x42,
	0xB9, 0x5B, 0xA4, 0xAB, 0x35, 0x0F, 0x97, 0x82,
	0x65, 0xDE, 0xFE, 0xAC, 0x0B, 0x2F, 0x52, 0x90,
	0xAD, 0x8C, 0xAB, 0x8C, 0x87, 0x42, 0x7D, 0x80,
	0x07, 0xEB, 0x1B, 0xBE, 0x38, 0x5C, 0xEA, 0xF6,
	0xD6, 0x9E, 0x34, 0x22, 0xDB, 0x9F, 0xF1, 0x87,
	0x21, 0xA8, 0x4D, 0xA4, 0xA1, 0xA9, 0x86, 0x8F,
	0x2E, 0x6C, 0x1A, 0xEE, 0xC8, 0xA9, 0x9C, 0xE5,
	0x33, 0x9C, 0xA5, 0x94, 0x82, 0xE4, 0xF0, 0xC1,
	0xFC, 0x44, 0x68, 0x4B, 0xC7, 0x6C, 0x6E, 0x87,
	0x24, 0xB5, 0x47, 0x3C, 0x33, 0x95, 0x05, 0xD9,
	0xBD, 0xFB, 0x01, 0x52, 0xD0, 0xE7, 0x54, 0xDB,
	0x14, 0x9A, 0x0E, 0x05, 0xC6, 0xAC, 0x2A, 0x0A,
	0xB6, 0xBD, 0x71, 0x1D, 0x1C, 0xCE, 0x67, 0x27,
	0x8B, 0x14, 0x4F, 0x6D, 0x73, 0x26, 0xB6, 0x63,
};
#else	/* product version */
uint8_t pubkey_n_2048[256] = {
	0xEA, 0x4A, 0x8E, 0x5C, 0xE2, 0xAB, 0xA5, 0x1D,
	0x4F, 0x1B, 0xD8, 0xBA, 0xAE, 0x1C, 0xBC, 0xCF,
	0xC8, 0xE7, 0x81, 0xD9, 0x26, 0xAC, 0x73, 0x11,
	0x5F, 0x2E, 0x7A, 0xB5, 0xED, 0xDF, 0xAB, 0x15,
	0x68, 0x51, 0xE5, 0x20, 0xDB, 0x04, 0x0E, 0xA2,
	0xE3, 0xAE, 0xF3, 0xBF, 0x16, 0x89, 0x70, 0xF3,
	0xFC, 0x09, 0x23, 0xC6, 0xB8, 0x78, 0xEC, 0x1C,
	0xD4, 0x9C, 0x65, 0x3F, 0x91, 0x7E, 0x02, 0x69,
	0x7D, 0xBF, 0x22, 0xB8, 0x3F, 0xBA, 0xD1, 0x6E,
	0xA8, 0xC5, 0x98, 0x05, 0xEA, 0x17, 0x76, 0xC8,
	0xC8, 0x4B, 0xFC, 0x4F, 0xC6, 0xC8, 0xE3, 0x5F,
	0xA5, 0x13, 0xC7, 0x5F, 0xA7, 0xCC, 0x1F, 0xA0,
	0x3D, 0x0F, 0x1D, 0xE0, 0xA6, 0xD8, 0xA0, 0x49,
	0x2D, 0x32, 0xCE, 0xED, 0x5C, 0x8A, 0xE9, 0x49,
	0x8D, 0xC6, 0xC9, 0xE3, 0x49, 0x9A, 0x2F, 0xCC,
	0x52, 0x30, 0xD6, 0xCF, 0x42, 0x79, 0xA5, 0x01,
	0x68, 0xD4, 0x69, 0x61, 0x4C, 0xA0, 0x74, 0xA3,
	0x2F, 0xA7, 0xEE, 0x0A, 0x89, 0x43, 0x7A, 0x7B,
	0xC4, 0xB9, 0xCD, 0x5F, 0x1C, 0x46, 0x77, 0x1C,
	0x9B, 0x84, 0x97, 0xEC, 0xA7, 0xB1, 0x4C, 0x18,
	0x76, 0xE0, 0xBE, 0xA3, 0xF5, 0x0B, 0x06, 0xBF,
	0x29, 0x9B, 0x18, 0xDB, 0x3E, 0x95, 0x21, 0xA4,
	0x1A, 0x9D, 0xC1, 0xCE, 0x3E, 0x23, 0xFE, 0xE5,
	0x36, 0x23, 0x0F, 0x3F, 0x4F, 0xAF, 0x23, 0x7C,
	0xCC, 0xF6, 0x1D, 0xFF, 0xF3, 0x7E, 0x5B, 0x06,
	0x19, 0x5E, 0x5A, 0xC4, 0xEF, 0xFD, 0xE6, 0xEE,
	0x36, 0x2D, 0x32, 0x4C, 0x58, 0x2D, 0xC1, 0xB7,
	0x55, 0x5B, 0xB5, 0x74, 0xAA, 0x07, 0x1A, 0x6A,
	0x65, 0xC9, 0x53, 0x41, 0x2F, 0xFC, 0xDD, 0x7B,
	0xF3, 0xEC, 0xCC, 0xAD, 0x42, 0xBA, 0x15, 0x58,
	0x6A, 0x77, 0x81, 0xED, 0x3C, 0x18, 0x97, 0x25,
	0x66, 0xD5, 0x59, 0xE5, 0x4D, 0xBE, 0xC1, 0x5B,
};
uint8_t pubkey_n_1024[128] = {
	0xA3, 0x43, 0x01, 0x5C, 0x99, 0xC6, 0xA1, 0xDE,
	0xCA, 0xB7, 0xA7, 0x76, 0x21, 0x5C, 0x0E, 0x37,
	0x0B, 0x9F, 0xE9, 0x33, 0x54, 0x83, 0x91, 0x32,
	0x70, 0x03, 0xD7, 0xCF, 0x03, 0xB8, 0xC9, 0xF3,
	0x7D, 0x5B, 0x99, 0xE8, 0xEB, 0x2D, 0x35, 0x34,
	0xB4, 0x1E, 0x17, 0x34, 0x12, 0x84, 0xC5, 0x94,
	0xAF, 0x81, 0x97, 0xAC, 0x3B, 0x58, 0x32, 0xA5,
	0x9F, 0x19, 0xC9, 0x1C, 0xCF, 0x15, 0xAF, 0x56,
	0xC0, 0x26, 0xB5, 0xD3, 0x13, 0x7F, 0x96, 0x53,
	0x78, 0x4E, 0x9A, 0xAE, 0x1F, 0x3A, 0x66, 0x57,
	0x59, 0xA1, 0x00, 0x3C, 0x48, 0x01, 0xDE, 0x62,
	0x3C, 0xE5, 0x01, 0xCC, 0x98, 0x45, 0x39, 0x7E,
	0xDD, 0xE9, 0xB6, 0x47, 0x79, 0x9C, 0xF3, 0x2D,
	0xFE, 0xB8, 0xC3, 0x86, 0xC8, 0x57, 0x8E, 0x70,
	0x33, 0xA4, 0x75, 0x3D, 0xB7, 0x3D, 0xBB, 0x14,
	0xF2, 0x40, 0x73, 0x42, 0x97, 0x99, 0x6A, 0xA5,
};
#endif /* CONFIG_VDFS4_DEBUG_AUTHENTICAION */
uint8_t pubkey_e[] =  {0x01, 0x00, 0x01};
#endif /* CONFIG_VDFS4_AUTHENTICATION */
