package socks5

const ver = 0x05
const authNone = 0x00
const cmdConnect = 0x01
const cmdUDPAssociate = 0x03

const atypIPv4 = 0x01
const atypDomain = 0x03
const atypIPv6 = 0x04

const repOK = 0x00
const repFail = 0x01
const repUnreachable = 0x04
const repCmdUnsupported = 0x07
