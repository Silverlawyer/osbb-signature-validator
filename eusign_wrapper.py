import ctypes
import os

LIB_PATH = "/opt/iit/eu/sw/euscp.so"

_lib = None
_initialized = False


class EuSignError(Exception):
    pass


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", ctypes.c_ushort),
        ("wMonth", ctypes.c_ushort),
        ("wDayOfWeek", ctypes.c_ushort),
        ("wDay", ctypes.c_ushort),
        ("wHour", ctypes.c_ushort),
        ("wMinute", ctypes.c_ushort),
        ("wSecond", ctypes.c_ushort),
        ("wMilliseconds", ctypes.c_ushort),
    ]


class EU_SIGN_INFO(ctypes.Structure):
    _fields_ = [
        ("bFilled", ctypes.c_int),
        ("pszIssuer", ctypes.c_char_p),
        ("pszIssuerCN", ctypes.c_char_p),
        ("pszSerial", ctypes.c_char_p),
        ("pszSubject", ctypes.c_char_p),
        ("pszSubjCN", ctypes.c_char_p),
        ("pszSubjOrg", ctypes.c_char_p),
        ("pszSubjOrgUnit", ctypes.c_char_p),
        ("pszSubjTitle", ctypes.c_char_p),
        ("pszSubjState", ctypes.c_char_p),
        ("pszSubjLocality", ctypes.c_char_p),
        ("pszSubjFullName", ctypes.c_char_p),
        ("pszSubjAddress", ctypes.c_char_p),
        ("pszSubjPhone", ctypes.c_char_p),
        ("pszSubjEMail", ctypes.c_char_p),
        ("pszSubjDNS", ctypes.c_char_p),
        ("pszSubjEDRPOUCode", ctypes.c_char_p),
        ("pszSubjDRFOCode", ctypes.c_char_p),
        ("bTimeAvail", ctypes.c_int),
        ("bTimeStamp", ctypes.c_int),
        ("Time", SYSTEMTIME),
    ]


def _get_lib():
    global _lib
    if _lib is None:
        lib = ctypes.CDLL(LIB_PATH)
        lib.EUVerifyDataInternal.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(EU_SIGN_INFO),
        ]
        lib.EUVerifyDataInternal.restype = ctypes.c_ulong
        lib.EUFreeSignInfo.argtypes = [ctypes.POINTER(EU_SIGN_INFO)]
        lib.EUFreeSignInfo.restype = None
        lib.EUFreeMemory.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
        lib.EUFreeMemory.restype = None
        _lib = lib
    return _lib


def initialize():
    global _initialized
    lib = _get_lib()
    lib.EUInitialize.restype = ctypes.c_long
    lib.EUInitialize.argtypes = [ctypes.c_void_p]
    res = lib.EUInitialize(None)
    if res != 0:
        raise EuSignError('EUInitialize failed, code=%d' % res)
    _initialized = True
    return None


def is_initialized():
    lib = _get_lib()
    lib.EUIsInitialized.restype = ctypes.c_int
    return bool(lib.EUIsInitialized())


def finalize():
    lib = _get_lib()
    lib.EUFinalize.restype = ctypes.c_long
    lib.EUFinalize()
    global _initialized
    _initialized = False


def verify_internal(signed_data):
    if not is_initialized():
        raise EuSignError('EUSignCP is not initialized')
    lib = _get_lib()
    if isinstance(signed_data, str):
        signed_data_bytes = signed_data.encode('utf-8')
    else:
        signed_data_bytes = signed_data
    sign_info = EU_SIGN_INFO()
    ctypes.memset(ctypes.byref(sign_info), 0, ctypes.sizeof(sign_info))
    ppb_data = ctypes.POINTER(ctypes.c_ubyte)()
    pdw_data_length = ctypes.c_ulong(0)
    res = lib.EUVerifyDataInternal(signed_data_bytes, None, 0, ctypes.byref(ppb_data), ctypes.byref(pdw_data_length), ctypes.byref(sign_info))
    try:
        if res != 0:
            raise EuSignError('EUVerifyDataInternal failed, code=%d' % res)
        full_name = sign_info.pszSubjFullName or sign_info.pszSubjCN or sign_info.pszSubject
        if isinstance(full_name, bytes):
            full_name = full_name.decode('utf-8', errors='replace')
        drfo_code = sign_info.pszSubjDRFOCode
        if isinstance(drfo_code, bytes):
            drfo_code = drfo_code.decode('utf-8', errors='replace')
        edrpou_code = sign_info.pszSubjEDRPOUCode
        if isinstance(edrpou_code, bytes):
            edrpou_code = edrpou_code.decode('utf-8', errors='replace')
        data_bytes = None
        if ppb_data and pdw_data_length.value:
            data_bytes = ctypes.string_at(ppb_data, pdw_data_length.value)
        return {'full_name': full_name, 'drfo_code': drfo_code, 'edrpou_code': edrpou_code, 'data': data_bytes}
    finally:
        lib.EUFreeSignInfo(ctypes.byref(sign_info))
        if ppb_data:
            lib.EUFreeMemory(ppb_data)
