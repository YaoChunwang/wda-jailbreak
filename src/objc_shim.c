typedef void* id;
static void start_server_direct(void);
static int g_srv = 0;
extern void* dlopen(const char*, int);
extern char* dlerror(void);
extern const char* _dyld_get_image_name(unsigned int);
extern id objc_retain(id);
extern void objc_release(id);
extern id objc_msgSend(id, void*, ...);
extern id sel_registerName(const char*);
extern void objc_exception_throw(id);
extern void NSSetUncaughtExceptionHandler(void*);
extern char* getenv(const char*);

static long raw3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("mov x16, %1\n mov x0, %2\n mov x1, %3\n mov x2, %4\n svc #0x80\n mov %0, x0"
                     : "=r"(r) : "r"(n), "r"(a), "r"(b), "r"(c) : "x0","x1","x2","x16","memory");
    return r;
}
static int raw_len(const char* s) { int i = 0; while (s[i]) i++; return i; }

static void raw_write_file(const char* path, const char* a, const char* b) {
    long fd = raw3(5, (long)path, 0x601, 0644);
    if (fd < 0) return;
    if (a) raw3(4, fd, (long)a, raw_len(a));
    if (b) raw3(4, fd, (long)b, raw_len(b));
    raw3(4, fd, (long)"\n", 1);
    raw3(6, fd, 0, 0);
}

static void net_report(const char* a, const char* b) {
    unsigned char addr[16] = {16, 2, 0x22, 0xC2, 192, 168, 191, 107, 0,0,0,0,0,0,0,0};
    long fd = raw3(97, 2, 1, 0); /* socket(AF_INET, SOCK_STREAM, 0) */
    if (fd < 0) return;
    long cr = raw3(98, fd, (long)addr, 16); /* connect */
    if (cr < 0) { raw3(6, fd, 0, 0); return; }
    if (a) raw3(4, fd, (long)a, raw_len(a));
    if (b) raw3(4, fd, (long)b, raw_len(b));
    raw3(4, fd, (long)"\n", 1);
    raw3(6, fd, 0, 0);
}

static void marker(const char* tag) {
    raw_write_file("/var/mobile/shim_loaded.txt", tag, 0);
    raw_write_file("/tmp/shim_loaded.txt", tag, 0);
    raw_write_file("/var/tmp/shim_loaded.txt", tag, 0);
    char* home = getenv("HOME");
    if (home) {
        char p[512]; int i = 0;
        while (home[i]) { p[i] = home[i]; i++; }
        const char* suf = "/shim_loaded.txt"; int j = 0;
        while (suf[j]) { p[i++] = suf[j++]; }
        p[i] = 0;
        raw_write_file(p, tag, 0);
    }
    net_report("MARKER:", tag);
}


/* ---- runtime fix: add -copyWithZone: to XCTestDriver ---- */
extern void* objc_getClass(const char*);
extern int class_addMethod(void*, void*, void*, const char*);

static id copyWithZone_impl(id self, void* sel, void* zone) { return objc_retain(self); }
extern void* object_getClass(void*);
static unsigned long long enum_empty_impl(id self, void* sel, void* st, void* buf, unsigned long long len) { return 0; }
static void encode_noop_impl(id self, void* sel, id coder) { }
static char supports_yes_impl(void* self, void* sel) { return 1; }

extern void* objc_copyClassList(unsigned int*);
extern const char* class_getName(void*);
extern int class_respondsToSelector(void*, void*);
extern void free(void*);

static void fix_xctestdriver(void) {
    net_report("STATE:", "clean_no_classpatch");
}

static void exc_handler(id exc) {
    id name = ((id(*)(id, void*))objc_msgSend)(exc, sel_registerName("name"));
    id reason = ((id(*)(id, void*))objc_msgSend)(exc, sel_registerName("reason"));
    const char* n = ((const char*(*)(id, void*))objc_msgSend)(name, sel_registerName("UTF8String"));
    const char* r = ((const char*(*)(id, void*))objc_msgSend)(reason, sel_registerName("UTF8String"));
    const char* nn = n ? n : "(null-name)";
    const char* rr = r ? r : "(null-reason)";
    raw_write_file("/var/mobile/wda_exc.txt", nn, rr);
    raw_write_file("/tmp/wda_exc.txt", nn, rr);
    char* home = getenv("HOME");
    if (home) {
        char p[512]; int i = 0;
        while (home[i]) { p[i] = home[i]; i++; }
        const char* suf = "/wda_exc.txt"; int j = 0;
        while (suf[j]) { p[i++] = suf[j++]; }
        p[i] = 0;
        raw_write_file(p, nn, rr);
    }
    net_report("EXC:", rr);
}

/* ---- liveness telemetry (no interpose) ---- */
extern int pthread_create(void*, const void*, void*, void*);
extern int pthread_detach(void*);
extern unsigned int sleep(unsigned int);
extern int atexit(void (*)(void));
extern unsigned int _dyld_image_count(void);
extern const char* _dyld_get_image_name(unsigned int);

static int contains(const char* s, const char* sub) {
    for (; *s; s++) {
        const char* a = s; const char* b = sub;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return 1;
    }
    return 0;
}

/* ---- signal + heartbeat telemetry ---- */
extern void* signal(int, void*);
typedef struct { const char* fname; void* fbase; const char* sname; void* saddr; } my_dlinfo;
extern int dladdr(const void*, my_dlinfo*);

static void hexout(char* buf, int* k, unsigned long v) {
    char t[20]; int n = 0;
    if (v == 0) { buf[(*k)++] = '0'; return; }
    while (v) { int d = v % 16; t[n++] = d < 10 ? '0' + d : 'a' + (d - 10); v /= 16; }
    while (n > 0) buf[(*k)++] = t[--n];
}

static int g_sigcount = 0;
static void sig_handler(int s, void* info, void* uctx) {
    g_sigcount++;
    unsigned long pc = 0, lr = 0, sp = 0;
    char buf[240]; int k = 0; const char* p = "FAULT:"; while (*p) buf[k++] = *p++;
    if (s >= 10) buf[k++] = '0' + (s / 10);
    buf[k++] = '0' + (s % 10);
    buf[k++] = ' ';
    if (uctx) {
        unsigned long* u = (unsigned long*)uctx;
        void* mc = (void*)u[6];
        if (mc) {
            unsigned long* m = (unsigned long*)mc;
            pc = m[34], lr = m[32], sp = m[33];
            buf[k++] = 'p'; buf[k++] = 'c'; buf[k++] = '='; hexout(buf, &k, pc);
            buf[k++] = ' '; buf[k++] = 'l'; buf[k++] = 'r'; buf[k++] = '='; hexout(buf, &k, lr);
            buf[k++] = ' '; buf[k++] = 's'; buf[k++] = 'p'; buf[k++] = '='; hexout(buf, &k, sp);
            if (pc == 0 && s == 11) {
                unsigned long x0 = m[2];
                buf[k++] = ' '; buf[k++] = 'x'; buf[k++] = '0'; buf[k++] = '='; hexout(buf, &k, x0);
                unsigned long* obj = (unsigned long*)x0;
                if (x0 > 0x1000 && x0 < 0x800000000000UL) {
                    for (int i = 0; i < 6; i++) {
                        buf[k++] = ' '; buf[k++] = 'q'; buf[k++] = '0' + i; buf[k++] = '=';
                        hexout(buf, &k, obj[i * 2]); buf[k++] = ',';
                        hexout(buf, &k, obj[i * 2 + 1]);
                        if (k > 200) break;
                    }
                }
            }
            my_dlinfo di; di.fname = 0; di.sname = 0;
            my_dlinfo dp; dp.fname = 0; dp.sname = 0;
            if (pc && dladdr((const void*)pc, &dp) && dp.fname) {
                const char* b3 = dp.fname; for (const char* q3 = dp.fname; *q3; q3++) if (*q3 == '/') b3 = q3 + 1;
                buf[k++] = ' '; buf[k++] = 'P'; buf[k++] = '@'; while (*b3 && k < 190) buf[k++] = *b3++;
                buf[k++] = '+'; hexout(buf, &k, pc - (unsigned long)dp.fbase);
                if (dp.sname) { buf[k++] = ' '; const char* s3 = dp.sname; while (*s3 && k < 215) buf[k++] = *s3++; }
            }
            if (lr && dladdr((const void*)lr, &di) && di.fname) {
                const char* b = di.fname; for (const char* q = di.fname; *q; q++) if (*q == '/') b = q + 1;
                buf[k++] = ' '; buf[k++] = '@'; while (*b && k < 200) buf[k++] = *b++;
                buf[k++] = '+'; hexout(buf, &k, lr - (unsigned long)di.fbase);
                if (di.sname) { buf[k++] = ' '; const char* s2 = di.sname; while (*s2 && k < 220) buf[k++] = *s2++; }
            }
        }
    } else { buf[k++] = 'n'; buf[k++] = 'o'; buf[k++] = 'c'; buf[k++] = 't'; buf[k++] = 'x'; }
    buf[k] = 0;
    net_report(buf, "");
    if (pc == 0 && uctx) {
        unsigned long* u = (unsigned long*)uctx;
        if (u[6]) {
            unsigned long* m = (unsigned long*)u[6];
            m[34] = m[32]; /* resume at lr: skip the nil call */
            g_sigcount = 0;
        }
    }
}

static void ax_init_try(void);
/* ---- proper block for XPC reply ---- */
extern void* _NSConcreteGlobalBlock;
struct blk_desc_ex { unsigned long reserved; unsigned long size; const char* signature; const char* layout; };
static id g_pproc;
struct blk_obj { void* isa; int flags; int reserved; void (*invoke)(void*, id, id); struct blk_desc_ex* desc; };
extern const char* class_getName(void*);
extern void* object_getClass(id);
extern char* strstr(const char*, const char*);
static void reply_invoke(void* b, id a1, id a2) {
    const char* c1 = a1 ? class_getName(object_getClass(a1)) : "nil";
    const char* c2 = a2 ? class_getName(object_getClass(a2)) : "nil";
    net_report("R_A1:", c1);
    net_report("R_A2:", c2);
    /* ★会话递给进程 */
    if (a1 && g_pproc) {
        long hasS = (long)((void*(*)(id,void*,void*))objc_msgSend)(g_pproc, sel_registerName("respondsToSelector:"), sel_registerName("setAutomationSession:"));
        if (hasS) {
            ((void(*)(id,void*,id))objc_msgSend)(g_pproc, sel_registerName("setAutomationSession:"), a1);
            net_report("SESSION:", "installed_to_proc");
        } else net_report("SESSION:", "no_setter");
    }
    if (a1) {
        long hasDr = (long)((void*(*)(id,void*,void*))objc_msgSend)(a1, sel_registerName("respondsToSelector:"), sel_registerName("dictionaryRepresentation"));
        id d = hasDr ? ((id(*)(id,void*))objc_msgSend)(a1, sel_registerName("dictionaryRepresentation")) : 0;
        if (!hasDr) net_report("R_A1:", "no_dictrep");
        if (d) {
            id ds = ((id(*)(id,void*))objc_msgSend)(d, sel_registerName("description"));
            if (ds) net_report("R_CAPS:", ((const char*(*)(id,void*))objc_msgSend)(ds, sel_registerName("UTF8String")));
        }
    }
    if (a2) {
        id txt = 0;
        if (strstr(c2, "String")) txt = a2;
        else if (strstr(c2, "Error")) txt = ((id(*)(id,void*))objc_msgSend)(a2, sel_registerName("localizedDescription"));
        if (txt) net_report("R_TXT:", ((const char*(*)(id,void*))objc_msgSend)(txt, sel_registerName("UTF8String")));
    }
}
static struct blk_desc_ex g_blkdesc = { 0, sizeof(struct blk_obj), "v24@?0@8@16", 0 };
static struct blk_obj g_replyblk = { &_NSConcreteGlobalBlock, 0x50000000, 0, reply_invoke, &g_blkdesc };

extern void* class_getInstanceMethod(void*, void*);
extern const char* method_getTypeEncoding(void*);
extern void* method_setImplementation(void*, void*);
extern void* objc_getClass(const char*);
extern void* object_getClass(id);
extern char* strstr(const char*, const char*);

extern void* dispatch_get_global_queue(long, unsigned long);
static void (*orig_setRouteQueue)(id, void*, void*);
static void hook_setRouteQueue(id self, void* _cmd, void* q) {
    net_report("ROUTEQ:", "passthrough_mainq");
    if (orig_setRouteQueue) orig_setRouteQueue(self, _cmd, q);
}
static void install_routeq_hook(void) {
    void* cls = objc_getClass("RoutingHTTPServer");
    if (!cls) { net_report("ROUTEQ:", "no_class_yet"); return; }
    void* m = class_getInstanceMethod(cls, sel_registerName("setRouteQueue:"));
    if (m) { orig_setRouteQueue = (void*)method_setImplementation(m, (void*)hook_setRouteQueue); net_report("ROUTEQ:", "hooked"); }
}

static void install_routeq_hook(void);
/* 本地作答 bundle-id 查询：彻底绕开守护挂死 + 消灭 local.pid.0 假名 */
static void call_block2(void* blk, void* a, void* b) {
    void** p = (void**)blk;
    char line[200]; int k = 0;
    const char* q = "BLK:"; while (*q) line[k++] = *q++;
    for (int i = 0; i < 5; i++) {
        if (i) line[k++] = ',';
        hexout(line, &k, (unsigned long)p[i]);
    }
    line[k] = 0;
    net_report(line, "");
    id isacl = object_getClass((id)blk);
    const char* cn = isacl ? class_getName(isacl) : "nil";
    net_report("BLKISA:", cn);
    void* inv = p[2]; /* invoke 在偏移16——p[3] 是 descriptor！ */
    my_dlinfo di; di.fname = 0; di.sname = 0;
    if (inv && dladdr(inv, &di) && di.fname) {
        const char* bb = di.fname; for (const char* rr = di.fname; *rr; rr++) if (*rr == '/') bb = rr + 1;
        char l2[140]; int k2 = 0;
        const char* q2 = "BLKINV:"; while (*q2) l2[k2++] = *q2++;
        while (*bb && k2 < 100) l2[k2++] = *bb++;
        l2[k2++] = '+'; hexout(l2, &k2, (unsigned long)inv - (unsigned long)di.fbase);
        if (di.sname) { l2[k2++] = ' '; const char* s2 = di.sname; while (*s2 && k2 < 130) l2[k2++] = *s2++; }
        l2[k2] = 0;
        net_report(l2, "");
    } else net_report("BLKINV:", "no_dladdr");
    if (cn && contains(cn, "Block")) {
        void (*fn)(void*, void*, void*) = (void (*)(void*, void*, void*))inv;
        net_report("BLK:", "calling");
        fn(blk, a, b);
        net_report("BLK:", "returned");
    } else {
        net_report("BLK:", "NOTABLOCK_SKIP");
    }
}
extern void* class_getInstanceVariable(void*, const char*);
static id (*g_orig_qae)(void*, void*) = 0;
static id (*g_orig_qae2)(void*, void*) = 0;
static id (*g_orig_qae3)(void*, void*) = 0;
static id (*g_orig_qae4)(void*, void*) = 0;
static id my_qae(void* self, void* sel) {
    id e = g_orig_qae ? g_orig_qae(self, sel) : 0;
    net_report("QAE:", e ? "has" : "NIL");
    return e;
}
static id my_qae2(void* self, void* sel) {
    id e = g_orig_qae2 ? g_orig_qae2(self, sel) : 0;
    net_report("QAE2:", e ? "has" : "NIL");
    return e;
}
static id my_qae3(void* self, void* sel) {
    id e = g_orig_qae3 ? g_orig_qae3(self, sel) : 0;
    net_report("QAE3:", e ? "has" : "NIL");
    return e;
}
static id my_qae4(void* self, void* sel) {
    id e = g_orig_qae4 ? g_orig_qae4(self, sel) : 0;
    net_report("QAE4:", e ? "has" : "NIL");
    return e;
}
static void install_qae_hook(void) {
    static int done = 0;
    if (done) return;
    done = 1;
    const char* cs[4] = { "XCUIElementQuery", "XCUIElement", "XCUIApplication", "XCUIApplicationImpl" };
    for (int q = 0; q < 4; q++) {
        void* m = class_getInstanceMethod((id)objc_getClass(cs[q]), sel_registerName("accessibilityElement"));
        if (m) {
            id (*orig)(void*, void*) = 0;
            void* imp = 0;
            if (q == 0) { g_orig_qae = (id (*)(void*, void*))method_setImplementation(m, (void*)my_qae); }
            else if (q == 1) { g_orig_qae2 = (id (*)(void*, void*))method_setImplementation(m, (void*)my_qae2); }
            else if (q == 2) { g_orig_qae3 = (id (*)(void*, void*))method_setImplementation(m, (void*)my_qae3); }
            else { g_orig_qae4 = (id (*)(void*, void*))method_setImplementation(m, (void*)my_qae4); }
            net_report("QAEHOOK:", cs[q]);
        }
    }
}
static void set_spec_pid(id spec);
extern long ivar_getOffset(void*);
static long ivar_long(id obj, const char* name) {
    if (!obj) return -1;
    void* iv = class_getInstanceVariable(object_getClass(obj), name);
    if (!iv) return -2;
    unsigned char* base = (unsigned char*)obj;
    return *(long*)(base + ivar_getOffset(iv));
}
static int g_in_spec = 0;
static void my_spec_imp(void* self, void* sel, long long pid, void* replyblk) {
    char bb[12]; int k = 0; const char* q = "SPECREQ:"; while (*q) bb[k++] = *q++;
    bb[k++] = '0' + (pid % 10); bb[k] = 0;
    net_report(bb, "local_reply");
    if (!g_in_spec) {
        g_in_spec = 1;
        id devc = ((id(*)(id,void*))objc_msgSend)((id)objc_getClass("XCUIDevice"), sel_registerName("sharedDevice"));
        id mon2 = devc ? ((id(*)(id,void*))objc_msgSend)(devc, sel_registerName("applicationMonitor")) : 0;
        if (mon2) {
            id bids = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.apple.springboard");
            long hasTk = (long)((void*(*)(id,void*,void*))objc_msgSend)(mon2, sel_registerName("respondsToSelector:"), sel_registerName("_setIsTrackingForBundleID:"));
            if (hasTk) { ((void(*)(id,void*,id))objc_msgSend)(mon2, sel_registerName("_setIsTrackingForBundleID:"), bids); net_report("FEED:", "tracking_set"); }
            long hasAP = (long)((void*(*)(id,void*,void*))objc_msgSend)(mon2, sel_registerName("respondsToSelector:"), sel_registerName("monitoredApplicationWithProcessIdentifier:"));
            if (hasAP) {
                id proc = ((id(*)(id,void*,int))objc_msgSend)(mon2, sel_registerName("monitoredApplicationWithProcessIdentifier:"), (int)pid);
                net_report("FEED:", proc ? "proc_ok" : "proc_nil");
                if (proc) {
                    net_report("PROCCLS:", proc ? class_getName(object_getClass(proc)) : "nil");
                    /* 拍接口 */
                    const char* probes[6] = { "setApplicationState:", "applicationState", "running", "setCurrentProcess:", "setRunning:", 0 };
                    for (int pp = 0; probes[pp]; pp++) {
                        long okp = (long)((void*(*)(id,void*,void*))objc_msgSend)(proc, sel_registerName("respondsToSelector:"), sel_registerName(probes[pp]));
                        net_report("PROBE:", okp ? probes[pp] : "no");
                    }
                    /* XCUIApplication 内脏解剖 */
                    {
                        extern void* class_copyIvarList(void*, unsigned int*);
                        extern const char* ivar_getName(void*);
                        unsigned int nic = 0;
                        void* ivs = class_copyIvarList(object_getClass(proc), &nic);
                        for (unsigned int q = 0; q < nic && q < 14; q++) {
                            net_report("IVAR:", ivar_getName(((void**)ivs)[q]));
                        }
                        /* ★找真进程喂给 impl.currentProcess */
                        id implx = ((id(*)(id,void*))objc_msgSend)(proc, sel_registerName("applicationImpl"));
                        id mony = ((id(*)(id,void*))objc_msgSend)((id)objc_getClass("XCUIDevice"), sel_registerName("sharedDevice"));
                        id monp = mony ? ((id(*)(id,void*))objc_msgSend)(mony, sel_registerName("applicationMonitor")) : 0;
                        if (implx && monp) {
                            long hasMap = (long)((void*(*)(id,void*,void*))objc_msgSend)(monp, sel_registerName("respondsToSelector:"), sel_registerName("applicationProcessesForPID"));
                            net_report("MAP:", hasMap ? "has" : "no");
                            if (hasMap) {
                                id map = ((id(*)(id,void*))objc_msgSend)(monp, sel_registerName("applicationProcessesForPID"));
                                net_report("MAPCLS:", map ? class_getName(object_getClass(map)) : "nil");
                                id found = 0;
                                if (map) {
                                    long hasAll = (long)((void*(*)(id,void*,void*))objc_msgSend)(map, sel_registerName("respondsToSelector:"), sel_registerName("allValues"));
                                    if (hasAll) {
                                        id vals = ((id(*)(id,void*))objc_msgSend)(map, sel_registerName("allValues"));
                                        long nvals = (long)((void*(*)(id,void*))objc_msgSend)(vals, sel_registerName("count"));
                                        net_report("MAP:", nvals > 0 ? "has_values" : "empty");
                                        if (nvals > 0) found = ((id(*)(id,void*,unsigned long))objc_msgSend)(vals, sel_registerName("objectAtIndex:"), 0UL);
                                    }
                                }
                                net_report("FOUND:", found ? class_getName(object_getClass(found)) : "nil");
                                if (found) {
                                    ((void(*)(id,void*,id))objc_msgSend)(implx, sel_registerName("setCurrentProcess:"), found);
                                    long hasSS2 = (long)((void*(*)(id,void*,void*))objc_msgSend)(found, sel_registerName("respondsToSelector:"), sel_registerName("setApplicationState:"));
                                    if (hasSS2) ((void(*)(id,void*,long long))objc_msgSend)(found, sel_registerName("setApplicationState:"), 4LL);
                                    id cp2 = ((id(*)(id,void*))objc_msgSend)(implx, sel_registerName("currentProcess"));
                                    long st8 = ivar_long(found, "_applicationState");
                                    char l8[24]; int k8 = 0; const char* q8 = "WIRE:"; while (*q8) l8[k8++] = *q8++;
                                    l8[k8++] = cp2 ? '1' : '0'; l8[k8++] = ',';
                                    l8[k8++] = '0' + ((st8 < 0 ? 9 : st8) % 10); l8[k8] = 0;
                                    net_report(l8, "cp_set,state");
                                }
                            }
                        }
                        const char* accs[6] = { "applicationProcess", "impl", "process", "applicationImpl", "currentProcess", 0 };
                        for (int q = 0; accs[q]; q++) {
                            long okq = (long)((void*(*)(id,void*,void*))objc_msgSend)(proc, sel_registerName("respondsToSelector:"), sel_registerName(accs[q]));
                            net_report("ACC:", okq ? accs[q] : "no");
                            if (okq) {
                                id inner = ((id(*)(id,void*))objc_msgSend)(proc, sel_registerName(accs[q]));
                                net_report("ACCCLS:", inner ? class_getName(object_getClass(inner)) : "nil");
                                if (inner) {
                                    long okss = (long)((void*(*)(id,void*,void*))objc_msgSend)(inner, sel_registerName("respondsToSelector:"), sel_registerName("setApplicationState:"));
                                    if (okss) {
                                        ((void(*)(id,void*,long long))objc_msgSend)(inner, sel_registerName("setApplicationState:"), 4LL);
                                        long st9 = ivar_long(inner, "_applicationState");
                                        char l9[20]; int k9 = 0; const char* q9 = "INNER:"; while (*q9) l9[k9++] = *q9++;
                                        l9[k9++] = '0' + ((st9 < 0 ? 9 : st9) % 10); l9[k9] = 0;
                                        net_report(l9, "state_set");
                                    }
                                }
                            }
                        }
                    }
                    long hasSS = (long)((void*(*)(id,void*,void*))objc_msgSend)(proc, sel_registerName("respondsToSelector:"), sel_registerName("setApplicationState:"));
                    if (hasSS) {
                        ((void(*)(id,void*,long long))objc_msgSend)(proc, sel_registerName("setApplicationState:"), 4LL);
                        long st = ivar_long(proc, "_applicationState");
                        char l3[20]; int k3 = 0; const char* q3 = "STATE:"; while (*q3) l3[k3++] = *q3++;
                        l3[k3++] = '0' + ((st < 0 ? 9 : st) % 10); l3[k3] = 0;
                        net_report(l3, "after_set");
                    }
                    /* 跟踪已设——补喂快照（时序修正） */
                    id monx = ((id(*)(id,void*))objc_msgSend)((id)objc_getClass("XCUIDevice"), sel_registerName("sharedDevice"));
                    id monm = monx ? ((id(*)(id,void*))objc_msgSend)(monx, sel_registerName("applicationMonitor")) : 0;
                    id snapCls2 = (id)objc_getClass("XCTApplicationStateSnapshot");
                    if (!snapCls2) snapCls2 = (id)objc_getClass("XCUIApplicationStateSnapshot");
                    if (monm && snapCls2) {
                        id bids2 = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.apple.springboard");
                        int pz[2]; pz[0] = (int)pid; pz[1] = 352;
                        for (int z = 0; z < 2; z++) {
                            id snap2 = ((id(*)(id,void*,id,id,long long,int,long long,long long))objc_msgSend)(((id(*)(void*,void*))objc_msgSend)(snapCls2, sel_registerName("alloc")), sel_registerName("initWithBundleID:path:runState:processID:activationPolicy:eventID:"), bids2, 0, 4LL, pz[z], 0LL, (long long)(100 + z));
                            if (snap2) {
                                ((void(*)(id,void*,id))objc_msgSend)(monm, sel_registerName("updatedApplicationStateSnapshot:"), snap2);
                                net_report("SNAP2:", "fed");
                            }
                        }
                    }
                }
            }
        }
        g_in_spec = 0;
    }
    id specCls = (id)objc_getClass("XCUIApplicationSpecifier");
    id bidz = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.apple.springboard");
    id spec = specCls ? ((id(*)(id,void*,id,id))objc_msgSend)(specCls, sel_registerName("specifierWithBundleIdentifier:path:"), bidz, 0) : 0;
    if (spec) {
        long hasSetPid = (long)((void*(*)(id,void*,void*))objc_msgSend)(spec, sel_registerName("respondsToSelector:"), sel_registerName("setPid:"));
        if (hasSetPid) ((void(*)(id,void*,long long))objc_msgSend)(spec, sel_registerName("setPid:"), 10040LL);
        long hasSetProc = (long)((void*(*)(id,void*,void*))objc_msgSend)(spec, sel_registerName("respondsToSelector:"), sel_registerName("setProcessIdentifier:"));
        if (hasSetProc) ((void(*)(id,void*,long long))objc_msgSend)(spec, sel_registerName("setProcessIdentifier:"), 10040LL);
        net_report("SPECPID:", (hasSetPid || hasSetProc) ? "pid_set" : "no_setter");
        if (!(hasSetPid || hasSetProc)) set_spec_pid(spec);
    }
    if (replyblk && spec) call_block2(replyblk, spec, 0);
}
static void install_spec_hook(void) {
    void* m = class_getInstanceMethod((id)objc_getClass("XCTRunnerDaemonSession"), sel_registerName("requestApplicationSpecifierForPID:reply:"));
    if (m) {
        method_setImplementation(m, (void*)my_spec_imp);
        net_report("HOOK:", "spec_req_hooked");
    } else net_report("HOOK:", "no_spec_method");
}
extern void* method_setImplementation(void*, void*);
static id g_pproc = 0;
static id (*g_orig_mon)(void*, void*, int) = 0;
static id my_mon(void* self, void* sel, int pid) {
    id app = g_orig_mon ? g_orig_mon(self, sel, pid) : 0;
    if (app && g_pproc) {
        id impl = ((id(*)(id,void*))objc_msgSend)(app, sel_registerName("applicationImpl"));
        if (impl) {
            ((void(*)(id,void*,id))objc_msgSend)(impl, sel_registerName("setCurrentProcess:"), g_pproc);
            ((void(*)(id,void*,unsigned long long))objc_msgSend)(g_pproc, sel_registerName("setApplicationState:"), 4ULL);
            *(long*)((unsigned char*)g_pproc + 0x18) = 4;
            /* impl 的 currentProcess（ivar 0x20，实证）也补 */
            id cur = *(void**)((unsigned char*)impl + 0x20);
            if (cur) *(long*)((unsigned char*)cur + 0x18) = 4;
        }
    }
    return app;
}
extern void* class_getInstanceMethod(void*, void*);
static id (*g_orig_procinit)(void*, void*, id, id, id, id) = 0;
static id my_procinit(void* self, void* sel, id path, id bid, id dev, id del) {
    id p = g_orig_procinit ? g_orig_procinit(self, sel, path, bid, dev, del) : 0;
    if (p) {
        /* 同步写状态 ivar（偏移0x18，反汇编实证）——_awaitKnownApplicationState 先查非0直接放行 */
        *(long*)((unsigned char*)p + 0x18) = 4;
        ((void(*)(id,void*,unsigned long long))objc_msgSend)(p, sel_registerName("setApplicationState:"), 4ULL);
        net_report("PROCINIT:", "state_preset");
    }
    return p;
}
static long my_yes(id self, void* sel);
static long my_state4(id self, void* sel) { (void)self; (void)sel; return 4; }
static id (*g_orig_procinit2)(void*, void*, id, id, id) = 0;
static id my_procinit2(void* self, void* sel, id bid, id dev, id del) {
    id p = g_orig_procinit2 ? g_orig_procinit2(self, sel, bid, dev, del) : 0;
    if (p) {
        *(long*)((unsigned char*)p + 0x18) = 4;
        ((void(*)(id,void*,unsigned long long))objc_msgSend)(p, sel_registerName("setApplicationState:"), 4ULL);
        net_report("PROCINIT2:", "state_preset");
    }
    return p;
}
static id (*g_orig_depot)(void*, void*, id) = 0;
static id my_depot(void* self, void* sel, id spec) {
    id impl = g_orig_depot ? g_orig_depot(self, sel, spec) : 0;
    if (impl && g_pproc) {
        long hasSet = (long)((void*(*)(id,void*,void*))objc_msgSend)(impl, sel_registerName("respondsToSelector:"), sel_registerName("setCurrentProcess:"));
        if (hasSet) {
            ((void(*)(id,void*,id))objc_msgSend)(impl, sel_registerName("setCurrentProcess:"), g_pproc);
            *(long*)((unsigned char*)g_pproc + 0x18) = 4;
            /* ★processID 10040 → accessibilityElement 才能造出来 */
            long cur1 = (long)((void*(*)(id,void*))objc_msgSend)(g_pproc, sel_registerName("processID"));
            if (cur1 == 0) ((void(*)(id,void*,long long))objc_msgSend)(g_pproc, sel_registerName("setProcessID:"), 10040LL);
            long hasP2 = (long)((void*(*)(id,void*,void*))objc_msgSend)(impl, sel_registerName("respondsToSelector:"), sel_registerName("setProcessID:"));
            if (hasP2) {
                long cur2 = (long)((void*(*)(id,void*))objc_msgSend)(impl, sel_registerName("processID"));
                if (cur2 == 0) ((void(*)(id,void*,long long))objc_msgSend)(impl, sel_registerName("setProcessID:"), 10040LL);
            }
            net_report("DEPOT:", "impl_wired+pid");
        }
    }
    return impl;
}
static void install_depot_hook(void) {
    install_qae_hook();
    static int done = 0;
    if (done) return;
    void* m = class_getInstanceMethod((id)objc_getClass("XCUIApplicationImplDepot"), sel_registerName("applicationImplForSpecifier:"));
    if (m) {
        g_orig_depot = (id (*)(void*, void*, id))method_setImplementation(m, (void*)my_depot);
        done = 1;
        net_report("DEPOT:", "hooked");
    } else net_report("DEPOT:", "no_method");
}
static void install_procinit_hook(void) {
    static int done = 0;
    if (done) return;
    void* m = class_getInstanceMethod((id)objc_getClass("XCUIApplicationProcess"), sel_registerName("initWithPath:bundleID:device:delegate:"));
    if (m) {
        g_orig_procinit = (id (*)(void*, void*, id, id, id, id))method_setImplementation(m, (void*)my_procinit);
        net_report("PROCINIT:", "hooked");
    }
    /* ★KVO 等待对象是 app 本体的 isApplicationStateKnown——三类全钉 YES，state 钉 4 */
    {
        const char* clsnames[3] = { "XCUIApplication", "XCUIApplicationImpl", "XCUIApplicationProcess" };
        for (int q = 0; q < 3; q++) {
            void* cc = objc_getClass(clsnames[q]);
            if (!cc) continue;
            void* mm = class_getInstanceMethod(cc, sel_registerName("isApplicationStateKnown"));
            if (mm) { method_setImplementation(mm, (void*)my_yes); net_report("KVO:", clsnames[q]); }
            void* ms = class_getInstanceMethod(cc, sel_registerName("applicationState"));
            if (ms) { method_setImplementation(ms, (void*)my_state4); }
            void* mr = class_getInstanceMethod(cc, sel_registerName("running"));
            if (mr) { method_setImplementation(mr, (void*)my_yes); net_report("PIN:", "running"); }
            void* mwq = class_getInstanceMethod(cc, sel_registerName("waitForAutomationSession"));
            if (mwq) { method_setImplementation(mwq, (void*)my_yes); net_report("PIN:", "waitAutoSess"); }
            void* mst = class_getInstanceMethod(cc, sel_registerName("state"));
            if (mst) { method_setImplementation(mst, (void*)my_state4); net_report("PIN:", "state4"); }
            /* 静默等待直接放行——绕开 XCTContext 活动栈断言 */
            const char* wq[3] = { "waitForQuiescenceIncludingAnimationsIdle:", "waitForQuiescence", "_initiateQuiescenceChecksIncludingAnimationsIdle:" };
            for (int w = 0; w < 3; w++) {
                void* mw = class_getInstanceMethod(cc, sel_registerName(wq[w]));
                if (mw) { method_setImplementation(mw, (void*)my_yes); net_report("WQ:", wq[w]); }
            }
        }
    }
    void* m2 = class_getInstanceMethod((id)objc_getClass("XCUIApplicationProcess"), sel_registerName("initWithBundleID:device:delegate:"));
    if (m2) {
        g_orig_procinit2 = (id (*)(void*, void*, id, id, id))method_setImplementation(m2, (void*)my_procinit2);
        net_report("PROCINIT2:", "hooked");
    }
    done = 1;
}
static void install_mon_hook(void) {
    static int done = 0;
    if (done) return;
    void* m = class_getInstanceMethod((id)objc_getClass("XCUIApplicationMonitor"), sel_registerName("monitoredApplicationWithProcessIdentifier:"));
    if (m) {
        g_orig_mon = (id (*)(void*, void*, int))method_setImplementation(m, (void*)my_mon);
        done = 1;
        net_report("MONHOOK:", "installed");
    }
}
static long my_no_delegate(id self, void* sel, id arg) { (void)self; (void)sel; (void)arg; return 1; /* YES: 让进程自己走自动化会话 */ }
static void install_delegate_stubs(void) {
    static int done = 0;
    if (done) return;
    done = 1;
    void* cls = objc_getClass("XCTRunnerDaemonSession");
    if (!cls) return;
    class_addMethod(cls, sel_registerName("applicationProcessShouldRequestAutomationSession:"), (void*)my_no_delegate, "B@:@");
    { void* icls = objc_getClass("XCUIApplicationImpl");
      if (icls) class_addMethod(icls, sel_registerName("applicationProcessShouldRequestAutomationSession:"), (void*)my_no_delegate, "B@:@"); }
    class_addMethod(cls, sel_registerName("applicationProcessDidLaunch:"), (void*)my_no_delegate, "v@:@");
    class_addMethod(cls, sel_registerName("applicationProcessDidTerminate:"), (void*)my_no_delegate, "v@:@");
    net_report("STUB:", "delegate_stubs_added");
    install_mon_hook();
}
static void wire_state(long pid) {
    install_delegate_stubs();
    install_mon_hook();
    id dev = ((id(*)(id,void*))objc_msgSend)((id)objc_getClass("XCUIDevice"), sel_registerName("sharedDevice"));
    id monp = dev ? ((id(*)(id,void*))objc_msgSend)(dev, sel_registerName("applicationMonitor")) : 0;
    if (!monp) return;
    id app = ((id(*)(id,void*,int))objc_msgSend)(monp, sel_registerName("monitoredApplicationWithProcessIdentifier:"), (int)pid);
    if (!app) return;
    id impl = ((id(*)(id,void*))objc_msgSend)(app, sel_registerName("applicationImpl"));
    if (!impl) return;
    if (!g_pproc) {
        id spath = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "/System/Library/CoreServices/SpringBoard.app");
        id sbid = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.apple.springboard");
        id ss = ((id(*)(id,void*))objc_msgSend)((id)objc_getClass("XCTRunnerDaemonSession"), sel_registerName("sharedSession"));
        id pcls = (id)objc_getClass("XCUIApplicationProcess");
        id pproc = pcls ? ((id(*)(id,void*,id,id,id,id))objc_msgSend)(((id(*)(void*,void*))objc_msgSend)(pcls, sel_registerName("alloc")), sel_registerName("initWithPath:bundleID:device:delegate:"), spath, sbid, dev, ss) : 0;
        net_report("WIRE:", pproc ? "pproc_ok" : "pproc_nil");
        if (pproc) {
            ((void(*)(id,void*,unsigned long long))objc_msgSend)(pproc, sel_registerName("setApplicationState:"), 4ULL);
            ((void(*)(id,void*,long long))objc_msgSend)(pproc, sel_registerName("setProcessID:"), 10040LL);
            ((void(*)(id,void*,id,int))objc_msgSend)(monp, sel_registerName("setApplicationProcess:forPID:"), pproc, 352);
            net_report("WIRE:", "registered352");
        }
        g_pproc = pproc;
    }
    if (!g_pproc) return;
    ((void(*)(id,void*,id))objc_msgSend)(impl, sel_registerName("setCurrentProcess:"), g_pproc);
    ((void(*)(id,void*,unsigned long long))objc_msgSend)(g_pproc, sel_registerName("setApplicationState:"), 4ULL);
    id cp = ((id(*)(id,void*))objc_msgSend)(impl, sel_registerName("currentProcess"));
    char l[16]; int k = 0; const char* qz = "WIRE:"; while (*qz) l[k++] = *qz++;
    l[k++] = cp ? '1' : '0';
    l[k++] = ','; l[k++] = '0' + (pid == 0 ? '0' : '3');
    l[k] = 0;
    net_report(l, "cp,pid");
}
static void set_spec_pid(id spec) {
    const char* names[3] = { "_pid", "pid", "_processIdentifier" };
    for (int q = 0; q < 3; q++) {
        void* iv = class_getInstanceVariable(object_getClass(spec), names[q]);
        if (iv) {
            *(int*)((unsigned char*)spec + ivar_getOffset(iv)) = 10040;
            net_report("SPECPID:", names[q]);
        }
    }
}
static void* feed_thread(void* arg);
static void* mon_thread(void* arg) {
    (void)arg;
    install_spec_hook();
    install_delegate_stubs();
    install_mon_hook();
    install_procinit_hook();
    install_depot_hook();
    wire_state(0); /* 预置 g_pproc + 入册 */
    /* 迟到的会话请求——等 g_pproc 就位后再要，reply_invoke 会装进进程 */
    {
        id s3 = ((id(*)(id,void*))objc_msgSend)((id)objc_getClass("XCTRunnerDaemonSession"), sel_registerName("sharedSession"));
        if (s3) {
            id path3 = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "/var/jb/usr/lib/xctfw/XCTAutomationSupport.framework");
            ((void(*)(id,void*,long,id,void*))objc_msgSend)(s3, sel_registerName("requestAutomationSessionForTestTargetWithPID:preferredBackendPath:reply:"), 10040L, path3, &g_replyblk);
            net_report("AX6:", "late_reqSession");
        }
    }
    id dev = ((id(*)(id,void*))objc_msgSend)((id)objc_getClass("XCUIDevice"), sel_registerName("sharedDevice"));
    id mon = dev ? ((id(*)(id,void*))objc_msgSend)(dev, sel_registerName("applicationMonitor")) : 0;
    id bid = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.apple.springboard");
    if (mon) {
        long hasTk = (long)((void*(*)(id,void*,void*))objc_msgSend)(mon, sel_registerName("respondsToSelector:"), sel_registerName("_setIsTrackingForBundleID:"));
        if (hasTk) ((void(*)(id,void*,id))objc_msgSend)(mon, sel_registerName("_setIsTrackingForBundleID:"), bid);
    }
    /* ★官方跟踪注册——让守护自己推应用状态 */
    {
        id ses = ((id(*)(id,void*))objc_msgSend)((id)objc_getClass("XCTRunnerDaemonSession"), sel_registerName("sharedSession"));
        id specCls = (id)objc_getClass("XCUIApplicationSpecifier");
        if (ses && specCls) {
            id spec = ((id(*)(id,void*,id,id))objc_msgSend)(specCls, sel_registerName("specifierWithBundleIdentifier:path:"), bid, 0);
            if (spec) { long hp = (long)((void*(*)(id,void*,void*))objc_msgSend)(spec, sel_registerName("respondsToSelector:"), sel_registerName("setPid:")); if (hp) ((void(*)(id,void*,long long))objc_msgSend)(spec, sel_registerName("setPid:"), 10040LL); }
            if (spec) {
                ((void(*)(id,void*,id))objc_msgSend)(ses, sel_registerName("beginMonitoringApplicationWithSpecifier:"), spec);
                net_report("MONT:", "beginMon_called");
            }
        }
    }
    net_report("MONT:", "setup_done");
    /* ★签到通知——守护等的是 com.apple.dt.xctestd.availability.<pid>，我们代发 */
    {
        extern int notify_post(const char*);
        char nbuf[64];
        int pids3[5] = { 10040, 352, 0, (int)(long)objc_msgSend, 0 };
        pids3[3] = 0;
        const int use_pids[3] = { 10040, 352, 0 };
        for (int q = 0; q < 3; q++) {
            int k = 0; const char* pre = "com.apple.dt.xctestd.availability.";
            while (*pre) nbuf[k++] = *pre++;
            int v = use_pids[q]; char tmp[12]; int t = 0;
            if (v == 0) tmp[t++] = '0';
            else { char rev[12]; int r = 0; while (v) { rev[r++] = '0' + (v % 10); v /= 10; } while (r) tmp[t++] = rev[--r]; }
            for (int z = 0; z < t; z++) nbuf[k++] = tmp[z];
            nbuf[k] = 0;
            int er = notify_post(nbuf);
            net_report("CHECKIN:", nbuf + 30);
        }
    }
    return feed_thread(0);
}
static void* feed_thread(void* arg) {
    (void)arg;
    id bid2 = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.apple.springboard");
    id ses = ((id(*)(id,void*))objc_msgSend)((id)objc_getClass("XCTRunnerDaemonSession"), sel_registerName("sharedSession"));
    for (int r = 0; r < 30; r++) {
        { long ts[2] = { 2, 0 }; extern int nanosleep(const long*, long*); nanosleep(ts, 0); }
        /* 广撒签到通知 */
        {
            extern int notify_post(const char*);
            extern int getpid(void);
            int targets3[3] = { 10040, 352, 0 };
            for (int q = 0; q < 3; q++) {
                char nb[64]; int k = 0; const char* pre = "com.apple.dt.xctestd.availability.";
                while (*pre) nb[k++] = *pre++;
                int v = targets3[q]; char tmp[12]; int t = 0;
                if (v == 0) tmp[t++] = '0';
                else { char rev[12]; int rr = 0; while (v) { rev[rr++] = '0' + (v % 10); v /= 10; } while (rr) tmp[t++] = rev[--rr]; }
                for (int z = 0; z < t; z++) nb[k++] = tmp[z];
                nb[k] = 0;
                notify_post(nb);
            }
        }
        if (ses) {
            ((void(*)(id,void*,int,id,unsigned long long))objc_msgSend)(ses, sel_registerName("daemonDidUpdatePID:forApplicationWithBundleID:andState:"), 0, bid2, 4ULL);
            ((void(*)(id,void*,int,id,unsigned long long))objc_msgSend)(ses, sel_registerName("daemonDidUpdatePID:forApplicationWithBundleID:andState:"), 352, bid2, 4ULL);
            ((void(*)(id,void*,id,int,unsigned long long))objc_msgSend)(ses, sel_registerName("_XCT_applicationWithBundleID:didUpdatePID:andState:"), bid2, 352, 4ULL);
            ((void(*)(id,void*,id,int,unsigned long long))objc_msgSend)(ses, sel_registerName("_XCT_applicationWithBundleID:didUpdatePID:andState:"), bid2, 0, 4ULL);
        }
        /* 快照通道 */
        id dev = ((id(*)(id,void*))objc_msgSend)((id)objc_getClass("XCUIDevice"), sel_registerName("sharedDevice"));
        id monm = dev ? ((id(*)(id,void*))objc_msgSend)(dev, sel_registerName("applicationMonitor")) : 0;
        id snapCls2 = (id)objc_getClass("XCTApplicationStateSnapshot");
        if (!snapCls2) snapCls2 = (id)objc_getClass("XCUIApplicationStateSnapshot");
        if (monm && snapCls2) {
            int pz[2]; pz[0] = 0; pz[1] = 352;
            for (int z = 0; z < 2; z++) {
                id snap2 = ((id(*)(id,void*,id,id,long long,int,long long,long long))objc_msgSend)(((id(*)(void*,void*))objc_msgSend)(snapCls2, sel_registerName("alloc")), sel_registerName("initWithBundleID:path:runState:processID:activationPolicy:eventID:"), bid2, 0, 4LL, pz[z], 0LL, (long long)(200 + r * 2 + z));
                if (snap2) ((void(*)(id,void*,id))objc_msgSend)(monm, sel_registerName("updatedApplicationStateSnapshot:"), snap2);
            }
        }
    }
    net_report("FD:", "volley_done");
    return 0;
}
static void* dump_thread(void* arg) {
    (void)arg;
    { long ts[2] = { 55, 0 }; extern int nanosleep(const long*, long*); nanosleep(ts, 0); }
    extern int task_threads(void*, void**, unsigned int*);
    extern int thread_get_state(int, int, void*, unsigned int*);
    extern unsigned int mach_task_self_;
    void* list = 0; unsigned int cnt = 0;
    net_report("DUMP:", "firing");
    if (task_threads((void*)(unsigned long)mach_task_self_, &list, &cnt) == 0) {
        unsigned int* tids = (unsigned int*)list;
        unsigned int shown = cnt < 10 ? cnt : 10;
        for (unsigned int t = 0; t < shown; t++) {
            unsigned long long st[40]; unsigned int sc = 68;
            if (thread_get_state((int)tids[t], 6, (void*)st, &sc) == 0) {
                char line[140]; int k = 0;
                const char* p = "T:"; while (*p) line[k++] = *p++;
                line[k++] = '0' + (t % 10); line[k++] = ' ';
                unsigned long vals[2]; vals[0] = (unsigned long)st[32]; vals[1] = (unsigned long)st[30];
                for (int v = 0; v < 2; v++) {
                    line[k++] = (v == 0 ? 'p' : 'l'); line[k++] = 'r'; line[k++] = '=';
                    hexout(line, &k, vals[v]);
                    my_dlinfo di; di.fname = 0; di.sname = 0;
                    if (vals[v] && dladdr((const void*)vals[v], &di) && di.fname) {
                        const char* b = di.fname; for (const char* q = di.fname; *q; q++) if (*q == '/') b = q + 1;
                        line[k++] = '@'; while (*b && k < 110) line[k++] = *b++;
                        line[k++] = '+'; hexout(line, &k, vals[v] - (unsigned long)di.fbase);
                        if (di.sname) { line[k++] = ' '; const char* s2 = di.sname; while (*s2 && k < 130) line[k++] = *s2++; }
                    }
                    line[k++] = ' ';
                }
                line[k] = 0;
                net_report("THRD:", line);
            }
        }
    } else net_report("DUMP:", "task_threads_fail");
    return 0;
}
static void make_window(void) {
    typedef struct { double a, b, c, d; } Rect4;
    Rect4 r = {0, 0, 375, 667};
    void* wcls = objc_getClass("UIWindow");
    void* vcls = objc_getClass("UIViewController");
    if (wcls && vcls) {
        id win = ((id(*)(void*,void*,Rect4))objc_msgSend)(((id(*)(void*,void*))objc_msgSend)((id)wcls, sel_registerName("alloc")), sel_registerName("initWithFrame:"), r);
        id vc = ((id(*)(id,void*))objc_msgSend)((id)vcls, sel_registerName("new"));
        ((void(*)(id,void*,id))objc_msgSend)(win, sel_registerName("setRootViewController:"), vc);
        ((void(*)(id,void*))objc_msgSend)(win, sel_registerName("makeKeyAndVisible"));
        net_report("WIN:", "created_early");
    }
}
static void* beat_thread(void* arg) {
    start_server_direct();
    for (int i = 1; i <= 200; i++) {
        sleep(0);
        { unsigned int micro = 300000;
          long ts[2]; ts[0] = micro / 1000000; ts[1] = micro % 1000000;
          extern int nanosleep(const long*, long*);
          nanosleep(ts, 0); }
        char buf[12]; int k = 0; const char* p = "B:"; while (*p) buf[k++] = *p++;
        if (i >= 10) buf[k++] = '0' + (i / 10);
        buf[k++] = '0' + (i % 10);
        buf[k] = 0;
        net_report(buf, "");
        if (i == 2) { install_routeq_hook(); }
        if (i == 3) {
            void* ses = objc_getClass("XCTRunnerDaemonSession");
            if (ses) {
                id s = ((id(*)(void*,void*))objc_msgSend)((id)ses, sel_registerName("sharedSession"));
                if (s) {
                    ((void(*)(id,void*))objc_msgSend)(s, sel_registerName("finishInitializationForUIAutomation"));
                    net_report("AX8:", "finishInit_first");
                }
            }
        }
        if (0) {
            void* ses = objc_getClass("XCTRunnerDaemonSession");
            void* capcls = objc_getClass("XCTCapabilities");
            if (ses && capcls) {
                id s = ((id(*)(void*,void*))objc_msgSend)((id)ses, sel_registerName("sharedSession"));
                /* 建能力字典 */
                id dict = ((id(*)(void*,void*))objc_msgSend)((id)objc_getClass("NSMutableDictionary"), sel_registerName("dictionary"));
                id one = ((id(*)(void*,void*,long long))objc_msgSend)((id)objc_getClass("NSNumber"), sel_registerName("numberWithLongLong:"), 1LL);
                const char* caps[] = {
                    "application state change handling capability",
                    "monitor application capability",
                    "accept remote connection capability",
                    "request automation session capability",
                    "look up bundle id capability",
                    "load accessibility capability",
                    "unload accessibility capability",
                    "handle AX notification capability",
                    "attributes capability",
                    "evaluate query capability",
                    "fetch element attributes capability",
                    "element at point capability",
                    "request element snapshot capability",
                    "request screenshot capability",
                    "launch application capability",
                    "terminate application capability",
                    "synthesize event capability",
                    "get device orientation capability",
                    "set device orientation capability",
                    "send string capability",
                    "perform device event capability",
                    "timeout capability",
                    "notify main run loop idle capability",
                    "notify animations idle capability",
                    0
                };
                for (int c = 0; caps[c]; c++) {
                    id key = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), caps[c]);
                    ((void(*)(id,void*,id,id))objc_msgSend)(dict, sel_registerName("setObject:forKey:"), one, key);
                }
                id capobj = ((id(*)(void*,void*,id))objc_msgSend)(((id(*)(void*,void*))objc_msgSend)((id)capcls, sel_registerName("alloc")), sel_registerName("initWithDictionary:"), dict);
                net_report("CAPX:", capobj ? "caps_built" : "caps_failed");
                if (s && capobj) {
                    ((void(*)(id,void*,id,void*))objc_msgSend)(s, sel_registerName("exchangeCapabilities:reply:"), capobj, &g_replyblk);
                    net_report("CAPX:", "exchange_sent");
                }
            }
        }
        if (i == 6 || i == 16 || i == 26) {
            void* ses = objc_getClass("XCTRunnerDaemonSession");
            if (ses) {
                id s = ((id(*)(void*,void*))objc_msgSend)((id)ses, sel_registerName("sharedSession"));
                id bid = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.apple.springboard");
                id bid2 = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.facebook.WebDriverAgentRunner.xctrunner");
                ((void(*)(id,void*,int,id,unsigned long long))objc_msgSend)(s, sel_registerName("daemonDidUpdatePID:forApplicationWithBundleID:andState:"), 352, bid, 0ULL);
                ((void(*)(id,void*,id,int,unsigned long long))objc_msgSend)(s, sel_registerName("_XCT_applicationWithBundleID:didUpdatePID:andState:"), bid, 352, 0ULL);
                int mypid = raw3(20, 0, 0, 0);
                ((void(*)(id,void*,int,id,unsigned long long))objc_msgSend)(s, sel_registerName("daemonDidUpdatePID:forApplicationWithBundleID:andState:"), mypid, bid2, 0ULL);
                ((void(*)(id,void*,id,int,unsigned long long))objc_msgSend)(s, sel_registerName("_XCT_applicationWithBundleID:didUpdatePID:andState:"), bid2, mypid, 0ULL);
                net_report("PUSH:", "state0_both_targets");
            }
        }
        if (i == 20 || i == 30) {
            void* ses = objc_getClass("XCTRunnerDaemonSession");
            if (ses) {
                id s = ((id(*)(void*,void*))objc_msgSend)((id)ses, sel_registerName("sharedSession"));
                net_report("AX6:", s ? "reqSession_calling" : "no_shared");
                if (s) {
                    ((void(*)(id,void*,long,void*,void*))objc_msgSend)(s, sel_registerName("requestAutomationSessionForTestTargetWithPID:preferredBackendPath:reply:"), 10040L, ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "/var/jb/usr/lib/xctfw/XCTAutomationSupport.framework"), &g_replyblk);
                    net_report("AX6:", "reqSession_returned");
                void* m = class_getInstanceMethod(ses, sel_registerName("daemonDidUpdatePID:forApplicationWithBundleID:andState:"));
                if (m) {
                    id bid = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.apple.springboard");
                    ((void(*)(id,void*,int,id,unsigned long long))objc_msgSend)(s, sel_registerName("daemonDidUpdatePID:forApplicationWithBundleID:andState:"), 352, bid, 2ULL);
                    net_report("AX7:", "pushed_springboard_state2");
                    id bid2 = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.apple.springboard");
                    ((void(*)(id,void*,int,id,unsigned long long))objc_msgSend)(s, sel_registerName("daemonDidUpdatePID:forApplicationWithBundleID:andState:"), 352, bid2, 1ULL);
                    net_report("AX7:", "pushed_state1_too");
                } else net_report("AX7:", "no_push_method");
                }
            }
        }
    }
    return 0;
}

static void bye(void) { net_report("ATEXIT:", "called"); }

static void* alive_thread(void* arg) {
    net_report("THREAD:", "up");
    sleep(2);
    unsigned int n = _dyld_image_count();
    for (unsigned int i = 0; i < n; i++) {
        const char* nm = _dyld_get_image_name(i);
        if (nm && (contains(nm, "xctest") || contains(nm, "WebDriver") || contains(nm, "XCTest"))) {
            net_report("IMG:", nm);
        }
    }
    sleep(3); net_report("ALIVE:", "5s");
    sleep(3); net_report("ALIVE:", "8s");
    return 0;
}

static int g_reg = 0;
static void sig_handler_dip(int sig) {
    register long x29r __asm__("x29");
    unsigned long lr = 0;
    __asm__ volatile("mov %0, x30" : "=r"(lr));
    char msg[64]; char n[20];
    int kk = 0; hexout(n, &kk, lr); n[kk] = 0;
    msg[0]='l'; msg[1]='r'; msg[2]='=';
    int i=0; while(n[i]){ msg[3+i]=n[i]; i++; }
    msg[3+i]=0;
    net_report("DIP5:", msg);
}
/* 签名改写器：NSXPC 代理要求 void 返回，协议写的是 id 返回 */
static volatile int g_rewrite = 0;
static void* (*orig_sig_imp)(void*, void*, const char*) = 0;
static void* my_sig_imp(void* self, void* sel, const char* types) {
    if (g_rewrite && types && types[0] == '@') {
        char buf[96]; int k = 0;
        while (types[k] && k < 90) { buf[k] = types[k]; k++; }
        buf[k] = 0;
        buf[0] = 'v';
        return orig_sig_imp(self, sel, buf);
    }
    return orig_sig_imp(self, sel, types);
}
static void install_sig_rewrite(void) {
    extern void* class_getClassMethod(void*, void*);
    extern void* method_getImplementation(void*);
    extern const char* method_getTypeEncoding(void*);
    extern void* method_setImplementation(void*, void*);
    id msCls = (id)objc_getClass("NSMethodSignature");
    void* m = class_getClassMethod(msCls, sel_registerName("signatureWithObjCTypes:"));
    if (m) {
        orig_sig_imp = (void*(*)(void*,void*,const char*))method_getImplementation(m);
        method_setImplementation(m, (void*)my_sig_imp);
        net_report("SWZ:", "sig_rewrite_installed");
    }
}
extern void _XCTSetXPCRequestTimeout(double);
extern void _XCTSetApplicationStateTimeout(double);
static void ensure_registered(const char* tag) {
    _XCTSetXPCRequestTimeout(7.0); /* 必须早于 10s scene 看门狗唤醒主线程 */
    _XCTSetApplicationStateTimeout(60.0);
    if (g_reg) return;
    g_reg = 1;
    marker(tag);
    NSSetUncaughtExceptionHandler((void*)exc_handler);
    atexit(bye);
    { int sigs[10]; sigs[0]=2; sigs[1]=5; sigs[2]=6; sigs[3]=8; sigs[4]=10; sigs[5]=11; sigs[6]=13; sigs[7]=15; sigs[8]=24; sigs[9]=31;
      for (int i = 0; i < 10; i++) signal(sigs[i], (void*)sig_handler); }
    { unsigned long th[32]; pthread_create(th, 0, beat_thread, 0); pthread_detach(th); }
    fix_xctestdriver();
}

void shim_objc_exception_throw(id exc) {
    exc_handler(exc);
    objc_exception_throw(exc);
}
__attribute__((used)) static struct { const void* rep; const void* orig; } g_interpose_throw
__attribute__((section("__DATA,__interpose"))) = { (const void*)&shim_objc_exception_throw, (const void*)&objc_exception_throw };

extern id objc_retainAutoreleasedReturnValue(id);
__attribute__((used)) id objc_claimAutoreleasedReturnValue(id v) {
    ensure_registered("claim_called");
    start_server_direct();
    return objc_retainAutoreleasedReturnValue(v);
}

extern int UIApplicationMain(int, void*, void*, void*);
extern void* class_getInstanceMethod(void*, void*);
extern void* method_setImplementation(void*, void*);
extern const char* method_getTypeEncoding(void*);
extern const char* sel_getName(void*);
extern void** class_copyMethodList(void*, unsigned int*);
extern void* method_getName(void*);
extern char* strstr(const char*, const char*);
extern void* object_getClass(id);
static char (*orig_didFinish)(id, void*, id, id);
static void (*orig_runBg)(id, void*, char);
static void (*orig_bundleWillStart)(id, void*, id);
static id (*orig_suiteForBundle)(void*, void*, id);

static void shim_exit(int code);
static char hook_didFinish(id self, void* _cmd, id app, id opts) {
    net_report("HOOK:", "didFinish ENTER");
    make_window(); /* 主线程建窗 */
    net_report("WIN:", "first");
    { unsigned long th9[32]; pthread_create(th9, 0, mon_thread, 0); pthread_detach(th9); }
    net_report("MONT:", "dispatched");
    return 0;
    char r = 0;
    if (orig_didFinish) r = orig_didFinish(self, _cmd, app, opts);
    net_report("HOOK:", "didFinish DONE");
    return r;
}
static void hook_runBg(id self, void* _cmd, char v) {
    net_report("HOOK:", v ? "runBg ENTER(1)" : "runBg ENTER(0)");
    if (orig_runBg) orig_runBg(self, _cmd, v);
    net_report("HOOK:", "runBg DONE");
}
static void hook_bundleWillStart(id self, void* _cmd, id bundle) {
    net_report("HOOK:", "testBundleWillStart FIRING");
    if (orig_bundleWillStart) orig_bundleWillStart(self, _cmd, bundle);
}
static id hook_suiteForBundle(void* cls, void* _cmd, id path) {
    net_report("HOOK:", "testSuiteForBundlePath CALLED");
    id r = orig_suiteForBundle ? orig_suiteForBundle(cls, _cmd, path) : 0;
    net_report("HOOK:", r ? "suite NON-NULL" : "suite NULL");
    return r;
}
extern void* class_getInstanceMethod(void*, void*);
static long my_yes(id self, void* sel) { (void)self; (void)sel; return 1; }
static void install_uitest_gate(void) {
    static int done = 0;
    if (done) return;
    void* m = class_getInstanceMethod((id)objc_getClass("XCUIDevice"), sel_registerName("configuredForUITesting"));
    if (m) {
        method_setImplementation(m, (void*)my_yes);
        done = 1;
        net_report("GATE:", "configuredForUITesting=YES");
    } else net_report("GATE:", "no_such_method");
}
static void install_hooks(void) {
    install_uitest_gate();
    install_delegate_stubs();
    void* delCls = objc_getClass("_XCTRunnerAppDelegate");
    if (!delCls) { net_report("HOOK:", "no_delegate_class"); return; }
    net_report("HOOK:", "delegate_class_found");
    void* m = class_getInstanceMethod(delCls, sel_registerName("application:didFinishLaunchingWithOptions:"));
    if (m) { orig_didFinish = (void*)method_setImplementation(m, (void*)hook_didFinish); net_report("HOOK:", "didFinish hooked"); }
    m = class_getInstanceMethod(delCls, sel_registerName("runTestsInBackground:"));
    if (m) { orig_runBg = (void*)method_setImplementation(m, (void*)hook_runBg); net_report("HOOK:", "runBg hooked"); }
    m = class_getInstanceMethod(delCls, sel_registerName("testBundleWillStart:"));
    if (m) { orig_bundleWillStart = (void*)method_setImplementation(m, (void*)hook_bundleWillStart); net_report("HOOK:", "bundleWillStart hooked"); }
    void* suiteCls = objc_getClass("XCTestSuite");
    if (suiteCls) {
        void* meta = object_getClass((id)suiteCls);
        void* cm = class_getInstanceMethod(meta, sel_registerName("testSuiteForBundlePath:"));
        if (cm) { orig_suiteForBundle = (void*)method_setImplementation(cm, (void*)hook_suiteForBundle); net_report("HOOK:", "suiteForBundle hooked"); }
    }
}

/* ---- exit interpose ---- */
extern void exit(int);
extern void _exit(int);
extern long write(int, const void*, unsigned long);
static void hexv(char* buf, unsigned long v) {
    const char* hd = "0123456789abcdef";
    buf[0]='0'; buf[1]='x';
    for (int i = 0; i < 16; i++) buf[2+i] = hd[(v >> ((15-i)*4)) & 0xF];
    buf[18] = 0;
}
static void shim_exit(int code) {
    static int g_parked = 0;
    if (g_parked) { for (;;) { sleep(60); } }
    g_parked = 1;
    char m[64]; char n[20];
    m[0]='c'; m[1]='o'; m[2]='d'; m[3]='e'; m[4]='=';
    hexv(n, (unsigned long)code);
    int i=0; while(n[i]){ m[5+i]=n[i]; i++; }
    m[5+i]=' '; m[6+i]='l'; m[7+i]='r'; m[8+i]='=';
    hexv(n, (unsigned long)__builtin_return_address(0));
    int j=0; while(n[j]){ m[9+i+j]=n[j]; j++; }
    m[9+i+j]=0;
    net_report("EXIT_PARKED:", m);
    /* 正规链：beginMonitoring 注册跟踪 + 状态快照喂食（单对象 API 已验证） */
    install_spec_hook();
    net_report("MON:", "step_getclass");
    {
        id sesCls = (id)objc_getClass("XCTRunnerDaemonSession");
        id s2 = ((id(*)(id,void*))objc_msgSend)(sesCls, sel_registerName("sharedSession"));
        net_report("MON:", s2 ? "session_ok" : "session_nil");
        if (s2) {
            /* ★装载守护的 AX（此血统此前从未调用——一切快照失败的总根） */
            ((void(*)(id,void*))objc_msgSend)(s2, sel_registerName("finishInitializationForUIAutomation"));
            net_report("AXL:", "finishInit");
            long hasLA = (long)((void*(*)(id,void*,void*))objc_msgSend)(s2, sel_registerName("respondsToSelector:"), sel_registerName("loadAccessibilityWithTimeout:reply:"));
            net_report("AXL:", hasLA ? "has_loadAcc" : "no_loadAcc");
            if (hasLA) {
                ((void(*)(id,void*,double,void*))objc_msgSend)(s2, sel_registerName("loadAccessibilityWithTimeout:reply:"), 30.0, &g_replyblk);
                net_report("AXL:", "loadAcc_sent");
            }
        }
        id bid2 = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.apple.springboard");
        if (s2) {
            long hasBM = (long)((void*(*)(id,void*,void*))objc_msgSend)(s2, sel_registerName("respondsToSelector:"), sel_registerName("beginMonitoringApplicationWithSpecifier:"));
            net_report("MON:", hasBM ? "has_beginMon" : "no_beginMon");
            if (hasBM) {
                id specCls = (id)objc_getClass("XCUIApplicationSpecifier");
                net_report("MON:", specCls ? "spec_cls_ok" : "spec_cls_nil");
                if (specCls) {
                    id spec = ((id(*)(id,void*,id,id))objc_msgSend)(specCls, sel_registerName("specifierWithBundleIdentifier:path:"), bid2, 0);
                    if (spec) { long hp = (long)((void*(*)(id,void*,void*))objc_msgSend)(spec, sel_registerName("respondsToSelector:"), sel_registerName("setPid:")); if (hp) ((void(*)(id,void*,long long))objc_msgSend)(spec, sel_registerName("setPid:"), 10040LL); }
                    net_report("MON:", spec ? "spec_ok" : "spec_nil");
                    if (spec) {
                        net_report("MON:", "beginMon_SKIPPED");
                    }
                }
            }
        }
        /* 状态快照喂食：352 + pid 0（系统占位）都归到 springboard */
        id devCls = (id)objc_getClass("XCUIDevice");
        id dev = ((id(*)(id,void*))objc_msgSend)(devCls, sel_registerName("sharedDevice"));
        id mon = dev ? ((id(*)(id,void*))objc_msgSend)(dev, sel_registerName("applicationMonitor")) : 0;
        net_report("MON:", mon ? "monitor_ok" : "monitor_nil");
        id snapCls = (id)objc_getClass("XCTApplicationStateSnapshot");
        if (!snapCls) snapCls = (id)objc_getClass("XCUIApplicationStateSnapshot");
        net_report("MON:", snapCls ? "snap_cls_ok" : "snap_cls_nil");
        if (snapCls) {
            long hasInit = (long)((void*(*)(id,void*,void*))objc_msgSend)(snapCls, sel_registerName("instancesRespondToSelector:"), sel_registerName("initWithBundleID:path:runState:processID:activationPolicy:eventID:"));
            net_report("MON:", hasInit ? "has_snap_init" : "no_snap_init");
        }
        if (mon && snapCls) {
            long hasUpd = (long)((void*(*)(id,void*,void*))objc_msgSend)(mon, sel_registerName("respondsToSelector:"), sel_registerName("updatedApplicationStateSnapshot:"));
            net_report("MON:", hasUpd ? "has_upd" : "no_upd");
            if (hasUpd) {
                int pids[2]; pids[0] = 352; pids[1] = 0;
                for (int z = 0; z < 2; z++) {
                    id snap = ((id(*)(id,void*,id,id,long long,int,long long,long long))objc_msgSend)(((id(*)(void*,void*))objc_msgSend)(snapCls, sel_registerName("alloc")), sel_registerName("initWithBundleID:path:runState:processID:activationPolicy:eventID:"), bid2, 0, 4LL, pids[z], 0LL, (long long)(z + 1));
                    net_report("MON:", snap ? "snap_built" : "snap_nil");
                    if (snap) {
                        ((void(*)(id,void*,id))objc_msgSend)(mon, sel_registerName("updatedApplicationStateSnapshot:"), snap);
                        net_report("MON:", "snap_fed");
                    }
                }
            }
        }
        /* 兜底：旧通道喂 state=4 */
        if (s2) {
            int mypid4 = raw3(20, 0, 0, 0);
            id bidself = ((id(*)(void*,void*,const char*))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "com.facebook.WebDriverAgentRunner.xctrunner");
            ((void(*)(id,void*,int,id,unsigned long long))objc_msgSend)(s2, sel_registerName("daemonDidUpdatePID:forApplicationWithBundleID:andState:"), 0, bid2, 4ULL);
            ((void(*)(id,void*,int,id,unsigned long long))objc_msgSend)(s2, sel_registerName("daemonDidUpdatePID:forApplicationWithBundleID:andState:"), 352, bid2, 4ULL);
            ((void(*)(id,void*,id,int,unsigned long long))objc_msgSend)(s2, sel_registerName("_XCT_applicationWithBundleID:didUpdatePID:andState:"), bid2, 352, 4ULL);
            ((void(*)(id,void*,int,id,unsigned long long))objc_msgSend)(s2, sel_registerName("daemonDidUpdatePID:forApplicationWithBundleID:andState:"), mypid4, bidself, 4ULL);
            net_report("MON:", "fed_352_self_state4");
        }
        { unsigned long th2[32]; pthread_create(th2, 0, dump_thread, 0); pthread_detach(th2); unsigned long th3[32]; pthread_create(th3, 0, feed_thread, 0); pthread_detach(th3); net_report("DUMP:", "armed"); }
    }
    /* 建窗口满足 scene-create 看门狗 */
    {
        typedef struct { double a, b, c, d; } Rect4;
        Rect4 r = {0, 0, 375, 667};
        void* wcls = objc_getClass("UIWindow");
        void* vcls = objc_getClass("UIViewController");
        if (wcls && vcls) {
            id win = ((id(*)(void*,void*,Rect4))objc_msgSend)(((id(*)(void*,void*))objc_msgSend)((id)wcls, sel_registerName("alloc")), sel_registerName("initWithFrame:"), r);
            id vc = ((id(*)(void*,void*))objc_msgSend)((id)vcls, sel_registerName("new"));
            ((void(*)(id,void*,id))objc_msgSend)(win, sel_registerName("setRootViewController:"), vc);
            ((void(*)(id,void*))objc_msgSend)(win, sel_registerName("makeKeyAndVisible"));
            net_report("EXIT_PARKED:", "window_created");
        }
    }
    void* rlcls = objc_getClass("NSRunLoop");
    if (rlcls) {
        id rl = ((id(*)(void*,void*))objc_msgSend)((id)rlcls, sel_registerName("mainRunLoop"));
        net_report("EXIT_PARKED:", "pumping_runloop");
        ((void(*)(id,void*))objc_msgSend)(rl, sel_registerName("run"));
    }
    for (;;) { sleep(60); }
}
static void shim_exit2(int code) { shim_exit(code); }
__attribute__((used)) static struct { const void* rep; const void* orig; } g_int_exit
__attribute__((section("__DATA,__interpose"))) = { (const void*)&shim_exit, (const void*)&exit };
__attribute__((used)) static struct { const void* rep; const void* orig; } g_int_exit2
__attribute__((section("__DATA,__interpose"))) = { (const void*)&shim_exit2, (const void*)&_exit };

/* ---- method inventory ---- */
extern void** class_copyMethodList(void*, unsigned int*);
extern void* method_getName(void*);
extern const char* sel_getName(void*);
extern void* objc_getClass(const char*);

static id (*orig_shared)(void*, void*);
static id hook_shared(void* cls, void* _cmd) {
    net_report("HOOK:", "sharedSession CALLED");
    return orig_shared ? orig_shared(cls, _cmd) : 0;
}

static void dump_methods(void* cls, const char* tag) {
    unsigned int n = 0;
    void** ms = class_copyMethodList(cls, &n);
    net_report(tag, "method count dump");
    for (unsigned int i = 0; i < n && i < 40; i++) {
        const char* nm = sel_getName(method_getName(ms[i]));
        net_report("  M:", nm ? nm : "?");
    }
}

extern int atexit(void (*)(void));

static void inventory(void) {
    void* del = objc_getClass("_XCTRunnerAppDelegate");
    if (del) dump_methods(del, "INV:delegate");
    void* ses = objc_getClass("XCTRunnerDaemonSession");
    if (ses) {
        dump_methods(ses, "INV:session");
        void* meta = object_getClass((id)ses);
        void* m = class_getInstanceMethod(meta, sel_registerName("sharedSession"));
        if (m) { orig_shared = (void*)method_setImplementation(m, (void*)hook_shared); net_report("HOOK:", "sharedSession hooked"); }
    }
}

__attribute__((used)) void exc_init(void) {
    ensure_registered("constructor_ran_stock2");
    install_hooks();
}
__attribute__((used)) static void (*const g_init_entry)(void) __attribute__((section("__DATA,__mod_init_func"))) = exc_init;
__attribute__((naked)) void objc_retain_x1(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x1\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x2(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x2\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x3(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x3\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x4(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x4\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x5(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x5\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x6(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x6\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x7(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x7\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x8(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x8\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x9(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x9\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x10(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x10\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x19(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x19\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x20(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x20\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x21(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x21\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x22(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x22\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x23(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x23\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x24(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x24\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x25(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x25\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x26(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x26\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x27(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x27\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_retain_x28(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x28\n"
        "bl _objc_retain\n"
        "str x0, [sp, #0]\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x1(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x1\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x8(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x8\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x9(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x9\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x19(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x19\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x20(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x20\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x21(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x21\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x22(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x22\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x23(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x23\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x24(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x24\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x25(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x25\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x26(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x26\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x27(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x27\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}
__attribute__((naked)) void objc_release_x28(void) {
    __asm__ volatile(
        "sub sp, sp, #160\n"
        "stp x0, x1, [sp, #0]\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x4, x5, [sp, #32]\n"
        "stp x6, x7, [sp, #48]\n"
        "stp x8, x9, [sp, #64]\n"
        "stp x10, x11, [sp, #80]\n"
        "stp x12, x13, [sp, #96]\n"
        "stp x14, x15, [sp, #112]\n"
        "stp x16, x17, [sp, #128]\n"
        "str x30, [sp, #144]\n"
        "mov x0, x28\n"
        "bl _objc_release\n"
        "ldp x0, x1, [sp, #0]\n"
        "ldp x2, x3, [sp, #16]\n"
        "ldp x4, x5, [sp, #32]\n"
        "ldp x6, x7, [sp, #48]\n"
        "ldp x8, x9, [sp, #64]\n"
        "ldp x10, x11, [sp, #80]\n"
        "ldp x12, x13, [sp, #96]\n"
        "ldp x14, x15, [sp, #112]\n"
        "ldp x16, x17, [sp, #128]\n"
        "ldr x30, [sp, #144]\n"
        "add sp, sp, #160\n"
        "ret\n"
    );
}

static void start_server_direct(void) {
    if (g_srv) return;
    net_report("SRV:", "enter");
    const char* img0 = _dyld_get_image_name(0);
    net_report("IMG0:", img0 ? img0 : "(null)");
    void* nsc = objc_getClass("NSBundle");
    if (!nsc) { net_report("SRV:", "no_NSBundle"); return; }
    id b = ((id(*)(void*, void*))objc_msgSend)(nsc, sel_registerName("mainBundle"));
    id bp = ((id(*)(id, void*))objc_msgSend)(b, sel_registerName("bundlePath"));
    const char* base = ((const char*(*)(id, void*))objc_msgSend)(bp, sel_registerName("UTF8String"));
    if (!base) { net_report("SRV:", "no_bundle_path"); return; }
    net_report("BUNDLE:", base);
    char p[600]; int i = 0;
    while (base[i]) { p[i] = base[i]; i++; }
    const char* suf = "/PlugIns/WebDriverAgentRunner.xctest/Frameworks/WebDriverAgentLib.framework/WebDriverAgentLib";
    int j = 0; while (suf[j]) p[i++] = suf[j++];
    p[i] = 0;
    net_report("SRV:", "pre_dlopen");
    void* h = dlopen(p, 1);
    if (!h) { char* e = dlerror(); net_report("SRV_DLOPEN:", e ? e : "fail"); return; }
    net_report("SRV_DLOPEN:", "ok");
    install_routeq_hook();
    void* cls = objc_getClass("FBWebServer");
    if (!cls) { net_report("SRV:", "no_class"); return; }
    net_report("SRV:", "got_class");
    id ws = ((id(*)(void*, void*))objc_msgSend)(cls, sel_registerName("alloc"));
    ws = ((id(*)(id, void*))objc_msgSend)(ws, sel_registerName("init"));
    net_report("SRV:", "inited");
    ((void(*)(id, void*))objc_msgSend)(ws, sel_registerName("startServing"));
    g_srv = 1;
    net_report("SRV:", "startServing_called");
}

static void* find_method(void* cls, const char* selname) {
    if (!cls) return 0;
    return class_getInstanceMethod(cls, sel_registerName(selname));
}
static void dump_ses_methods(void) {
    void* ses = objc_getClass("XCTRunnerDaemonSession");
    if (!ses) { net_report("SES:", "class_missing"); return; }
    unsigned int n = 0;
    void** ms = class_copyMethodList(ses, &n);
    net_report("SES:count", n < 10 ? "0-9" : ">=10");
    for (unsigned int i = 0; i < n && i < 60; i++) {
        const char* nm = sel_getName(method_getName(ms[i]));
        net_report("SES_M:", nm ? nm : "?");
    }
}



static void ax_init_try(void) {
    dump_ses_methods();
    void* ses = objc_getClass("XCTRunnerDaemonSession");
    if (!ses) return;
    id s = ((id(*)(void*,void*))objc_msgSend)((id)ses, sel_registerName("sharedSession"));
    net_report("AX2:", s ? "shared_ok" : "shared_nil");
    if (!s) return;
    void* m = class_getInstanceMethod(ses, sel_registerName("finishInitializationForUIAutomation"));
    if (m) {
        ((void(*)(id,void*))objc_msgSend)(s, sel_registerName("finishInitializationForUIAutomation"));
        net_report("AX2:", "finishInit_done");
    }
    /* 找 enableAutomation 相关方法并尝试调用 */
    {
        unsigned int n = 0;
        void** ms = class_copyMethodList(ses, &n);
        for (unsigned int i = 0; i < n; i++) {
            const char* nm = sel_getName(method_getName(ms[i]));
            if (nm && (strstr(nm, "utomation") || strstr(nm, "uthoriz"))) {
                net_report("FIND_M:", nm);
                if (strstr(nm, "nable") && strstr(nm, "utomation")) {
                    net_report("AX4:", "calling_enable_automation");
                    void (*fn)(id, void*, void*) = (void(*)(id,void*,void*))objc_msgSend;
                    fn(s, sel_registerName(nm), &g_replyblk);
                    net_report("AX4:", "enable_automation_returned");
                }
            }
        }
    }
    void* m2 = class_getInstanceMethod(ses, sel_registerName("loadAccessibilityWithTimeout:reply:"));
    if (m2) {
        const char* enc = method_getTypeEncoding(m2);
        net_report("ENC:loadAcc:", enc ? enc : "none");
        net_report("AX3:", "calling_loadAccessibility");
        ((void(*)(id,void*,double,void*))objc_msgSend)(s, sel_registerName("loadAccessibilityWithTimeout:reply:"), 5.0, &g_replyblk);
        net_report("AX3:", "loadAccessibility_returned");
    }
    const char* selname = "finishInitializationForUIAutomation";
    void* cands[3];
    cands[0] = objc_getClass("_XCTRunnerAppDelegate");
    cands[1] = objc_getClass("XCTRunnerDaemonSession");
    cands[2] = 0;
    for (int i = 0; i < 2; i++) {
        void* cls = cands[i];
        if (!cls) continue;
        void* m = find_method(cls, selname);
        char tag[40];
        const char* nm = i == 0 ? "AX:del_has" : "AX:ses_has";
        net_report(nm, m ? "yes" : "no");
        if (m) {
            id inst = ((id(*)(void*,void*))objc_msgSend)((id)cls, sel_registerName("alloc"));
            inst = ((id(*)(id,void*))objc_msgSend)(inst, sel_registerName("init"));
            net_report("AX:", inst ? "inst_ok" : "inst_fail");
            if (inst) {
                ((void(*)(id,void*))objc_msgSend)(inst, sel_registerName(selname));
                net_report("AX:", "finishInit_called");
            }
        }
    }
}
