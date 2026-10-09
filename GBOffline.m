// GBOffline.m - in-process "virtual server" for Gunship Battle (Joycity/Joyple backend is dead).
//
// No real server and no local server process: requests to the dead hosts are answered from
// local files by code running inside the game itself.
//
//  Layer 1 (NSURLProtocol)  : catches NSURLConnection / NSURLSession traffic (Joyple SDK, HTTPS).
//  Layer 2 (libc interpose) : dead hostnames resolve to 127.77.0.1; connect() to that address (or the
//                             hardcoded 61.43.46.177) is swapped for a socketpair whose other end is
//                             served by a tiny HTTP responder thread. Covers Marmalade's s3eSocket/s3eHTTP
//                             lobby traffic (gunship-lb...:8000, plain HTTP).
//  Every request is logged to Documents/gb_capture.log so you can see what the game asks for.
//
// Routes: gb_routes.json (Documents/ overrides the app bundle). See README.md.
//
// Build: xcrun -sdk iphoneos clang -arch arm64 -dynamiclib -fobjc-arc -framework Foundation \
//        -miphoneos-version-min=10.0 -o GBOffline.dylib GBOffline.m

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <pthread.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#include "gb_keyscan.h"

#pragma mark - Config / logging

static NSArray<NSString *> *gHosts;
static NSDictionary *gDefault;
static NSArray<NSDictionary *> *gRoutes;
static NSString *gStubDir;
static NSString *gLogPath;
static struct in_addr gDeadIP;               // 61.43.46.177
static NSLock *gLock;
static BOOL gScanEnabled = YES;
static BOOL gDumpEnabled = NO;
static BOOL gHookVersion = YES;
static int gCryptoLogBudget = 600;
static NSMutableSet *gSeenDNS;

static void GBLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void GBLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *line = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], msg];
    [gLock lock];
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:gLogPath];
    if (!h) { [[NSFileManager defaultManager] createFileAtPath:gLogPath contents:nil attributes:nil];
              h = [NSFileHandle fileHandleForWritingAtPath:gLogPath]; }
    [h seekToEndOfFile];
    [h writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    [h closeFile];
    [gLock unlock];
}

static void GBLoadConfig(void) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *res = [[NSBundle mainBundle] resourcePath];
    BOOL inDocs = [[NSFileManager defaultManager] fileExistsAtPath:[docs stringByAppendingPathComponent:@"gb_routes.json"]];
    gStubDir = inDocs ? docs : res;
    NSData *d = [NSData dataWithContentsOfFile:[gStubDir stringByAppendingPathComponent:@"gb_routes.json"]];
    NSDictionary *cfg = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
    gHosts = cfg[@"hosts"] ?: @[@"joycity.com", @"joycityplay.com", @"joycityglobal.com", @"61.43.46.177"];
    gDefault = cfg[@"default"] ?: @{@"status": @200, @"content_type": @"application/json", @"body": @"{\"result\":0}"};
    gRoutes = cfg[@"routes"] ?: @[];
    gLogPath = [docs stringByAppendingPathComponent:@"gb_capture.log"];
    if (cfg[@"scan_key"]) gScanEnabled = [cfg[@"scan_key"] boolValue];
    if (cfg[@"dump_segments"]) gDumpEnabled = [cfg[@"dump_segments"] boolValue];
    if (cfg[@"hook_checkversion"]) gHookVersion = [cfg[@"hook_checkversion"] boolValue];
    inet_pton(AF_INET, "61.43.46.177", &gDeadIP);
}

static BOOL GBHostIsDead(NSString *h) {
    if (!h.length) return NO;
    h = h.lowercaseString;
    for (NSString *s in gHosts)
        if ([h isEqualToString:s] || [h hasSuffix:[@"." stringByAppendingString:s]]) return YES;
    return NO;
}


#pragma mark - Key finder (memory scan) and CommonCrypto trace

static NSString *GBHex(const void *p, size_t n, size_t max) {
    if (!p) return @"(null)";
    NSMutableString *h = [NSMutableString string]; const uint8_t *b = p;
    for (size_t i = 0; i < n && i < max; i++) [h appendFormat:@"%02x", b[i]];
    if (n > max) [h appendFormat:@"...(%zu bytes)", n];
    return h;
}
static NSString *GBText(const void *p, size_t n, size_t max) {
    if (!p) return @"(null)";
    NSMutableString *h = [NSMutableString string]; const uint8_t *b = p;
    for (size_t i = 0; i < n && i < max; i++) [h appendFormat:@"%c", (b[i] >= 32 && b[i] < 127) ? b[i] : '.'];
    return h;
}

static uint8_t gScanCT[1024]; static size_t gScanCTLen; static BOOL gScanStarted;

static void GBScanHit(const uint8_t *key, int klen, const char *how, const uint8_t *plain, size_t plen, size_t off, void *ud) {
    GBLog(@"[KEYSCAN] HIT (%s) AES-%d key=%@  ascii=%@  at 0x%lx\n    decrypted blocks 1..n: %@",
          how, klen * 8, GBHex(key, klen, 32), GBText(key, klen, 32), (unsigned long)((uintptr_t)ud + off), GBText(plain, plen, 200));
}

static void *GBScanThread(void *arg) {
    pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0);
    gb_aes_init();
    GBLog(@"[keyscan] scanning writable memory for the AES key (one time, can take a few minutes)...");
    static uint8_t buf[(1 << 20) + 64];
    vm_address_t addr = 0; size_t total = 0, nextLog = 64u << 20;
    for (;;) {
        vm_size_t size = 0; vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64; mach_port_t obj;
        if (vm_region_64(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE) && size <= ((vm_size_t)1 << 30)) {
            for (vm_size_t o = 0; o < size; o += (1 << 20)) {
                vm_size_t want = MIN((vm_size_t)((1 << 20) + 32), size - o), got = 0;
                if (vm_read_overwrite(mach_task_self(), addr + o, want, (vm_address_t)buf, &got) != KERN_SUCCESS || got < 16) continue;
                gb_scan_buffer(buf, got, gScanCT, gScanCTLen, 4, GBScanHit, (void *)(addr + o));
                total += got;
                if (total >= nextLog) { GBLog(@"[keyscan] progress: %zu MB scanned", total >> 20); nextLog += 64u << 20; }
            }
        }
        addr += size;
    }
    GBLog(@"[keyscan] finished, scanned %zu MB of writable memory", total >> 20);
    return NULL;
}

// Called with every lobby request body; the first encrypted {"PayLoad":"..."} starts the one-time scan.
static void GBMaybeStartScan(NSData *body) {
    if (!gScanEnabled || gScanStarted || !body.length) return;
    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:body options:0 error:nil];
    NSString *pl = [j isKindOfClass:[NSDictionary class]] ? j[@"PayLoad"] : nil;
    if (![pl isKindOfClass:[NSString class]]) return;
    NSData *ct = [[NSData alloc] initWithBase64EncodedString:pl options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (ct.length < 32 || ct.length % 16 || ct.length > sizeof gScanCT) return;
    memcpy(gScanCT, ct.bytes, ct.length); gScanCTLen = ct.length; gScanStarted = YES;
    pthread_t t; pthread_create(&t, NULL, GBScanThread, NULL); pthread_detach(t);
}

// CommonCrypto trace: shows key / iv / data for every call (many come from ad SDKs; capped).
static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions opts, const void *key, size_t kl, const void *iv,
                                  const void *in, size_t inl, void *out, size_t outl, size_t *moved) {
    CCCryptorStatus r = CCCrypt(op, alg, opts, key, kl, iv, in, inl, out, outl, moved);
    if (gCryptoLogBudget > 0) { gCryptoLogBudget--;
        GBLog(@"[crypto] CCCrypt op=%d alg=%d opts=%d status=%d\n    key(%zu)=%@ ascii=%@\n    iv=%@\n    in(%zu)=%@\n    out=%@ ascii=%@",
              (int)op, (int)alg, (int)opts, (int)r, kl, GBHex(key, kl, 32), GBText(key, kl, 32), GBHex(iv, iv ? 16 : 0, 16), inl, GBHex(in, inl, 64),
              GBHex(out, moved ? *moved : 0, 64), GBText(out, moved ? *moved : 0, 120)); }
    return r;
}
static CCCryptorStatus my_CCCryptorCreateWithMode(CCOperation op, CCMode mode, CCAlgorithm alg, CCPadding pad, const void *iv,
        const void *key, size_t kl, const void *tweak, size_t tl, int rounds, CCModeOptions mopts, CCCryptorRef *ref) {
    if (gCryptoLogBudget > 0) { gCryptoLogBudget--;
        GBLog(@"[crypto] CCCryptorCreateWithMode op=%d mode=%d alg=%d pad=%d\n    key(%zu)=%@ ascii=%@\n    iv=%@", (int)op, (int)mode, (int)alg, (int)pad,
              kl, GBHex(key, kl, 32), GBText(key, kl, 32), GBHex(iv, iv ? 16 : 0, 16)); }
    return CCCryptorCreateWithMode(op, mode, alg, pad, iv, key, kl, tweak, tl, rounds, mopts, ref);
}
static CCCryptorStatus my_CCCryptorUpdate(CCCryptorRef ref, const void *in, size_t inl, void *out, size_t outl, size_t *moved) {
    CCCryptorStatus r = CCCryptorUpdate(ref, in, inl, out, outl, moved);
    if (gCryptoLogBudget > 0) { gCryptoLogBudget--;
        GBLog(@"[crypto] CCCryptorUpdate in(%zu)=%@ out=%@ ascii=%@", inl, GBHex(in, inl, 48), GBHex(out, moved ? *moved : 0, 48), GBText(out, moved ? *moved : 0, 96)); }
    return r;
}
static unsigned char *my_CC_MD5(const void *d, CC_LONG l, unsigned char *md) {
    unsigned char *r = CC_MD5(d, l, md);
    if (gCryptoLogBudget > 0) { gCryptoLogBudget--; GBLog(@"[crypto] MD5(%@) = %@", GBText(d, l, 96), GBHex(md, 16, 16)); }
    return r;
}
static unsigned char *my_CC_SHA1(const void *d, CC_LONG l, unsigned char *md) {
    unsigned char *r = CC_SHA1(d, l, md);
    if (gCryptoLogBudget > 0) { gCryptoLogBudget--; GBLog(@"[crypto] SHA1(%@) = %@", GBText(d, l, 96), GBHex(md, 20, 20)); }
    return r;
}
static unsigned char *my_CC_SHA256(const void *d, CC_LONG l, unsigned char *md) {
    unsigned char *r = CC_SHA256(d, l, md);
    if (gCryptoLogBudget > 0) { gCryptoLogBudget--; GBLog(@"[crypto] SHA256(%@) = %@", GBText(d, l, 96), GBHex(md, 32, 32)); }
    return r;
}


#pragma mark - Runtime segment dump (Marmalade unpacks __S3E_DATA only in memory)

static void GBDumpSegments(void) {
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSMutableString *info = [NSMutableString stringWithFormat:@"main image slide=0x%lx\n", (long)slide];
    const char *segs[] = {"__S3E_DATA", "__S3E_META", "__DATA"};
    for (int i = 0; i < 3; i++) {
        unsigned long sz = 0;
        uint8_t *p = getsegmentdata(mh, segs[i], &sz);
        if (!p || !sz) { [info appendFormat:@"%s: not found\n", segs[i]]; continue; }
        NSData *d = [NSData dataWithBytes:p length:sz];
        NSString *path = [docs stringByAppendingPathComponent:[NSString stringWithFormat:@"gb_dump%s.bin", segs[i]]];
        BOOL ok = [d writeToFile:path atomically:YES];
        [info appendFormat:@"%s: runtime=0x%lx unslid=0x%lx size=0x%lx written=%d\n", segs[i], (unsigned long)p, (unsigned long)((intptr_t)p - slide), sz, ok];
    }
    [info writeToFile:[docs stringByAppendingPathComponent:@"gb_dump_info.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    GBLog(@"[dump] %@", info);
}


#pragma mark - Version-check bypass (data patch: swaps one vtable pointer, no code is modified)

static uintptr_t gSlide;

// Replacement for the game's checkVersion reply callback (original code at 0x100afabd0, unslid).
// The original sets the game state to 6 when the reply is valid and shows the "download the latest
// version" popup otherwise. This does what the success path does: state = 6.
static void GBCheckVersionDone(void *req, int err, void *resp) {
    uintptr_t *slot = (uintptr_t *)(0x100d7b4f8 + gSlide);      // slot holding &gameObjectPtr
    uintptr_t *var = slot ? (uintptr_t *)*slot : NULL;
    char *obj = var ? (char *)*var : NULL;                       // the game singleton
    if (obj) *(int *)(obj + 0x1b000 + 0x5a0) = 6;
    GBLog(@"[patch] checkVersion callback intercepted (err=%d, obj=%p) -> game state 6", err, obj);
}

// __S3E_DATA is unpacked by the engine after dyld loads us, so wait until the slot holds the original pointer.
static void *GBVtableThread(void *arg) {
    uintptr_t slotAddr = 0x100d68d50 + gSlide, orig = 0x100afabd0 + gSlide;
    for (int i = 0; i < 2400; i++) {                             // up to ~2 minutes
        if (*(volatile uintptr_t *)slotAddr == orig) {
            size_t pg = (size_t)getpagesize();
            kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)(slotAddr & ~(pg - 1)), pg, FALSE, VM_PROT_READ | VM_PROT_WRITE);
            *(volatile uintptr_t *)slotAddr = (uintptr_t)&GBCheckVersionDone;
            GBLog(@"[patch] vtable slot 0x%lx swapped (vm_protect=%d)", (unsigned long)slotAddr, (int)kr);
            return NULL;
        }
        usleep(50000);
    }
    GBLog(@"[patch] vtable slot never held the expected callback (0x%lx) - NOT patched", (unsigned long)orig);
    return NULL;
}

#pragma mark - Router (shared by both layers)

static NSData *GBRoute(NSString *src, NSString *method, NSString *host, NSString *pathq,
                       NSData *body, NSInteger *status, NSString **ctype) {
    NSString *bodyStr = body.length ? ([[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding]
                                       ?: [NSString stringWithFormat:@"<binary %lu bytes: %@>", (unsigned long)body.length,
                                           [[body subdataWithRange:NSMakeRange(0, MIN(body.length, 64))] description]])
                                      : @"";
    NSDictionary *hit = nil;
    for (NSDictionary *r in gRoutes) {
        NSString *m = r[@"match"];         if (m  && ![pathq containsString:m]) continue;
        NSString *bc = r[@"body_contains"]; if (bc && ![bodyStr containsString:bc]) continue;
        NSString *me = r[@"method"];       if (me && ![me.uppercaseString isEqualToString:method.uppercaseString]) continue;
        hit = r; break;
    }
    NSDictionary *spec = hit ?: gDefault;
    NSData *out = nil;
    NSString *file = spec[@"file"];
    if (file) out = [NSData dataWithContentsOfFile:[gStubDir stringByAppendingPathComponent:file]];
    if (!out) out = [(spec[@"body"] ?: @"") dataUsingEncoding:NSUTF8StringEncoding];
    *status = [spec[@"status"] integerValue] ?: 200;
    *ctype = spec[@"content_type"] ?: @"application/json";
    GBLog(@"[%@] %@ %@%@ -> %@ (%ld, %lu bytes)\n    req body: %@", src, method, host ?: @"?", pathq,
          hit ? @"ROUTE" : @"DEFAULT", (long)*status, (unsigned long)out.length,
          bodyStr.length > 2000 ? [bodyStr substringToIndex:2000] : bodyStr);
    return out;
}

#pragma mark - Layer 1: NSURLProtocol

@interface GBProto : NSURLProtocol
@end
@implementation GBProto
+ (BOOL)canInitWithRequest:(NSURLRequest *)r { return GBHostIsDead(r.URL.host); }
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)startLoading {
    NSURLRequest *r = self.request;
    NSData *body = r.HTTPBody;
    if (!body && r.HTTPBodyStream) {
        NSMutableData *m = [NSMutableData data];
        uint8_t buf[4096]; NSInputStream *s = r.HTTPBodyStream; [s open];
        NSInteger n; while ((n = [s read:buf maxLength:sizeof buf]) > 0) [m appendBytes:buf length:n];
        [s close]; body = m;
    }
    NSString *pq = r.URL.path ?: @"/";
    if (r.URL.query) pq = [pq stringByAppendingFormat:@"?%@", r.URL.query];
    NSInteger st; NSString *ct;
    NSData *out = GBRoute(@"nsurl", r.HTTPMethod ?: @"GET", r.URL.host, pq, body, &st, &ct);
    NSHTTPURLResponse *resp = [[NSHTTPURLResponse alloc] initWithURL:r.URL statusCode:st HTTPVersion:@"HTTP/1.1"
        headerFields:@{@"Content-Type": ct, @"Content-Length": @(out.length).stringValue}];
    [self.client URLProtocol:self didReceiveResponse:resp cacheStoragePolicy:NSURLCacheStorageNotAllowed];
    [self.client URLProtocol:self didLoadData:out];
    [self.client URLProtocolDidFinishLoading:self];
}
- (void)stopLoading {}
@end

static NSArray *(*orig_protocolClasses)(id, SEL);
static NSArray *my_protocolClasses(id self, SEL _cmd) {
    NSArray *o = orig_protocolClasses ? (orig_protocolClasses(self, _cmd) ?: @[]) : @[];
    return [@[[GBProto class]] arrayByAddingObjectsFromArray:o];
}

#pragma mark - Layer 2: libc interpose + in-process HTTP responder

typedef struct { const void *replacement; const void *replacee; } gb_interpose_t;
#define GB_INTERPOSE(rep, rpl) \
    __attribute__((used)) static const gb_interpose_t gb_ip_##rpl \
    __attribute__((section("__DATA,__interpose"))) = { (const void *)(uintptr_t)&rep, (const void *)(uintptr_t)&rpl };

#define GB_VIRT_IP "127.77.0.1"

static void GBNoteDNS(const char *node) {
    if (!node) return;
    NSString *n = @(node);
    [gLock lock]; BOOL fresh = ![gSeenDNS containsObject:n]; [gSeenDNS addObject:n]; [gLock unlock];
    if (fresh) GBLog(@"[dns] lookup %@%@", n, GBHostIsDead(n) ? @"  (dead host -> virtual)" : @"");
}

static int my_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    GBNoteDNS(node);
    if (node && GBHostIsDead(@(node))) {
        struct addrinfo h2; if (hints) h2 = *hints; else memset(&h2, 0, sizeof h2);
        h2.ai_flags &= ~AI_ADDRCONFIG; h2.ai_flags |= AI_NUMERICHOST; h2.ai_family = AF_INET;
        return getaddrinfo(GB_VIRT_IP, service, &h2, res);
    }
    return getaddrinfo(node, service, hints, res);
}
static struct hostent *my_gethostbyname(const char *name) {
    GBNoteDNS(name);
    if (name && GBHostIsDead(@(name))) return gethostbyname(GB_VIRT_IP);
    return gethostbyname(name);
}

static BOOL GBIsVirtualAddr(const struct sockaddr *a, socklen_t len, int *port) {
    if (!a || a->sa_family != AF_INET || len < sizeof(struct sockaddr_in)) return NO;
    const struct sockaddr_in *s = (const struct sockaddr_in *)a;
    uint32_t ip = ntohl(s->sin_addr.s_addr);
    if ((ip >> 16) == 0x7F4D || s->sin_addr.s_addr == gDeadIP.s_addr) { if (port) *port = ntohs(s->sin_port); return YES; }
    return NO;
}

static ssize_t GBReadFull(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) { ssize_t r = read(fd, (char *)buf + got, n - got); if (r <= 0) return -1; got += r; }
    return (ssize_t)got;
}

static void *GBServe(void *arg) {
    int fd = (int)(intptr_t)arg;
    NSMutableData *buf = [NSMutableData data];
    for (;;) {
        @autoreleasepool {
            NSRange hdrEnd = {NSNotFound, 0};
            const char *crlf2 = "\r\n\r\n";
            while (hdrEnd.location == NSNotFound) {
                hdrEnd = [buf rangeOfData:[NSData dataWithBytes:crlf2 length:4] options:0 range:NSMakeRange(0, buf.length)];
                if (hdrEnd.location != NSNotFound) break;
                uint8_t tmp[4096]; ssize_t n = read(fd, tmp, sizeof tmp);
                if (n <= 0) { close(fd); return NULL; }
                [buf appendBytes:tmp length:n];
            }
            NSString *head = [[NSString alloc] initWithData:[buf subdataWithRange:NSMakeRange(0, hdrEnd.location)]
                                                   encoding:NSISOLatin1StringEncoding];
            NSArray *lines = [head componentsSeparatedByString:@"\r\n"];
            NSArray *rl = [lines.firstObject componentsSeparatedByString:@" "];
            NSString *method = rl.count > 0 ? rl[0] : @"GET", *path = rl.count > 1 ? rl[1] : @"/", *host = @"";
            NSInteger clen = 0; BOOL chunked = NO;
            for (NSString *l in lines) {
                NSString *ll = l.lowercaseString;
                if ([ll hasPrefix:@"content-length:"]) clen = [[l substringFromIndex:15] integerValue];
                else if ([ll hasPrefix:@"host:"]) host = [[l substringFromIndex:5] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                else if ([ll hasPrefix:@"transfer-encoding:"] && [ll containsString:@"chunked"]) chunked = YES;
            }
            if (chunked) GBLog(@"[sock] WARNING chunked request body not supported for %@ %@", method, path);
            NSUInteger bodyStart = hdrEnd.location + 4;
            while ((NSInteger)(buf.length - bodyStart) < clen) {
                uint8_t tmp[4096]; ssize_t n = read(fd, tmp, sizeof tmp);
                if (n <= 0) { close(fd); return NULL; }
                [buf appendBytes:tmp length:n];
            }
            NSData *body = [buf subdataWithRange:NSMakeRange(bodyStart, clen)];
            [buf replaceBytesInRange:NSMakeRange(0, bodyStart + clen) withBytes:NULL length:0];

            GBMaybeStartScan(body);
            NSInteger st; NSString *ct;
            NSData *out = GBRoute(@"sock", method, host, path, body, &st, &ct);
            NSString *rh = [NSString stringWithFormat:@"HTTP/1.1 %ld OK\r\nContent-Type: %@\r\nContent-Length: %lu\r\nConnection: keep-alive\r\n\r\n",
                            (long)st, ct, (unsigned long)out.length];
            NSMutableData *resp = [[rh dataUsingEncoding:NSISOLatin1StringEncoding] mutableCopy];
            [resp appendData:out];
            const uint8_t *p = resp.bytes; size_t left = resp.length;
            while (left) { ssize_t w = write(fd, p, left); if (w <= 0) { close(fd); return NULL; } p += w; left -= w; }
        }
    }
}

static int my_connect(int fd, const struct sockaddr *a, socklen_t len) {
    int port = 0;
    if (GBIsVirtualAddr(a, len, &port)) {
        if (port == 443 || port == 8443) GBLog(@"[sock] connect to virtual host on TLS port %d - plaintext responder cannot serve this", port);
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
            int fl = fcntl(fd, F_GETFL, 0);
            dup2(sv[0], fd); close(sv[0]);
            if (fl != -1 && (fl & O_NONBLOCK)) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
            pthread_t t; pthread_attr_t at; pthread_attr_init(&at); pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
            pthread_create(&t, &at, GBServe, (void *)(intptr_t)sv[1]);
            GBLog(@"[sock] virtual connect fd=%d port=%d", fd, port);
            return 0;
        }
    }
    return connect(fd, a, len);
}

GB_INTERPOSE(my_getaddrinfo, getaddrinfo)
GB_INTERPOSE(my_gethostbyname, gethostbyname)
GB_INTERPOSE(my_connect, connect)
GB_INTERPOSE(my_CCCrypt, CCCrypt)
GB_INTERPOSE(my_CCCryptorCreateWithMode, CCCryptorCreateWithMode)
GB_INTERPOSE(my_CCCryptorUpdate, CCCryptorUpdate)
GB_INTERPOSE(my_CC_MD5, CC_MD5)
GB_INTERPOSE(my_CC_SHA1, CC_SHA1)
GB_INTERPOSE(my_CC_SHA256, CC_SHA256)

#pragma mark - Entry point

__attribute__((constructor)) static void GBInit(void) {
    @autoreleasepool {
        gLock = [NSLock new]; gSeenDNS = [NSMutableSet set];
        GBLoadConfig();
        [NSURLProtocol registerClass:[GBProto class]];
        gSlide = (uintptr_t)_dyld_get_image_vmaddr_slide(0);
        if (gHookVersion) { pthread_t vt; pthread_create(&vt, NULL, GBVtableThread, NULL); pthread_detach(vt); }
        if (gDumpEnabled)
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC), dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ GBDumpSegments(); });
        Class cfg = objc_getClass("__NSCFURLSessionConfiguration") ?: [NSURLSessionConfiguration class];
        Method m = class_getInstanceMethod(cfg, @selector(protocolClasses));
        if (m) { orig_protocolClasses = (void *)method_getImplementation(m); method_setImplementation(m, (IMP)my_protocolClasses); }
        GBLog(@"=== GBOffline v4 loaded (scan_key=%d). stubs dir: %@, hosts: %@, routes: %lu ===", (int)gScanEnabled, gStubDir, gHosts, (unsigned long)gRoutes.count);
    }
}