#import <CoreBluetooth/CoreBluetooth.h>
#import <Foundation/Foundation.h>
#include <substrate.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>

// ── log layer (pure C, ASCII content only) ─────────────────────

// resolved at ctor: shared path for privileged processes,
// per-app container path for sandboxed ones
static char bs_logpath[512] = "/var/mobile/Documents/blesniff/log";

#define BS_MAX_HEX 384
#define BS_MAX_LINE 2048

static pthread_mutex_t bs_mutex = PTHREAD_MUTEX_INITIALIZER;

static void bs_hexdump(const unsigned char *bytes, NSUInteger len, char *out, size_t outsz) {
    NSUInteger n = len * 2;
    if (n > BS_MAX_HEX) n = BS_MAX_HEX;
    if (n + 1 > outsz) n = outsz - 1;
    size_t o = 0;
    for (NSUInteger i = 0; i + 1 < n; i += 2) {
        if (o + 2 >= outsz) break;
        static const char *hx = "0123456789abcdef";
        unsigned char b = bytes[i / 2];
        out[o++] = hx[(b >> 4) & 0xf];
        out[o++] = hx[b & 0xf];
    }
    out[o] = 0;
    if (len * 2 > BS_MAX_HEX) {
        size_t l = strlen(out);
        snprintf(out + l, outsz - l, "...(%luB)", (unsigned long)len);
    }
}

static void bs_write_line(const char *line) {
    pthread_mutex_lock(&bs_mutex);
    FILE *f = fopen(bs_logpath, "a");
    if (f) { fputs(line, f); fclose(f); }
    pthread_mutex_unlock(&bs_mutex);
}

static NSString *bs_host() {
    static NSString *bid;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"(null)";
    });
    return bid;
}

// unified entry: host= prefix on every line
static void bs_log(const char *event, NSString *svc, NSString *chr,
                   const char *extra, NSData *data) {
    char hexbuf[BS_MAX_HEX + 64];
    hexbuf[0] = 0;
    if (data.length > 0) bs_hexdump(data.bytes, data.length, hexbuf, sizeof(hexbuf));
    const char *s = svc ? svc.UTF8String : "-";
    const char *c = chr ? chr.UTF8String : "-";
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    char line[BS_MAX_LINE];
    snprintf(line, sizeof(line), "[%02d:%02d:%02d] %s host=%s svc=%s chr=%s %s %s\n",
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
             event, bs_host().UTF8String, s, c, extra ?: "", hexbuf);
    bs_write_line(line);
}

static void bs_log_svc_list(const char *event, NSArray<CBService *> *svcs) {
    NSMutableString *m = [NSMutableString stringWithString:@""];
    for (CBService *s in svcs) [m appendFormat:@"%@ ", s.UUID.UUIDString];
    char buf[512];
    snprintf(buf, sizeof(buf), "n=%lu %s", (unsigned long)svcs.count, m.UTF8String);
    bs_log(event, nil, nil, buf, nil);
}

static void bs_log_chr_list(CBService *svc, NSArray<CBCharacteristic *> *chrs) {
    for (CBCharacteristic *ch in chrs) {
        char buf[256];
        snprintf(buf, sizeof(buf), "props=0x%02lx", (unsigned long)ch.properties);
        bs_log("CHR", svc.UUID.UUIDString, ch.UUID.UUIDString, buf, nil);
    }
}

// ── decode layer: frame split / checksum rule / write-response diff ─────

static NSMutableDictionary *bs_anlz;
static NSDate *bs_respUntil;

static NSString *bs_anlz_key(CBCharacteristic *ch) {
    return [NSString stringWithFormat:@"%@/%@", ch.service.UUID.UUIDString, ch.UUID.UUIDString];
}

static void bs_init_anlz(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ bs_anlz = [NSMutableDictionary new]; });
}

static NSString *bs_match_rule(const unsigned char *b, NSUInteger len) {
    if (len < 3) return nil;
    unsigned int sum = 0, x = 0, sum2 = 0;
    for (NSUInteger i = 0; i < len - 1; i++) { sum += b[i]; x ^= b[i]; if (i >= 1) sum2 += b[i]; }
    unsigned char cks = b[len - 1];
    if ((unsigned char)sum == cks) return @"sum_all";
    if ((unsigned char)sum2 == cks) return @"sum_excl";
    if ((unsigned char)x == cks) return @"xor";
    return nil;
}

static void bs_analyze(CBCharacteristic *ch, NSData *data) {
    bs_init_anlz();
    if (data.length < 3) return;
    const unsigned char *b = data.bytes;
    NSUInteger len = data.length;
    NSString *key = bs_anlz_key(ch);

    pthread_mutex_lock(&bs_mutex);
    NSMutableDictionary *st = bs_anlz[key];
    if (!st) { st = [NSMutableDictionary new]; bs_anlz[key] = st; }

    NSString *rule = st[@"rule"] ?: bs_match_rule(b, len);
    BOOL framed = (rule != nil);
    if (rule && !st[@"rule"]) { st[@"rule"] = rule; }

    NSDate *now = [NSDate date];
    BOOL inResp = bs_respUntil && [now compare:bs_respUntil] == NSOrderedAscending;
    NSData *prev = st[@"last"];

    if (framed) {
        if (inResp) {
            NSData *base = st[@"baseline"] ?: prev;
            if (base && base.length == len) {
                const unsigned char *d = base.bytes;
                char diffs[512]; size_t o = 0;
                o += snprintf(diffs + o, sizeof(diffs) - o, "chg=");
                int n = 0;
                for (NSUInteger i = 0; i < len && o < sizeof(diffs) - 16; i++) {
                    if (d[i] != b[i]) {
                        o += snprintf(diffs + o, sizeof(diffs) - o, "b%lu:%02x->%02x ",
                                      (unsigned long)i, d[i], b[i]);
                        n++;
                    }
                }
                if (n) bs_log("DIFF", ch.service.UUID.UUIDString, ch.UUID.UUIDString, diffs, nil);
                else bs_log("SAME", ch.service.UUID.UUIDString, ch.UUID.UUIDString, "", nil);
            }
        } else {
            st[@"baseline"] = data;
        }
        st[@"last"] = data;
    }
    pthread_mutex_unlock(&bs_mutex);

    if (framed) {
        char buf[160];
        snprintf(buf, sizeof(buf), "rule=%s len=%lu resp=%d", rule.UTF8String, (unsigned long)len, inResp ? 1 : 0);
        bs_log("FRAME", ch.service.UUID.UUIDString, ch.UUID.UUIDString, buf, data);
    } else {
        bs_log("RAWCHUNK", ch.service.UUID.UUIDString, ch.UUID.UUIDString, "", data);
    }
}

static void bs_mark_write(CBCharacteristic *ch, NSData *data) {
    bs_init_anlz();
    NSString *key = bs_anlz_key(ch);
    pthread_mutex_lock(&bs_mutex);
    NSMutableDictionary *st = bs_anlz[key];
    if (st && st[@"last"]) st[@"baseline"] = st[@"last"];
    bs_respUntil = [NSDate dateWithTimeIntervalSinceNow:1.5];
    pthread_mutex_unlock(&bs_mutex);
}

// ── delegate runtime swizzle ────────────────────────────────────────
// Delegate callbacks are implemented on the APP's delegate class,
// NOT on CBCentralManager/CBPeripheral. So we hook setDelegate: and
// swizzle the delegate class at runtime. This works for ANY app.

static void (*bs_old_adv)(id, SEL, CBCentralManager *, CBPeripheral *,
                          NSDictionary *, NSNumber *);
static void (*bs_old_conn)(id, SEL, CBCentralManager *, CBPeripheral *);
static void (*bs_old_discsvc)(id, SEL, CBPeripheral *, NSError *);
static void (*bs_old_discchr)(id, SEL, CBPeripheral *, CBService *, NSError *);
static void (*bs_old_updval_err)(id, SEL, CBPeripheral *, CBCharacteristic *, NSError *);
static void (*bs_old_updval)(id, SEL, CBPeripheral *, CBCharacteristic *);
static void (*bs_old_notifstate)(id, SEL, CBPeripheral *, CBCharacteristic *, NSError *);
static void (*bs_old_writeack)(id, SEL, CBPeripheral *, CBCharacteristic *, NSError *);

static NSMutableSet *bs_swz_done;

static void bs_swz_once(Class cls, SEL sel, IMP imp, IMP *old_store) {
    if (!cls || !sel) return;
    if (!class_getInstanceMethod(cls, sel)) return;  // delegate does not implement it
    pthread_mutex_lock(&bs_mutex);
    if (!bs_swz_done) bs_swz_done = [NSMutableSet new];
    NSString *key = [NSString stringWithFormat:@"%p:%@", cls, NSStringFromSelector(sel)];
    BOOL dup = [bs_swz_done containsObject:key];
    if (!dup) [bs_swz_done addObject:key];
    pthread_mutex_unlock(&bs_mutex);
    if (dup) return;
    IMP old = NULL;
    MSHookMessageEx(cls, sel, imp, &old);
    if (old_store) *old_store = old;
}

// central delegate handlers
static void bs_h_adv(id self, SEL _cmd, CBCentralManager *cm, CBPeripheral *p,
                     NSDictionary *adv, NSNumber *rssi) {
    NSString *name = p.name ?: adv[CBAdvertisementDataLocalNameKey] ?: @"-";
    char buf[256];
    snprintf(buf, sizeof(buf), "name=%s rssi=%ld", name.UTF8String, (long)rssi.intValue);
    bs_log("ADV", nil, nil, buf, nil);
    if (bs_old_adv) bs_old_adv(self, _cmd, cm, p, adv, rssi);
}

static void bs_h_conn(id self, SEL _cmd, CBCentralManager *cm, CBPeripheral *p) {
    char buf[128];
    snprintf(buf, sizeof(buf), "id=%s", p.identifier.UUIDString.UTF8String ?: "-");
    bs_log("CONNECT", nil, nil, buf, nil);
    if (bs_old_conn) bs_old_conn(self, _cmd, cm, p);
}

// peripheral delegate handlers
static void bs_h_discsvc(id self, SEL _cmd, CBPeripheral *p, NSError *err) {
    if (err) {
        char buf[128];
        snprintf(buf, sizeof(buf), "err=%ld", (long)err.code);
        bs_log("DISCSVC_ERR", nil, nil, buf, nil);
    } else {
        bs_log_svc_list("DISCSVC", p.services);
    }
    if (bs_old_discsvc) bs_old_discsvc(self, _cmd, p, err);
}

static void bs_h_discchr(id self, SEL _cmd, CBPeripheral *p, CBService *svc, NSError *err) {
    if (!err && svc.characteristics) bs_log_chr_list(svc, svc.characteristics);
    if (bs_old_discchr) bs_old_discchr(self, _cmd, p, svc, err);
}

static void bs_h_updval_err(id self, SEL _cmd, CBPeripheral *p, CBCharacteristic *ch, NSError *err) {
    if (err) {
        char buf[128];
        snprintf(buf, sizeof(buf), "err=%ld", (long)err.code);
        bs_log("READ_ERR", ch.service.UUID.UUIDString, ch.UUID.UUIDString, buf, nil);
    } else {
        bs_log("RECV", ch.service.UUID.UUIDString, ch.UUID.UUIDString, "", ch.value);
        bs_analyze(ch, ch.value);
    }
    if (bs_old_updval_err) bs_old_updval_err(self, _cmd, p, ch, err);
}

static void bs_h_updval(id self, SEL _cmd, CBPeripheral *p, CBCharacteristic *ch) {
    bs_log("RECV", ch.service.UUID.UUIDString, ch.UUID.UUIDString, "", ch.value);
    bs_analyze(ch, ch.value);
    if (bs_old_updval) bs_old_updval(self, _cmd, p, ch);
}

static void bs_h_notifstate(id self, SEL _cmd, CBPeripheral *p, CBCharacteristic *ch, NSError *err) {
    char buf[128];
    snprintf(buf, sizeof(buf), "notifying=%d err=%ld", ch.isNotifying ? 1 : 0,
             err ? (long)err.code : 0L);
    bs_log("NOTIFYSTATE", ch.service.UUID.UUIDString, ch.UUID.UUIDString, buf, nil);
    if (bs_old_notifstate) bs_old_notifstate(self, _cmd, p, ch, err);
}

static void bs_h_writeack(id self, SEL _cmd, CBPeripheral *p, CBCharacteristic *ch, NSError *err) {
    char buf[128];
    snprintf(buf, sizeof(buf), "ack=%d err=%ld", err ? 0 : 1, err ? (long)err.code : 0L);
    bs_log("WRITEACK", ch.service.UUID.UUIDString, ch.UUID.UUIDString, buf, nil);
    if (bs_old_writeack) bs_old_writeack(self, _cmd, p, ch, err);
}

static void bs_swz_central_delegate(id delegate) {
    if (!delegate) return;
    Class cls = object_getClass(delegate);
    bs_swz_once(cls, @selector(centralManager:didDiscoverPeripheral:advertisementData:RSSI:), (IMP)bs_h_adv, (IMP *)&bs_old_adv);
    bs_swz_once(cls, @selector(centralManager:didConnectPeripheral:), (IMP)bs_h_conn, (IMP *)&bs_old_conn);
}

static void bs_swz_peripheral_delegate(id delegate) {
    if (!delegate) return;
    Class cls = object_getClass(delegate);
    bs_swz_once(cls, @selector(peripheral:didDiscoverServices:), (IMP)bs_h_discsvc, (IMP *)&bs_old_discsvc);
    bs_swz_once(cls, @selector(peripheral:didDiscoverCharacteristicsForService:error:), (IMP)bs_h_discchr, (IMP *)&bs_old_discchr);
    bs_swz_once(cls, @selector(peripheral:didUpdateValueForCharacteristic:error:), (IMP)bs_h_updval_err, (IMP *)&bs_old_updval_err);
    bs_swz_once(cls, @selector(peripheral:didUpdateValueForCharacteristic:), (IMP)bs_h_updval, (IMP *)&bs_old_updval);
    bs_swz_once(cls, @selector(peripheral:didUpdateNotificationStateForCharacteristic:error:), (IMP)bs_h_notifstate, (IMP *)&bs_old_notifstate);
    bs_swz_once(cls, @selector(peripheral:didWriteValueForCharacteristic:error:), (IMP)bs_h_writeack, (IMP *)&bs_old_writeack);
}

// ── hooks ────────────────────────────────────────────────

%hook CBCentralManager
- (void)scanForPeripheralsWithServices:(NSArray<CBUUID *> *)serviceUUIDs
                               options:(NSDictionary<NSString *, id> *)options {
    NSMutableString *m = [NSMutableString stringWithString:@"filter="];
    if (serviceUUIDs.count == 0) [m appendString:@"ALL"];
    else for (CBUUID *u in serviceUUIDs) [m appendFormat:@"%@ ", u.UUIDString];
    bs_log("SCAN", nil, nil, m.UTF8String, nil);
    %orig;
}

- (void)setDelegate:(id<CBCentralManagerDelegate>)delegate {
    %orig;
    bs_swz_central_delegate(delegate);
}
%end

%hook CBPeripheral
- (void)writeValue:(NSData *)data
 forCharacteristic:(CBCharacteristic *)characteristic
              type:(CBCharacteristicWriteType)type {
    char buf[128];
    snprintf(buf, sizeof(buf), "type=%ld", (long)type);
    bs_log("WRITE", characteristic.service.UUID.UUIDString, characteristic.UUID.UUIDString, buf, data);
    bs_mark_write(characteristic, data);
    %orig;
}

- (void)setNotifyValue:(BOOL)enabled forCharacteristic:(CBCharacteristic *)characteristic {
    char buf[128];
    snprintf(buf, sizeof(buf), "notify=%d", enabled ? 1 : 0);
    bs_log("NOTIFY", characteristic.service.UUID.UUIDString, characteristic.UUID.UUIDString, buf, nil);
    %orig;
}

- (void)setDelegate:(id<CBPeripheralDelegate>)delegate {
    %orig;
    bs_swz_peripheral_delegate(delegate);
}
%end

%ctor {
    // resolve writable log path: shared dir first, app container fallback
    mkdir("/var/mobile/Documents", 0755);
    mkdir("/var/mobile/Documents/blesniff", 0755);
    FILE *t = fopen("/var/mobile/Documents/blesniff/log", "a");
    if (t) { fclose(t); }
    else {
        NSString *home = NSHomeDirectory();
        snprintf(bs_logpath, sizeof(bs_logpath), "%s/Documents/blesniff.log", home.UTF8String);
    }
    // CoreBluetooth absent in this process: bail silently (avoid daemon log spam)
    if (!objc_getClass("CBCentralManager")) return;
    %init;
    char buf[160];
    snprintf(buf, sizeof(buf), "dir=%s", bs_logpath);
    bs_log("LOADED", nil, nil, buf, nil);
}
