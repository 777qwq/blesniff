#import <CoreBluetooth/CoreBluetooth.h>
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>

// ── 纯 C 日志层（全 ASCII 内容，避开通道吞字坑） ─────────────────────

#define BS_DIR "/var/mobile/Documents/blesniff"
#define BS_MAX_HEX 384   // 单行 data 最多 hex 字符数
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

static void bs_log_line(const char *event, NSString *svc, NSString *chr,
                        const char *extra, NSData *data) {
    char hexbuf[BS_MAX_HEX + 64];
    hexbuf[0] = 0;
    if (data.length > 0) bs_hexdump(data.bytes, data.length, hexbuf, sizeof(hexbuf));

    const char *s = svc ? svc.UTF8String : "-";
    const char *c = chr ? chr.UTF8String : "-";

    pthread_mutex_lock(&bs_mutex);
    FILE *f = fopen(BS_DIR "/log", "a");
    if (f) {
        time_t t = time(NULL);
        struct tm tmv;
        localtime_r(&t, &tmv);
        fprintf(f, "[%02d:%02d:%02d] %s svc=%s chr=%s %s %s\n",
                tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                event, s, c, extra, hexbuf);
        fclose(f);
    }
    pthread_mutex_unlock(&bs_mutex);
}

static void bs_log_svc_list(NSString *event, NSArray<CBService *> *svcs) {
    NSMutableString *m = [NSMutableString stringWithString:@""];
    for (CBService *s in svcs) [m appendFormat:@"%@ ", s.UUID.UUIDString];
    char buf[512];
    snprintf(buf, sizeof(buf), "n=%lu %s", (unsigned long)svcs.count, m.UTF8String);
    bs_log_line(event, nil, nil, buf, nil);
}

static void bs_log_chr_list(CBService *svc, NSArray<CBCharacteristic *> *chrs) {
    for (CBCharacteristic *ch in chrs) {
        char buf[256];
        snprintf(buf, sizeof(buf), "props=0x%02lx", (unsigned long)ch.properties);
        bs_log_line("CHR", svc.UUID.UUIDString, ch.UUID.UUIDString, buf, nil);
    }
}

// 宿主标识（写到行首，单文件统一日志也保留归属信息）
static NSString *bs_host() {
    static NSString *bid;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"(null)";
    });
    return bid;
}

// 统一入口：行首带宿主
static void bs_log(const char *event, NSString *svc, NSString *chr,
                   const char *extra, NSData *data) {
    char line[128];
    snprintf(line, sizeof(line), "host=%s", bs_host.UTF8String);
    pthread_mutex_lock(&bs_mutex);
    FILE *f = fopen(BS_DIR "/log", "a");
    if (f) {
        time_t t = time(NULL);
        struct tm tmv;
        localtime_r(&t, &tmv);
        char hexbuf[BS_MAX_HEX + 64];
        hexbuf[0] = 0;
        if (data.length > 0) bs_hexdump(data.bytes, data.length, hexbuf, sizeof(hexbuf));
        const char *s = svc ? svc.UTF8String : "-";
        const char *c = chr ? chr.UTF8String : "-";
        fprintf(f, "[%02d:%02d:%02d] %s %s svc=%s chr=%s %s %s\n",
                tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                event, line, s, c, extra ?: "", hexbuf);
        fclose(f);
    }
    pthread_mutex_unlock(&bs_mutex);
}

// ── 钩子 ────────────────────────────────────────────────

%hook CBCentralManager
- (void)scanForPeripheralsWithServices:(NSArray<CBUUID *> *)serviceUUIDs
                               options:(NSDictionary<NSString *, id> *)options {
    NSMutableString *m = [NSMutableString stringWithString:@"filter="];
    if (serviceUUIDs.count == 0) [m appendString:@"ALL"];
    else for (CBUUID *u in serviceUUIDs) [m appendFormat:@"%@ ", u.UUIDString];
    bs_log("SCAN", nil, nil, m.UTF8String, nil);
    %orig;
}

- (void)centralManager:(CBCentralManager *)central
 didDiscoverPeripheral:(CBPeripheral *)peripheral
     advertisementData:(NSDictionary<NSString *, id> *)advertisementData
                  RSSI:(NSNumber *)RSSI {
    NSString *name = peripheral.name ?: advertisementData[CBAdvertisementDataLocalNameKey] ?: @"-";
    char buf[256];
    snprintf(buf, sizeof(buf), "name=%s rssi=%ld", name.UTF8String, (long)RSSI.intValue);
    bs_log("ADV", nil, peripheral.identifier ? nil : nil, buf, nil);
    %orig;
}

- (void)centralManager:(CBCentralManager *)central
  didConnectPeripheral:(CBPeripheral *)peripheral {
    char buf[128];
    snprintf(buf, sizeof(buf), "id=%s", peripheral.identifier.UUIDString.UTF8String);
    bs_log("CONNECT", nil, nil, buf, nil);
    %orig;
}
%end

%hook CBPeripheral
- (void)writeValue:(NSData *)data
 forCharacteristic:(CBCharacteristic *)characteristic
              type:(CBCharacteristicWriteType)type {
    char buf[128];
    snprintf(buf, sizeof(buf), "type=%ld", (long)type);
    bs_log("WRITE", characteristic.service.UUID.UUIDString, characteristic.UUID.UUIDString, buf, data);
    %orig;
}

- (void)setNotifyValue:(BOOL)enabled forCharacteristic:(CBCharacteristic *)characteristic {
    char buf[128];
    snprintf(buf, sizeof(buf), "notify=%d", enabled ? 1 : 0);
    bs_log("NOTIFY", characteristic.service.UUID.UUIDString, characteristic.UUID.UUIDString, buf, nil);
    %orig;
}

- (void)peripheral:(CBPeripheral *)peripheral
didDiscoverServices:(NSError *)error {
    if (error) {
        char buf[128];
        snprintf(buf, sizeof(buf), "err=%ld", (long)error.code);
        bs_log("DISCSVC_ERR", nil, nil, buf, nil);
    } else {
        bs_log_svc_list("DISCSVC", peripheral.services);
    }
    %orig;
}

- (void)peripheral:(CBPeripheral *)peripheral
didDiscoverCharacteristicsForService:(CBService *)service
             error:(NSError *)error {
    if (!error && service.characteristics) bs_log_chr_list(service, service.characteristics);
    %orig;
}

- (void)peripheral:(CBPeripheral *)peripheral
didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic
             error:(NSError *)error {
    if (error) {
        char buf[128];
        snprintf(buf, sizeof(buf), "err=%ld", (long)error.code);
        bs_log("READ_ERR", characteristic.service.UUID.UUIDString, characteristic.UUID.UUIDString, buf, nil);
    } else {
        bs_log("RECV", characteristic.service.UUID.UUIDString, characteristic.UUID.UUIDString, "", characteristic.value);
    }
    %orig;
}
%end

%ctor {
    mkdir(BS_DIR, 0755);
    %init;
    bs_log("LOADED", nil, nil, "", nil);
}
