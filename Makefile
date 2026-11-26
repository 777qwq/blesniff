TARGET := iphone:clang:16.5:16.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME := BLESniff
BLESniff_FILES := Tweak.x
BLESniff_FRAMEWORKS := CoreBluetooth

include $(THEOS_MAKE_PATH)/tweak.mk
