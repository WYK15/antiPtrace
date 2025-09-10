TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = SpringBoard


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = antiPtrace

antiPtrace_FILES = Tweak.xm
antiPtrace_CFLAGS = -fobjc-arc  -Wno-unused-variable -Wno-deprecated-declarations

include $(THEOS_MAKE_PATH)/tweak.mk
