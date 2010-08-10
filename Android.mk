BUILD_NETD := false
ifneq ($(TARGET_SIMULATOR),true)
    BUILD_NETD := true
endif

ifeq ($(BUILD_NETD),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

ifdef OMAP_ENHANCEMENT
ifdef USES_TI_WL1271
DK_ROOT = hardware/ti/wlan/wl1271_softAP
OS_ROOT = $(DK_ROOT)/platforms
STAD    = $(DK_ROOT)/stad
UTILS   = $(DK_ROOT)/utils
TWD     = $(DK_ROOT)/TWD
COMMON  = $(DK_ROOT)/common
TXN     = $(DK_ROOT)/Txn
CUDK    = $(DK_ROOT)/CUDK

WILINK_INCLUDES = $(STAD)/Export_Inc               \
                  $(STAD)/src/Application          \
                  $(UTILS)                         \
                  $(OS_ROOT)/os/linux/inc          \
                  $(OS_ROOT)/os/common/inc         \
                  $(TWD)/TWDriver                  \
                  $(TWD)/FirmwareApi               \
                  $(TWD)/TwIf                      \
                  $(TWD)/FW_Transfer/Export_Inc    \
                  $(TXN)                           \
                  $(CUDK)/configurationutility/inc \
                  $(CUDK)/hostapd                  \
                  $(CUDK)/os/common/inc
endif
endif

LOCAL_SRC_FILES:=                                      \
                  main.cpp                             \
                  CommandListener.cpp                  \
                  NetdCommand.cpp                      \
                  NetlinkManager.cpp                   \
                  NetlinkHandler.cpp                   \
                  logwrapper.c                         \
                  TetherController.cpp                 \
                  NatController.cpp                    \
                  PppController.cpp                    \
                  PanController.cpp                    \
                  UsbController.cpp                    \
                  ThrottleController.cpp

LOCAL_MODULE:= netd

LOCAL_C_INCLUDES := $(KERNEL_HEADERS) \
                    $(LOCAL_PATH)/../bluetooth/bluedroid/include \
                    $(LOCAL_PATH)/../bluetooth/bluez-clean-headers \
                    external/openssl/include

LOCAL_CFLAGS :=
ifdef WIFI_DRIVER_FW_STA_PATH
LOCAL_CFLAGS += -DWIFI_DRIVER_FW_STA_PATH=\"$(WIFI_DRIVER_FW_STA_PATH)\"
endif
ifdef WIFI_DRIVER_FW_AP_PATH
LOCAL_CFLAGS += -DWIFI_DRIVER_FW_AP_PATH=\"$(WIFI_DRIVER_FW_AP_PATH)\"
endif

ifdef OMAP_ENHANCEMENT
ifdef USES_TI_WL1271
LOCAL_CFLAGS += -D__BYTE_ORDER_LITTLE_ENDIAN
LOCAL_STATIC_LIBRARIES := libhostapdcli
LOCAL_C_INCLUDES += $(WILINK_INCLUDES)
LOCAL_SRC_FILES += SoftapControllerTI.cpp
else
LOCAL_SRC_FILES += SoftapController.cpp
endif
endif

LOCAL_SHARED_LIBRARIES := libsysutils libcutils libnetutils libcrypto

ifeq ($(BOARD_HAVE_BLUETOOTH),true)
  LOCAL_SHARED_LIBRARIES := $(LOCAL_SHARED_LIBRARIES) libbluedroid
  LOCAL_CFLAGS := $(LOCAL_CFLAGS) -DHAVE_BLUETOOTH
endif

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:=          \
                  ndc.c \

LOCAL_MODULE:= ndc

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)

endif # ifeq ($(BUILD_NETD,true)
