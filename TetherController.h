/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _TETHER_CONTROLLER_H
#define _TETHER_CONTROLLER_H

#include <netinet/in.h>

#include "List.h"

typedef android::netd::List<char *> InterfaceCollection;
typedef android::netd::List<struct in_addr> NetAddressCollection;

class TetherController {
    InterfaceCollection  *mInterfaces;
    NetAddressCollection *mDnsForwarders;
    pid_t                 mDaemonPid;
    pid_t                 mDhcpcdPid;
    int                   mDaemonFd;

public:
    TetherController();
    virtual ~TetherController();

    int setIpFwdEnabled(bool enable);
    bool getIpFwdEnabled();
#ifdef OMAP_ENHANCEMENT
    int startTethering(int num_addrs, struct in_addr* addrs, const char *script_path = NULL);
#else
    int startTethering(int num_addrs, struct in_addr* addrs);
#endif

    int stopTethering();
    bool isTetheringStarted();

    int startReverseTethering(const char* iface);
    int stopReverseTethering();

    int setDnsForwarders(char **servers, int numServers);
    NetAddressCollection *getDnsForwarders();

    int tetherInterface(const char *interface);
    int untetherInterface(const char *interface);
    InterfaceCollection *getTetheredInterfaceList();
};

#endif
