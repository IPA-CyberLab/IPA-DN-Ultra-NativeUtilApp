﻿// Thin Telework System Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) NTT-East Impossible Telecom Mission Group.
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on IPA-DN-Ultra Library and SoftEther VPN Project in GitHub.
// 
// All Rights Reserved.


#include "VarsCurrentBuildInfo.h"

#define APP_ID_PREFIX					"NativeUtilApp"
#define APP_ID_PREFIX_UNICODE			L"NativeUtilApp"

#define DS_RPC_PORT						9825

#define DESK_PUBLISHER_NAME_ANSI		"NativeUtilApp"

#define	DESK_PRODUCT_NAME_SUITE			"NativeUtilApp"
#define	DESK_PRODUCT_NAME_SUITE_UNICODE		L"NativeUtilApp"
#define DESK_PUBLISHER_NAME_UNICODE		L"NativeUtilApp"


// 以下は必要に応じていじること
#define DESK_LOCALHOST_DUMMY_FQDN		"%s.secure.ipantt.net"
#define DESK_LOCALHOST_DUMMY_FQDN_V6	"%s.secure6.ipantt.net"
#define	UPDATE_SERVER_URL_GLOBAL		"https://update-check.dynamic-ip.thin.cyber.ipa.go.jp/update/?family=%s&software=%s&mybuild=%u&lang=%s"

// RDUP ポート番号変更
#undef	DS_URDP_PORT
#define DS_URDP_PORT					3459


