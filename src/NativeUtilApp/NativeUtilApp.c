// Thin Telework System Source Code
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// Copyright (c) IPA CyberLab of Industrial Cyber Security Center.
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on IPA-DN-Ultra Library and SoftEther VPN Project in GitHub.
// 
// All Rights Reserved.
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (IPA CYBERLAB, SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI
// OR OTHER SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY
// KIND OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE IPA CYBERLAB HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// daiyuu.securityreport [at] dnobori.jp
// 
// Thank you for your cooperation.


#define	VPN_EXE
#define VARS_DEFINE_PATCH

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "NativeUtilApp.h"
#include "Vars/VarsActivePatch.h"

static DS *dss = NULL;

void test(UINT num, char **arg)
{
}

void gg(UINT num, char **arg)
{
	WIDE *w = WideGateStart();

	GetLine(NULL, 0);

	WideGateStop(w);
}

void ds(UINT num, char **arg)
{
	DS *ds = NewDs(true, false);

	GetLine(NULL, 0);

	FreeDs(ds);
}

void dg(UINT num, char **arg)
{
#ifdef	OS_WIN32
	DGExec();
#endif  // OS_WIN32
}

void du(UINT num, char **arg)
{
#ifdef	OS_WIN32
	DUExec();
#endif  // OS_WIN32
}

void di(UINT num, char **arg)
{
#ifdef	OS_WIN32
	SWExec();
#endif  // OS_WIN32
}

void stat_test(UINT num, char** arg)
{
	STATMAN* stat;
	STATMAN_CONFIG cfg = CLEAN;

	StrCpy(cfg.PostUrl, 0, "https://127.0.0.1/stat/");
	
	stat = NewStatMan(&cfg);

	{
		PACK* p = NewPack();

		PackAddStr(p, "str1", "Hello2");

		PackAddUniStr(p, "str2", L"World2");

		PackAddInt64(p, "int1_total", 5);

		StatManAddReport(stat, p);

		FreePack(p);
	}

	GetLine(NULL, 0);

	FreeStatMan(stat);
}

void ping_test(UINT num, char **arg)
{
#ifdef	OS_WIN32
	char *pcid;
	UINT count;
	UINT ret;
	WIDE *wide;
	SOCKIO *sockio;
	if (num == 0)
	{
		Print("Usage: ping pcid [num]\n");
		return;
	}

	pcid = arg[0];

	count = 0x7FFFFFFF;
	if (num >= 2)
	{
		count = ToInt(arg[1]);
	}

	Print("Connecting...\n");

	wide = WideClientStart("DESK", _GETLANG());

	ret = WideClientConnect(wide, pcid, 0, 0, &sockio, 0, false);

	if (ret != ERR_NO_ERROR)
	{
		Print("%S\n", _E(ret));
	}
	else
	{
		UINT i, num;
		double total = 0;
		PACK *p;

		p = NewPack();
		PackAddBool(p, "pingmode", true);

		SockIoSendPack(sockio, p);
		FreePack(p);

		num = 0;

		for (i = 0;i < count;i++)
		{
			UINT64 tick1, tick2, now, diff;
			double diff_double;

			tick1 = MsGetHiResCounter();

			if (SockIoSendAll(sockio, &tick1, sizeof(UINT64)) == false)
			{
				Print("Disconnected.\n");
				break;
			}

			if (SockIoRecvAll(sockio, &tick2, sizeof(UINT64)) == false)
			{
				Print("Disconnected.\n");
				break;
			}

			now = MsGetHiResCounter();

			if (tick1 != tick2)
			{
				Print("Ping Protocol Error !!\n");
				break;
			}

			diff = now - tick2;
			diff_double = MsGetHiResTimeSpan(diff);

			if (count == 1 || i != 0)
			{
				total += diff_double;
				num++;
			}

			Print("Ping %u: %f sec.\n", num, diff_double);

			SleepThread(1000);
		}

		SockIoDisconnect(sockio);

		Print("Aver: %f sec (Count: %u)\n", (double)((double)total / (double)num), num);
	}

	WideClientStop(wide);
#endif  // OS_WIN32
}

// テスト関数一覧定義
typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;
	TEST_PROC *proc;
} TEST_LIST;

TEST_LIST test_list[] =
{
	{"test", test},
	{"gg", gg},
	{"ds", ds},
	{"dg", dg},
	{"du", du},
	{"di", di},
	{"st", stat_test},
	{"ping", ping_test},
};

// テスト関数
void TestMain(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;

	Print("Hamster Tester\n");
	OSSetHighPriority();

	while (true)
	{
		Print("TEST>");
		if (first && StrLen(cmd) != 0 && g_memcheck == false)
		{
			first = false;
			StrCpy(tmp, sizeof(tmp), cmd);
			exit_now = true;
			Print("%s\n", cmd);
		}
		else
		{
#ifdef	VISTA_HAM
			_exit(0);
#endif
			if (GetLine(tmp, sizeof(tmp)) == false)
			{
				StrCpy(tmp, sizeof(tmp), "q");
			}
		}
		Trim(tmp);
		if (StrLen(tmp) != 0)
		{
			UINT i, num;
			bool b = false;
			TOKEN_LIST *token = ParseCmdLine(tmp);
			char *cmd = token->Token[0];
#ifdef	VISTA_HAM
			if (EndWith(cmd, "vlan") == false)
			{
				_exit(0);
			}
#endif
			if (!StrCmpi(cmd, "exit") || !StrCmpi(cmd, "quit") || !StrCmpi(cmd, "q"))
			{
				FreeToken(token);
				break;
			}
			else
			{
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					if (!StrCmpi(test_list[i].command_str, cmd))
					{
						char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
						UINT j;
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							arg[j] = CopyStr(token->Token[j + 1]);
						}
						test_list[i].proc(token->NumTokens - 1, arg);
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							Free(arg[j]);
						}
						Free(arg);
						b = true;
						Print("\n");
						break;
					}
				}
				if (b == false)
				{
					Print("Invalid Command: %s\n\n", cmd);
				}
			}
			FreeToken(token);

			if (exit_now)
			{
				break;
			}
		}
	}
	Print("Exiting...\n\n");
}


// main 関数
int main(int argc, char *argv[])
{
	bool memchk = false;
	UINT i;
	char cmd[MAX_SIZE];
	char *s;

	Vars_ApplyActivePatch();

	InitProcessCallOnceEx(true);

	printf("WideTunnel Test Program.\n");

	cmd[0] = 0;
	if (argc >= 2)
	{
		for (i = 1;i < (UINT)argc;i++)
		{
			s = argv[i];
			if (s[0] == '/')
			{
				if (!StrCmpi(s, "/memcheck"))
				{
					memchk = true;
				}
			}
			else
			{
				StrCpy(cmd, sizeof(cmd), &s[0]);
			}
		}
	}

	DcSetDebugFlag(true);

	InitMayaqua(memchk, true, argc, argv);
	InitCedar();

	TestMain(cmdline);
	FreeCedar();
	FreeMayaqua();

	return 0;
}

