// IPA-DN-Ultra-NativeUtilApp Source Code
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

typedef struct UDPBST
{
	IP ip;
	UINT port;
	UINT size;
	bool rand_flag;
} UDPBST;

#ifdef	UNIX_LINUX

struct mmsghdr2 {
	struct msghdr msg_hdr;
	unsigned int  msg_len;
};

#endif	// UNIX_LINUX

typedef struct SSL_SERVER_BENCH
{
	X* testcert_01_chain1;
	X* testcert_01_chain2;
	X* testcert_03_host;
	K* testcert_03_host_key;

	X* widecert_01_controller;
	K* widecert_01_controller_key;

	CERTS_AND_KEY* certs_and_key_for_sni;

	LIST* SockThreadList;

	COUNTER* CurrentConnections;
	COUNTER* CurrentSslInProgress;
	COUNTER* TotalSslOk;
	COUNTER* TotalSslError;

	UINT mode;

	bool Halt;
	EVENT* HaltEvent;
} SSL_SERVER_BENCH;

typedef struct SSL_SERVER_BENCH_STAT
{
	UINT CurrentConnections;
	UINT CurrentSslInProgress;
	UINT TotalSslOk;
	UINT TotalSslError;
	UINT64 Tick;
} SSL_SERVER_BENCH_STAT;

void sslserverbench_accepted(SSL_SERVER_BENCH* svr, SOCK* s)
{
	SetTimeout(s, CONNECTING_TIMEOUT);

	CERTS_AND_KEY* ssl_additional_certs_array[2] = CLEAN;
	UINT num_certs_array_items = 0;

	CERTS_AND_KEY* web_socket_certs = NULL;

	if (svr->mode != 0)
	{
		web_socket_certs = svr->certs_and_key_for_sni;
		AddRef(web_socket_certs->Ref);

		web_socket_certs->DetermineUseCallback = WtgDetermineWebSocketSslCertUseCallback;
		ssl_additional_certs_array[num_certs_array_items] = web_socket_certs;
		num_certs_array_items++;
	}

	Inc(svr->CurrentSslInProgress);
	if (StartSSLEx2(s, svr->widecert_01_controller, svr->widecert_01_controller_key, true, 0, NULL, ssl_additional_certs_array, num_certs_array_items, NULL))
	{
		Dec(svr->CurrentSslInProgress);
		Inc(svr->TotalSslOk);

		while (true)
		{
			UCHAR data[128] = CLEAN;

			if (RecvAll(s, data, sizeof(data), true) == false)
			{
				break;
			}

			if (SendAll(s, data, sizeof(data), true) == false)
			{
				break;
			}
		}
	}
	else
	{
		Dec(svr->CurrentSslInProgress);
		Inc(svr->TotalSslError);
	}

	ReleaseCertsAndKey(web_socket_certs);
}

void sslserverbench_print_stat_thread(THREAD* thread, void* param)
{
	SSL_SERVER_BENCH* svr = (SSL_SERVER_BENCH*)param;

	SSL_SERVER_BENCH_STAT last = CLEAN;

	last.Tick = Tick64();

	UINT num = 0;

	while (svr->Halt == false)
	{
		num++;

		Wait(svr->HaltEvent, 1000);
		if (svr->Halt) break;

		SSL_SERVER_BENCH_STAT current = CLEAN;

		current.CurrentConnections = Count(svr->CurrentConnections);
		current.CurrentSslInProgress = Count(svr->CurrentSslInProgress);
		current.TotalSslOk = Count(svr->TotalSslOk);
		current.TotalSslError = Count(svr->TotalSslError);
		current.Tick = Tick64();

		if (current.Tick > last.Tick)
		{
			SSL_SERVER_BENCH_STAT diff = CLEAN;

			diff.CurrentConnections = current.CurrentConnections - last.CurrentConnections;
			diff.CurrentSslInProgress = current.CurrentSslInProgress - last.CurrentSslInProgress;
			diff.TotalSslOk = current.TotalSslOk - last.TotalSslOk;
			diff.TotalSslError = current.TotalSslError - last.TotalSslError;
			diff.Tick = current.Tick - last.Tick;

			double total_ssl_ok_avr = (double)diff.TotalSslOk * 1000.0 / (double)diff.Tick;
			double total_ssl_err_svr = (double)diff.TotalSslError * 1000.0 / (double)diff.Tick;

			Print("Report #%u: SSL_OK/sec: %.1f, SSL_ERR/sec: %.1f, TCP: %u, SSLNego: %u\n",
				num, total_ssl_ok_avr, total_ssl_err_svr, current.CurrentConnections, current.CurrentSslInProgress);

			last = current;
		}
	}
}

void sslserverbench_thread(THREAD* thread, void* param)
{
	TCP_ACCEPTED_PARAM* accepted_param;
	LISTENER* r;
	SOCK* s;
	SSL_SERVER_BENCH* svr;
	// 引数チェック
	if (thread == NULL || param == NULL)
	{
		return;
	}

	accepted_param = (TCP_ACCEPTED_PARAM*)param;
	r = accepted_param->r;
	s = accepted_param->s;
	AddRef(r->ref);
	AddRef(s->ref);
	svr = (SSL_SERVER_BENCH*)r->ThreadParam;

	AddSockThread(svr->SockThreadList, s, thread);

	NoticeThreadInit(thread);
	AcceptInitEx2(s, true, false);

	Inc(svr->CurrentConnections);

	sslserverbench_accepted(svr, s);

	Dec(svr->CurrentConnections);

	DelSockThread(svr->SockThreadList, s);

	ReleaseSock(s);
	ReleaseListener(r);
}

void sslserverbench_test(UINT num, char** arg)
{
	if (num < 1)
	{
		Print("Usage: sslserverbench <TCP_Port> [mode=0]\n");
		Print("Modes: 0: Simple\n");
		Print("       1: SNI aware\n");
		return;
	}

	CEDAR* cedar;

	char* port_str = arg[0];
	UINT port = ToInt(port_str);

	SSL_SERVER_BENCH* svr = ZeroMalloc(sizeof(SSL_SERVER_BENCH));

	if (num >= 2)
	{
		svr->mode = ToInt(arg[1]);
	}

	svr->HaltEvent = NewEvent();

	svr->testcert_01_chain1 = FileToX("|TestCert_01_Chain1.cer");
	svr->testcert_01_chain2 = FileToX("|TestCert_02_Chain2.cer");
	svr->testcert_03_host = FileToX("|TestCert_03_Host.cer");
	svr->testcert_03_host_key = FileToK("|TestCert_03_Host.key", true, NULL);
	svr->widecert_01_controller = FileToX("|WideCert_01_Controller.cer");
	svr->widecert_01_controller_key = FileToK("|WideCert_01_Controller.key", true, NULL);

	svr->CurrentConnections = NewCounter();
	svr->CurrentSslInProgress = NewCounter();
	svr->TotalSslError = NewCounter();
	svr->TotalSslOk = NewCounter();

	if (svr->testcert_01_chain1 == NULL || svr->testcert_01_chain2 == NULL || svr->testcert_03_host == NULL ||
		svr->testcert_03_host_key == NULL || svr->widecert_01_controller == NULL || svr->widecert_01_controller_key == NULL)
	{
		Print("Load cert failed.\n");
		exit(1);
	}

	THREAD* stat_thread = NewThread(sslserverbench_print_stat_thread, svr);

	LIST* chain_list = NewList(NULL);
	Add(chain_list, svr->testcert_03_host);
	Add(chain_list, svr->testcert_01_chain1);
	Add(chain_list, svr->testcert_01_chain2);

	svr->certs_and_key_for_sni = NewCertsAndKeyFromObjects(chain_list, svr->testcert_03_host_key);

	svr->SockThreadList = NewSockThreadList();

	cedar = NewCedar(NULL, NULL);

	LISTENER* listener = NewListenerEx(cedar, LISTENER_TCP, port, sslserverbench_thread, svr);

	Print("Enter to exit>");
	GetLine(NULL, 0);

	Print("Exiting...\n");

	svr->Halt = true;
	Set(svr->HaltEvent);

	StopAllListener(cedar);
	StopListener(listener);
	ReleaseListener(listener);

	FreeSockThreadList(svr->SockThreadList);

	ReleaseCedar(cedar);

	ReleaseCertsAndKey(svr->certs_and_key_for_sni);

	FreeX(svr->testcert_01_chain1);
	FreeX(svr->testcert_01_chain2);
	FreeX(svr->testcert_03_host);
	FreeK(svr->testcert_03_host_key);
	FreeX(svr->widecert_01_controller);
	FreeK(svr->widecert_01_controller_key);

	ReleaseList(chain_list);

	svr->Halt = true;
	Set(svr->HaltEvent);
	WaitThread(stat_thread, INFINITE);
	ReleaseThread(stat_thread);

	DeleteCounter(svr->CurrentConnections);
	DeleteCounter(svr->CurrentSslInProgress);
	DeleteCounter(svr->TotalSslError);
	DeleteCounter(svr->TotalSslOk);

	ReleaseEvent(svr->HaltEvent);

	Free(svr);
}

void sslclientbench_test(UINT num, char** arg)
{
}

void udpbench_thread(THREAD* thread, void* param)
{
#ifdef	UNIX_LINUX
	bool is_ipv6;
	UDPBST* st;
	SOCK* s;
	UCHAR* buf;
	UINT size;
	UINT i;
	int socket;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	struct iovec msg_iov;
	struct msghdr msg_header;
	UINT count = 1024;
	struct mmsghdr2* msgvec = NULL;
	volatile static UINT dst_rand_addr = 0;
	char* dns_packet_hex = "0008010000010000000000000476706e3109736f66746574686572036e65740000010001";

	BUF* dns_packet_buf = StrToBin(dns_packet_hex);

	Zero(&msg_iov, sizeof(msg_iov));
	Zero(&msg_header, sizeof(msg_header));

	st = (UDPBST*)param;

	is_ipv6 = IsIP6(&st->ip);

	s = NewUDPEx(0, is_ipv6);

	size = st->size;
	buf = Malloc(size);

	Rand(buf, size);

	if (size == dns_packet_buf->Size)
	{
		Copy(buf, dns_packet_buf->Buf, dns_packet_buf->Size);
	}

	if (is_ipv6 == false)
	{
		Zero(&addr, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons((USHORT)st->port);
		IPToInAddr(&addr.sin_addr, &st->ip);
	}
	else
	{
		Zero(&addr6, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons((USHORT)st->port);
		IPToInAddr6(&addr6.sin6_addr, &st->ip);
	}

	socket = s->socket;

	msgvec = ZeroMalloc(sizeof(struct mmsghdr2) * count);
	for (i = 0;i < count;i++)
	{
		struct msghdr* msg_header;
		struct iovec* msg_iov;

		msg_iov = ZeroMalloc(sizeof(struct iovec));
		msg_iov->iov_base = Clone(buf, size);
		msg_iov->iov_len = size;

		msg_header = &msgvec[i].msg_hdr;

		if (is_ipv6 == false)
		{
			msg_header->msg_name = (struct sockaddr*)Clone(&addr, sizeof(struct sockaddr_in));
			msg_header->msg_namelen = sizeof(addr);
		}
		else
		{
			msg_header->msg_name = (struct sockaddr*)Clone(&addr6, sizeof(struct sockaddr_in6));
			msg_header->msg_namelen = sizeof(addr6);
		}

		msg_header->msg_iov = msg_iov;
		msg_header->msg_iovlen = 1;
		msg_header->msg_control = NULL;
		msg_header->msg_controllen = 0;
		msg_header->msg_flags = 0;
	}

	InitAsyncSocket(s);

	while (true)
	{
		if (st->rand_flag && is_ipv6 == false)
		{
			for (i = 0;i < count;i++)
			{
				UINT tmp = dst_rand_addr++;
				struct msghdr* msg_header;
				msg_header = &msgvec[i].msg_hdr;
				struct sockaddr_in* addr = (struct sockaddr_in*)msg_header->msg_name;

				(*((UINT*)(&addr->sin_addr))) = htonl(tmp);
			}
		}

		if (false)
		{
			sendto(socket, buf, size, 0, is_ipv6 ? (struct sockaddr*)&addr6 : (struct sockaddr*)&addr, is_ipv6 ? sizeof(addr6) : sizeof(addr));
		}
		else
		{
			int ret = sendmmsg(socket, msgvec, count, 0);
		}
	}
#endif	// UNIX_LINUX
}

void udpbench_test(UINT num, char** arg)
{
	char target_hostname[MAX_SIZE];
	UINT target_port_start = 0;
	UINT target_port_end = 0;
	UINT size = 0;
	IP ip;
	UINT i, num_ports;
	bool rand_flag = false;
	LIST* ip_list = NULL;

#ifndef	UNIX_LINUX
	Print("Not supported on non-Linux OS.\n");
	return;
#endif	// UNIX_LINUX

	UINT num_cpu = GetNumberOfCpu();

	Zero(target_hostname, sizeof(target_hostname));

	if (num >= 1)
	{
		StrCpy(target_hostname, sizeof(target_hostname), arg[0]);
	}

	if (num >= 2)
	{
		char* ports = arg[1];
		TOKEN_LIST* token = ParseToken(ports, ",:");
		target_port_start = target_port_end = ToInt(arg[1]);

		if (token->NumTokens >= 2)
		{
			target_port_start = ToInt(token->Token[0]);
			target_port_end = ToInt(token->Token[1]);

			target_port_end = MAX(target_port_end, target_port_start);
		}

		FreeToken(token);
	}

	if (num >= 3)
	{
		size = ToInt(arg[2]);
	}

	if (num >= 4)
	{
		rand_flag = ToBool(arg[3]);
	}

	if (num >= 5)
	{
		UINT i;
		for (i = 4;i < num;i++)
		{
			char* ips = arg[i];
			IP ip;

			if (GetIP(&ip, ips) || GetIPEx(&ip, ips, true))
			{
				if (ip_list == NULL)
				{
					ip_list = NewList(NULL);
				}

				Add(ip_list, Clone(&ip, sizeof(IP)));
			}
		}
	}

	if (IsEmptyStr(target_hostname) || target_port_start == 0 || size == 0)
	{
		Print("Usage: udpbench <hostname> <port>|<port_start:port_end> <packet_size> [dest_ip_rand_flag]\n");
		Print("       If packet_size = 36 then send dns query sample packet\n");
		return;
	}

	if (GetIP(&ip, target_hostname) == false)
	{
		if (GetIPEx(&ip, target_hostname, true) == false)
		{
			Print("GetIP for %s failed.\n", target_hostname);
			return;
		}
	}

	if (ip_list != NULL)
	{
		Add(ip_list, Clone(&ip, sizeof(IP)));
	}

	if (ip_list == NULL)
	{
		Print("Target = %r\n", &ip);
	}
	else
	{
		UINT i;
		Print("Targets List = ");
		for (i = 0;i < LIST_NUM(ip_list);i++)
		{
			IP* ip = LIST_DATA(ip_list, i);

			Print("%r ", ip);
		}
		Print("\n");
	}

	if (num_cpu == 0) num_cpu = 1;
	if (num_cpu >= 64) num_cpu = 64;

	Print("Number of CPUs: %u\n", num_cpu);

	num_ports = target_port_end - target_port_start + 1;

	UINT index = 0;

	for (i = 0;i < num_ports;i++)
	{
		UDPBST* st;

		st = ZeroMalloc(sizeof(UDPBST));

		if (ip_list == NULL)
		{
			Copy(&st->ip, &ip, sizeof(IP));
		}
		else
		{
			Copy(&st->ip, LIST_DATA(ip_list, i % LIST_NUM(ip_list)), sizeof(IP));
		}

		st->port = target_port_start + i;
		st->size = size;
		st->rand_flag = rand_flag;

		for (UINT j = 0;j < num_cpu;j++)
		{
			Print("Thread %u: [%r]:%u\n", index++, &st->ip, st->port);
			NewThread(udpbench_thread, st);
		}
	}

	SleepThread(INFINITE);
}

void udprand_test(UINT num, char** arg)
{
	if (num < 2)
	{
		Print("Usage: udprand <dest_ip> <dest_port>\n");
		Print("Warning: Please use this command with great caution.\n");
		Print("         This command may affect network or host computer.\n\n");
		return;
	}

	char* dest_host = arg[0];
	UINT dest_port = ToInt(arg[1]);

	IP dest_ip = CLEAN;
	if (GetIP(&dest_ip, dest_host) == false)
	{
		Print("Failed to get the IP address of '%s'.\n", dest_host);
		return;
	}

	SOCK* s = NewUDP(0);

	Print("Target host: %r:%u\n", &dest_ip, dest_port);
	Print("Local port: %u\n", s->LocalPort);

	for (UINT i = 0;;i++)
	{
		UCHAR rand[64] = CLEAN;
		Rand(rand, sizeof(rand));

		SendTo(s, &dest_ip, dest_port, rand, sizeof(rand));

		if ((i % 3000) == 0)
		{
			//SleepThread(10);
		}
	}
}

void test(UINT num, char **arg)
{
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
	{"udpbench", udpbench_test},
	{"udprand", udprand_test},

	{"sslserverbench", sslserverbench_test},
	{"ssb", sslserverbench_test},

	{"sslclientbench", sslclientbench_test},
	{"scb", sslclientbench_test},
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

	printf("IPA-DN-Ultra-NativeUtilApp Program.\n");

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

