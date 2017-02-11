/*
SIP User Agent Sample -- by larkguo@gmail.com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

1.Architecture:
	UA ==command==> eXosip2
	UA <==notify==  eXosip2

2.Requires:
	libosip2-5.0.0
	libeXosip2-5.0.0

3.Compile:(assumed that osip2 & eXosip2 are installed in /usr/local)
	gcc -I/usr/local/include -L/usr/local/lib ua.c -o ua -leXosip2 \
	-losip2 -losipparser2 -lpthread

4.Run:
	export LD_LIBRARY_PATH+=/usr/local/lib:
	./ua -r sip:DOMAIN-OR-IP -R sip:X.X.X.X:5060 -f sip:FROM-USER@DOMAIN \
	-t sip:TO-USER@DOMAIN -U AUTH-USER -P AUTH-PASSWORD

5.Register:
	UAC/UAS        PROXY
	1  -REGISTER->
		<-401-
		-REGISTER(auth)->
		<-200-

6.Call:
	UAC  (PROXY)    UAS
	2  -INVITE->
		<-407-
		-INVITE(auth)->
		<-180-
		<-200-        3
		-ACK->
	4  -reINVITE->
		<-200-
		-ACK->
	5  -BYE->
		<-200-
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <osip2/osip_mt.h>
#include <eXosip2/eXosip.h>

#define ualog(a,b...) fprintf(stderr,b);fprintf(stderr,"\n>")
#define null_if_empty(s) (((s)!=NULL&&(s)[0]!='\0')?(s):NULL)
#define UA_VERSION "SipUAv0.1"
#define	BUFFER_LEN (1024)

#define	UA_CMD_REGISTER	('1')
#define	UA_CMD_CALL_START	('2')
#define	UA_CMD_CALL_ANSWER	('3')
#define	UA_CMD_CALL_KEEP	('4')
#define	UA_CMD_CALL_STOP	('5')
#define	UA_CMD_UNREGISTER	('6')
#define	UA_CMD_HELP	('h')
#define	UA_CMD_QUIT	('q')

typedef struct ua_core{
	/* config */
	int expiry;
	int localport;
	int calltimeout;
	char *proxy;
	char *outboundproxy;
	char *username;
	char *password;
	char *from;
	char *to;
	char *contact;
	char *localip;
	char *firewallip;
	char *transport;

	/* dynamic */
	struct eXosip_t *context;
	pthread_t notifythread;
	int running;
	int regid;
	int callid;
	int dialogid;
	int transactionid;
	int cmd;
} uacore;

uacore g_core;
char g_test_sdp[] =
"v=0\r\n"
"o=1 2 3 IN IP4 0.0.0.0\r\n"
"s=Talk\r\n"
"c=IN IP4 0.0.0.0\r\n"
"t=0 0\r\n"
"m=audio 8288 RTP/AVP 0\r\n"
"a=rtpmap:0 PCMU/8000\r\n"
"a=ptime:20\r\n";

static int ua_add_outboundproxy(osip_message_t *msg, const char *outboundproxy);
int ua_cmd_register(uacore *core);
int ua_cmd_unregister(uacore *core);
int ua_cmd_callstart(uacore *core);
int ua_cmd_callring(uacore *core);
int ua_cmd_callanswer(uacore *core);
int ua_cmd_callkeep(uacore *core);
int ua_cmd_callstop(uacore *core);
int ua_notify_callack(uacore *core, eXosip_event_t *je);
int ua_notify_callkeep(uacore *core, eXosip_event_t *je);
void *ua_notify_thread(void *arg);
void ua_stop(int signum);
void usage(void);

void
ua_stop(int signum){
	g_core.running = 0;
}

void
usage(void){
#define short_options "r:f:t:k:U:P:T:e:p:c:l:F:R:hv"
	printf("Usage: " UA_VERSION " [required] [optional]\n"
		"\n\t[required]\n"
		"\t-r --proxy\tsip:proxyhost[:port]\n"
		"\t-f --fromuser\tsip:fromuser@host[:port]\n"
		"\n\t[optional]\n"
		"\t-t --touser\tsip:touser@host[:port]\n"
		"\t-U --username\tauthentication username\n"
		"\t-P --password\tauthentication password\n"
		"\t-T --transport\tUDP|TCP|TLS|DTLS(default UDP)\n"
		"\t-e --expiry\tnumber(default 3600)\n"
		"\t-p --port\tnumber(default 5060)\n"
		"\t-c --contact\tsip:user@host[:port]\n"
		"\t-l --localip\tX.X.X.X(force local IP address)\n"
		"\t-k --keep\tcall keep timeout(default 1800)\n"
		"\t-F --firewallip\tX.X.X.X\n"
		"\t-R --route\toutboundproxy or SBC or P-CSCF(sip:outboundproxyhost[:port])\n"
		"\n\t[help]\n"
		"\t-v --version\n"
		"\t-h --help\n"
		"\n\t[uas example]\n"
		"\tua -r sip:192.168.1.X:5060 -f sip:1001@domain.com"
		" -U 1001 -P 1001 -p 5080\n"
		"\n\t[uac example]\n"
		"\tua -r sip:domain.com -R sip:192.168.1.X:5060 -f sip:1002@domain.com"
		" -t sip:1001@domain.com -U 1002 -P 1002\n"
		"\n\t[ims uac example]\n"
		"\tua -r sip:domain.com -R sip:192.168.1.X:5060 -f sip:1002@domain.com"
		" -t sip:1001@domain.com -U 1001@domain.com -P 1002\n\n"
		);
}
void
ua_cmd_usage(void){
	printf("please select:\n"
		"\t1: register\n"
		"\t2: call start\n"
		"\t3: call answer\n"
		"\t4: call keep\n"
		"\t5: call stop\n"
		"\t6: unregister\n"
		"\th: help\n"
		"\tq: quit\n");
}

int ua_quit(uacore *core){
	if (NULL != core->proxy) free(core->proxy);
	if (NULL != core->from) free(core->from);
	if (NULL != core->to) free(core->to);
	if (NULL != core->contact) free(core->contact);
	if (NULL != core->localip) free(core->localip);
	if (NULL != core->username) free(core->username);
	if (NULL != core->password) free(core->password);
	if (NULL != core->outboundproxy) free(core->outboundproxy);
	if (NULL != core->firewallip) free(core->firewallip);
	if (NULL != core->transport) free(core->transport);
	return 0;
}

/***************************** command *****************************/
static int
ua_add_outboundproxy(osip_message_t *msg, const char *outboundproxy)
{
	int ret = 0;
	char head[BUFFER_LEN] = { 0 };

	if (NULL == null_if_empty(outboundproxy)){
		return 0;
	}
	snprintf(head, sizeof(head)-1, "<%s;lr>", outboundproxy);

	osip_list_special_free(&msg->routes, (void(*)(void*))osip_route_free);
	ret = osip_message_set_route(msg, head);
	return ret;
}

int
ua_cmd_register(uacore *core)
{
	int ret = -1;
	osip_message_t *msg = NULL;

	if (core->regid > 0){ // refresh register
		ret = eXosip_register_build_register(core->context, core->regid, core->expiry, &msg);
		if (0 != ret){
			ualog(LOG_ERR, "register %d refresh build failed %d", core->regid, ret);
			return -1;
		}
	}
	else{ // new register
		core->regid = eXosip_register_build_initial_register(core->context,
			core->from, core->proxy, core->contact, core->expiry, &msg);
		if (core->regid <= 0){
			ualog(LOG_ERR, "register build failed %d", core->regid);
			return -1;
		}
		ua_add_outboundproxy(msg, core->outboundproxy);
	}
	ret = eXosip_register_send_register(core->context, core->regid, msg);
	if (0 != ret){
		ualog(LOG_ERR, "register %d send failed", core->regid);
		return ret;
	}
	return ret;
}

int
ua_cmd_unregister(uacore *core)
{
	int ret = -1;
	osip_message_t *msg = NULL;
	int expiry = 0; //unregister 

	ret = eXosip_register_build_register(core->context, core->regid, expiry, &msg);
	if (0 != ret){
		ualog(LOG_ERR, "unregister %d build failed %d", core->regid, ret);
		return -1;
	}

	ret = eXosip_register_send_register(core->context, core->regid, msg);
	if (0 != ret){
		ualog(LOG_ERR, "register %d send failed %d", core->regid, ret);
		return ret;
	}
	core->regid = 0;
	return ret;
}

int
ua_cmd_callstart(uacore *core)
{
	int ret = -1;
	char session_exp[BUFFER_LEN] = { 0 };
	osip_message_t *msg = NULL;

	ret = eXosip_call_build_initial_invite(core->context, &msg, core->to, core->from, NULL, NULL);
	if (0 != ret){
		ualog(LOG_ERR, "call build failed", core->from, core->to);
		return -1;
	}
	ua_add_outboundproxy(msg, core->outboundproxy);
	osip_message_set_body(msg, g_test_sdp, strlen(g_test_sdp));
	osip_message_set_content_type(msg, "application/sdp");

	/* UAC call timeout */
	snprintf(session_exp, sizeof(session_exp)-1, "%i;refresher=uac", core->calltimeout);
	osip_message_set_header(msg, "Session-Expires", session_exp);
	osip_message_set_supported(msg, "timer");

	core->callid = eXosip_call_send_initial_invite(core->context, msg);
	ret = (core->callid > 0) ? 0 : -1;
	return ret;
}

int
ua_cmd_callring(uacore *core)
{
	int ret = 0;
	int code = 180;
	osip_message_t *msg = NULL;

	ret = eXosip_call_build_answer(core->context, core->transactionid, code, &msg);
	if (0 != ret){
		ualog(LOG_ERR, "call %d build ring failed", core->callid);
		return ret;
	}

	ret = eXosip_call_send_answer(core->context, core->transactionid, code, msg);
	if (0 != ret){
		ualog(LOG_ERR, "call %d send ring failed", core->callid);
		return ret;
	}
	return ret;
}

int
ua_cmd_callanswer(uacore *core)
{
	int ret = 0;
	int code = 200;
	osip_message_t *msg = NULL;

	ret = eXosip_call_build_answer(core->context, core->transactionid, code, &msg);
	if (0 != ret){
		ualog(LOG_ERR, "call %d build answer failed", core->callid);
		return ret;
	}

	/* UAS call timeout */
	osip_message_set_supported(msg, "timer");

	osip_message_set_body(msg, g_test_sdp, strlen(g_test_sdp));
	osip_message_set_content_type(msg, "application/sdp");

	ret = eXosip_call_send_answer(core->context, core->transactionid, code, msg);
	if (0 != ret){
		ualog(LOG_ERR, "call %d send answer failed", core->callid);
		return ret;
	}
	return ret;
}

int
ua_cmd_callkeep(uacore *core)
{
	int ret = -1;
	char session_exp[BUFFER_LEN] = { 0 };
	osip_message_t *msg = NULL;

	ret = eXosip_call_build_request(core->context, core->dialogid, "INVITE", &msg);
	if (NULL == msg){
		ualog(LOG_ERR, "call %d build keep failed", core->callid);
		return ret;
	}

	ret = eXosip_call_send_request(core->context, core->dialogid, msg);
	if (0 != ret){
		ualog(LOG_ERR, "call %d send keep failed", core->callid);
		return ret;
	}
	return ret;
}

int
ua_cmd_callstop(uacore *core)
{
	int ret = 0;
	ret = eXosip_call_terminate(core->context, core->callid, core->dialogid);
	if (0 != ret){
		ualog(LOG_ERR, "call %d send stop failed", core->callid);
		return ret;
	}
	return ret;
}

/***************************** notify *****************************/
int
ua_notify_callack(uacore *core, eXosip_event_t *je)
{
	int ret = 0;
	osip_message_t *msg = NULL;

	ret = eXosip_call_build_ack(core->context, je->did, &msg);
	if (0 != ret){
		ualog(LOG_ERR, "call %d build ack failed", je->cid);
		return ret;
	}
	ua_add_outboundproxy(msg, core->outboundproxy);

	ret = eXosip_call_send_ack(core->context, je->did, msg);
	if (0 != ret){
		ualog(LOG_ERR, "call %d send ack failed", je->cid);
		return ret;
	}
	return ret;
}

int
ua_notify_callkeep(uacore *core, eXosip_event_t *je)
{
	int ret = 0;
	int code = 200;
	osip_message_t *msg = NULL;
	eXosip_call_build_answer(core->context, je->tid, code, &msg);
	if (NULL == msg){
		ualog(LOG_ERR, "call %d send keep answer failed", je->cid);
	}
	ret = eXosip_call_send_answer(core->context, je->tid, code, msg);
	if (0 != ret){
		ualog(LOG_ERR, "call %d send keep answer failed", je->cid);
		return ret;
	}
	return ret;
}

int
ua_notidy_callid(uacore *core, eXosip_event_t *je)
{
	core->callid = je->cid;
	core->dialogid = je->did;
	core->transactionid = je->tid;
	return 0;
}

/* event notify loop */
void *
ua_notify_thread(void *arg)
{
	uacore *core = (uacore *)arg;
	int ret = 0;
	int code = -1;

	while (core->running){
		osip_message_t *msg = NULL;
		eXosip_event_t *je = eXosip_event_wait(core->context, 0, 1);
		if (NULL == je){
			/* auto process,such as:register refresh,auth,call keep... */
			eXosip_automatic_action(core->context);
			osip_usleep(100000);
			continue;
		}

		eXosip_lock(core->context);
		eXosip_automatic_action(core->context);
		switch (je->type){
		case EXOSIP_REGISTRATION_SUCCESS:
			if (UA_CMD_REGISTER == core->cmd){
				ualog(LOG_INFO, "register %d sucess", je->rid);
			}
			else {
				ualog(LOG_INFO, "unregister %d sucess", je->rid);
			}
			break;
		case EXOSIP_REGISTRATION_FAILURE:
			if (UA_CMD_REGISTER == core->cmd){
				ualog(LOG_INFO, "register %d failure", je->rid);
			}
			else{
				ualog(LOG_INFO, "unregister %d failure", je->rid);
			}
			break;
		case EXOSIP_CALL_INVITE:
			ua_notidy_callid(core, je);
			ua_cmd_callring(core);
			ualog(LOG_INFO, "call %d incoming,please answer...", je->cid);
			break;
		case EXOSIP_CALL_REINVITE:
			ua_notidy_callid(core, je);
			ualog(LOG_INFO, "call %d keep", je->cid);
			ua_notify_callkeep(core, je);
			break;
		case EXOSIP_CALL_RINGING:
			ua_notidy_callid(core, je);
			ualog(LOG_INFO, "call %d ring", je->cid);
			break;
		case EXOSIP_CALL_ANSWERED:
			ua_notidy_callid(core, je);
			if (je->response)
				code = osip_message_get_status_code(je->response);
			ualog(LOG_INFO, "call %d answer %d", je->cid, code);
			ua_notify_callack(core, je);
			break;
		case EXOSIP_CALL_NOANSWER:
			ua_notidy_callid(core, je);
			ualog(LOG_INFO, "call %d noanswer", je->cid);
			break;
		case EXOSIP_CALL_REQUESTFAILURE:
		case EXOSIP_CALL_GLOBALFAILURE:
		case EXOSIP_CALL_SERVERFAILURE:
			ua_notidy_callid(core, je);
			if (je->response)
				code = osip_message_get_status_code(je->response);
			ualog(LOG_INFO, "call %d failture %d", je->cid, code);
			break;
		case EXOSIP_CALL_ACK:
			ua_notidy_callid(core, je);
			ualog(LOG_INFO, "call %d ack", je->cid);
			break;
		case EXOSIP_CALL_CLOSED:
			ualog(LOG_INFO, "call %d stop", je->cid);
			break;
		case EXOSIP_CALL_CANCELLED:
			ualog(LOG_INFO, "call %d cancel", je->cid);
			break;
		case EXOSIP_CALL_RELEASED:
			ualog(LOG_INFO, "call %d release", je->cid);
			break;
		default:
			break;
		}
		eXosip_unlock(core->context);
		eXosip_event_free(je);
	}
	eXosip_quit(core->context);
	osip_free(core->context);

	pthread_detach(pthread_self());
	return 0;
}

/***************************** main *****************************/
int
main(int argc, char *argv[])
{
	int ret = 0;
	struct servent *service = NULL;

	/* init */
	signal(SIGINT, ua_stop);
	memset(&g_core, 0, sizeof(uacore));
	g_core.running = 1;
	g_core.expiry = 3600;
	g_core.localport = 5060;
	g_core.calltimeout = 1800;

	/* config */
	for (;;){
		int c = getopt(argc, argv, short_options);
		if (-1 == c)
			break;
		switch (c){
		case 'r':
			g_core.proxy = strdup(optarg);
			break;
		case 'f':
			g_core.from = strdup(optarg);
			break;
		case 't':
			g_core.to = strdup(optarg);
			break;
		case 'c':
			g_core.contact = strdup(optarg);
			break;
		case 'e':
			g_core.expiry = atoi(optarg);
			break;
		case 'l':
			g_core.localip = strdup(optarg);
			break;
		case 'p':
			service = getservbyname(optarg, "udp");
			if (service) g_core.localport = ntohs(service->s_port);
			else g_core.localport = atoi(optarg);
			break;
		case 'k':
			g_core.calltimeout = atoi(optarg);
			break;
		case 'U':
			g_core.username = strdup(optarg);
			break;
		case 'P':
			g_core.password = strdup(optarg);
			break;
		case 'R':
			g_core.outboundproxy = strdup(optarg);
			break;
		case 'F':
			g_core.firewallip = strdup(optarg);
			break;
		case 'T':
			g_core.transport = strdup(optarg);
			break;
		case 'v':
			printf("%s\n", UA_VERSION);
			return 0;
		case 'h':
		default:
			usage();
			return 0;
		}
	}
	if (!g_core.proxy || !g_core.from){
		usage();
		return -1;
	}
	if (NULL == g_core.transport)
		g_core.transport = strdup("UDP");
	ualog(LOG_INFO, "proxy: %s", g_core.proxy);
	ualog(LOG_INFO, "outboundproxy: %s", g_core.outboundproxy);
	ualog(LOG_INFO, "from: %s", g_core.from);
	ualog(LOG_INFO, "to: %s", g_core.to);
	ualog(LOG_INFO, "contact: %s", g_core.contact);
	ualog(LOG_INFO, "expiry: %d", g_core.expiry);
	ualog(LOG_INFO, "localport: %d", g_core.localport);
	ualog(LOG_INFO, "transport: %s", g_core.transport);
	ualog(LOG_INFO, "calltimeout: %d", g_core.calltimeout);

	g_core.context = eXosip_malloc();
	if (eXosip_init(g_core.context)){
		ualog(LOG_ERR, "init failed");
		return -1;
	}
	if (osip_strcasecmp(g_core.transport, "UDP") == 0){
		ret = eXosip_listen_addr(g_core.context, IPPROTO_UDP, NULL, g_core.localport, AF_INET, 0);
	}
	else if (osip_strcasecmp(g_core.transport, "TCP") == 0){
		ret = eXosip_listen_addr(g_core.context, IPPROTO_TCP, NULL, g_core.localport, AF_INET, 0);
	}
	else if (osip_strcasecmp(g_core.transport, "TLS") == 0){
		ret = eXosip_listen_addr(g_core.context, IPPROTO_TCP, NULL, g_core.localport, AF_INET, 1);
	}
	else if (osip_strcasecmp(g_core.transport, "DTLS") == 0){
		ret = eXosip_listen_addr(g_core.context, IPPROTO_UDP, NULL, g_core.localport, AF_INET, 1);
	}
	else{
		ret = -1;
	}
	if (ret){
		ualog(LOG_ERR, "listen failed");
		return -1;
	}
	if (g_core.localip){
		ualog(LOG_INFO, "local address: %s", g_core.localip);
		eXosip_masquerade_contact(g_core.context, g_core.localip, g_core.localport);
	}
	if (g_core.firewallip){
		ualog(LOG_INFO, "firewall address: %s:%i", g_core.firewallip, g_core.localport);
		eXosip_masquerade_contact(g_core.context, g_core.firewallip, g_core.localport);
	}
	eXosip_set_user_agent(g_core.context, UA_VERSION);
	if (g_core.username && g_core.password){
		ualog(LOG_INFO, "username: %s", g_core.username);
		ualog(LOG_INFO, "password: ******");
		if (eXosip_add_authentication_info(g_core.context, g_core.username,
			g_core.username, g_core.password, NULL, NULL)){
			ualog(LOG_ERR, "add_authentication_info failed");
			return -1;
		}
	}

	/* start */
	pthread_create(&g_core.notifythread, NULL, ua_notify_thread, &g_core);
	ualog(LOG_INFO, UA_VERSION " start");
	ua_cmd_usage();
	printf(">");
	while (g_core.running){ //command loop
		char c = getchar();

		eXosip_lock(g_core.context);
		switch (c){
		case UA_CMD_REGISTER:
			g_core.cmd = c;
			ua_cmd_register(&g_core);
			break;
		case UA_CMD_CALL_START:
			ua_cmd_callstart(&g_core);
			break;
		case UA_CMD_CALL_ANSWER:
			ua_cmd_callanswer(&g_core);
			break;
		case UA_CMD_CALL_KEEP:
			ua_cmd_callkeep(&g_core);
			break;
		case UA_CMD_CALL_STOP:
			ua_cmd_callstop(&g_core);
			break;
		case UA_CMD_UNREGISTER:
			g_core.cmd = c;
			ua_cmd_unregister(&g_core);
			break;
		case UA_CMD_HELP:
			ua_cmd_usage();
			break;
		case UA_CMD_QUIT:
			g_core.running = 0;
			break;
		case '\n':
			printf(">");
			break;
		default:
			ualog(LOG_ERR, "unknown '%c'", c);
			break;
		}
		eXosip_unlock(g_core.context);
	}

	/* stop */
	ua_quit(&g_core);
	printf("%s stop\n", UA_VERSION);
	return 0;
}
