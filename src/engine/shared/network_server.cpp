/* (c) Magnus Auvinen. See licence.txt in the root of the distribution for more information. */
/* If you are missing that file, acquire a complete release at teeworlds.com.                */
#include <base/system.h>
#include "network.h"

#include "config.h"

#include <engine/message.h>
#include <engine/shared/protocol.h>
#include <engine/external/md5/md5.h>

 //TODO: reduce dummy map size
const int DummyMapCrc = 0xbeae0b9f;

static const unsigned char g_aDummyMapData[] = {0x44,0x41,0x54,0x41,0x04,0x00,0x00,0x00,0x15,0x02,0x00,0x00,0xC8,0x01,0x00,0x00,0x05,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x4C,0x01,0x00,0x00,0x4D,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0C,0x00,0x00,0x00,0x28,0x00,0x00,0x00,0x6C,0x00,0x00,0x00,0xB0,0x00,0x00,0x00,0xE0,0x00,0x00,0x00,0x44,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x42,0x00,0x00,0x00,0x98,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x14,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x04,0x00,0x3C,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00,0x80,0x80,0x80,0x01,0x00,0x04,0x00,0x3C,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64,0x00,0x00,0x00,0x64,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xE5,0xED,0xE1,0xC7,0x80,0x80,0x80,0x80,0x00,0x80,0x80,0x80,0x00,0x00,0x05,0x00,0x28,0x00,0x00,0x00,0x90,0x72,0xDE,0x98,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xE4,0xE1,0xF5,0xD1,0x80,0x80,0x80,0xF3,0x00,0x80,0x80,0x80,0x01,0x00,0x05,0x00,0x5C,0x00,0x00,0x00,0x90,0x72,0xDE,0x98,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x01,0x00,0x00,0x00,0xE5,0xED,0xE1,0xC7,0x80,0x80,0x80,0x80,0x00,0x80,0x80,0x80,0x20,0xA1,0xEA,0x00,0x63,0xE7,0x3D,0x44,0x0C,0x00,0x00,0x00,0x00,0x00,0x80,0x40,0x00,0x00,0x8D,0x42,0x00,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x78,0x9C,0x63,0x38,0xFD,0xF9,0xBF,0xC3,0x8D,0x6F,0xFF,0x19,0x4C,0x79,0x18,0xC0,0x34,0x90,0x7F,0x40,0x9D,0x93,0x01,0xC4,0x07,0xD3,0x0D,0x0C,0x60,0x1C,0x07,0xA4,0x5A,0x80,0x78,0x1D,0x10,0xFF,0x67,0xC0,0xE4,0x9F,0x01,0xE2,0x17,0x50,0x36,0x36,0x3E,0x1C,0xB0,0xA0,0xB1,0xA1,0xF8,0x3F,0x10,0x80,0x84,0x60,0x34,0x00,0x3E,0x5E,0x23,0x81,0x78,0x9C,0x63,0x60,0x40,0x05,0x00,0x00,0x10,0x00,0x01};

static SECURITY_TOKEN ToSecurityToken(const unsigned char* pData)
{
	return (int)pData[0] | (pData[1] << 8) | (pData[2] << 16) | (pData[3] << 24);
}

#define MACRO_LIST_LINK_FIRST(Object, First, Prev, Next) \
	{ if(First) First->Prev = Object; \
	Object->Prev = (struct CBan *)0; \
	Object->Next = First; \
	First = Object; }

#define MACRO_LIST_LINK_AFTER(Object, After, Prev, Next) \
	{ Object->Prev = After; \
	Object->Next = After->Next; \
	After->Next = Object; \
	if(Object->Next) \
		Object->Next->Prev = Object; \
	}

#define MACRO_LIST_UNLINK(Object, First, Prev, Next) \
	{ if(Object->Next) Object->Next->Prev = Object->Prev; \
	if(Object->Prev) Object->Prev->Next = Object->Next; \
	else First = Object->Next; \
	Object->Next = 0; Object->Prev = 0; }

#define MACRO_LIST_FIND(Start, Next, Expression) \
	{ while(Start && !(Expression)) Start = Start->Next; }

bool CNetServer::Open(NETADDR BindAddr, int MaxClients, int MaxClientsPerIP, int Flags)
{
	// zero out the whole structure
	mem_zero(this, sizeof(*this));

	// open socket
	m_Socket = net_udp_create(BindAddr);
	if(!m_Socket.type)
		return false;

	// clamp clients
	m_MaxClients = MaxClients;
	if(m_MaxClients > NET_MAX_CLIENTS)
		m_MaxClients = NET_MAX_CLIENTS;
	if(m_MaxClients < 1)
		m_MaxClients = 1;

	m_MaxClientsPerIP = MaxClientsPerIP;

	IOHANDLE urandom = io_open("/dev/urandom", IOFLAG_READ);
	if (urandom) {
		io_read(urandom, m_SecurityTokenSeed, sizeof(m_SecurityTokenSeed));
		io_close(urandom);
	}
	else
	{
		dbg_msg("security", "/dev/urandom is not available. using sv_rcon_password for security token seed, make sure you have a long password!");
		str_copy(m_SecurityTokenSeed, g_Config.m_SvRconPassword, sizeof(m_SecurityTokenSeed));
		long timestamp = time_get();
		md5_state_t md5;
		md5_byte_t digest[16];
		// do over 9000 rounds of md5 on the rcon password, to make it harder to recover the password from the token values
		for (int i = 0; i < 1000000; i++)
		{
			md5_init(&md5);
			md5_append(&md5, (unsigned char*)m_SecurityTokenSeed, sizeof(m_SecurityTokenSeed));
			md5_append(&md5, (unsigned char*)&timestamp, sizeof(timestamp));
			md5_finish(&md5, digest);
			mem_copy(m_SecurityTokenSeed, digest, sizeof(m_SecurityTokenSeed) < sizeof(digest) ? sizeof(m_SecurityTokenSeed) : sizeof(digest));
		}
	}
 	m_NumConAttempts = 0;
	m_TimeNumConAttempts = time_get();

	for(int i = 0; i < NET_MAX_CLIENTS; i++)
		m_aSlots[i].m_Connection.Init(m_Socket);

	// setup all pointers for bans
	for(int i = 1; i < NET_SERVER_MAXBANS-1; i++)
	{
		m_BanPool[i].m_pNext = &m_BanPool[i+1];
		m_BanPool[i].m_pPrev = &m_BanPool[i-1];
	}

	m_BanPool[0].m_pNext = &m_BanPool[1];
	m_BanPool[NET_SERVER_MAXBANS-1].m_pPrev = &m_BanPool[NET_SERVER_MAXBANS-2];
	m_BanPool_FirstFree = &m_BanPool[0];

	return true;
}

int CNetServer::SetCallbacks(NETFUNC_NEWCLIENT pfnNewClient, NETFUNC_DELCLIENT pfnDelClient, void *pUser)
{
	m_pfnNewClient = pfnNewClient;
	m_pfnDelClient = pfnDelClient;
	m_UserPtr = pUser;
	return 0;
}

int CNetServer::SetCallbacks(NETFUNC_NEWCLIENT pfnNewClient, NETFUNC_NEWCLIENT_NOAUTH pfnNewClientNoAuth, NETFUNC_DELCLIENT pfnDelClient, void *pUser)
{
	m_pfnNewClient = pfnNewClient;
	m_pfnNewClientNoAuth = pfnNewClientNoAuth;
	m_pfnDelClient = pfnDelClient;
	m_UserPtr = pUser;
	return 0;
}

int CNetServer::Close()
{
	// TODO: implement me
	return 0;
}

int CNetServer::Drop(int ClientID, const char *pReason)
{
	// TODO: insert lots of checks here
	/*NETADDR Addr = ClientAddr(ClientID);

	dbg_msg("net_server", "client dropped. cid=%d ip=%d.%d.%d.%d reason=\"%s\"",
		ClientID,
		Addr.ip[0], Addr.ip[1], Addr.ip[2], Addr.ip[3],
		pReason
		);*/
	if(m_pfnDelClient)
		m_pfnDelClient(ClientID, pReason, m_UserPtr);

	m_aSlots[ClientID].m_Connection.Disconnect(pReason);

	return 0;
}

int CNetServer::BanGet(int Index, CBanInfo *pInfo)
{
	CBan *pBan;
	for(pBan = m_BanPool_FirstUsed; pBan && Index; pBan = pBan->m_pNext, Index--)
		{}

	if(!pBan)
		return 0;
	*pInfo = pBan->m_Info;
	return 1;
}

int CNetServer::BanNum()
{
	int Count = 0;
	CBan *pBan;
	for(pBan = m_BanPool_FirstUsed; pBan; pBan = pBan->m_pNext)
		Count++;
	return Count;
}

void CNetServer::BanRemoveByObject(CBan *pBan)
{
	int IpHash = (pBan->m_Info.m_Addr.ip[0]+pBan->m_Info.m_Addr.ip[1]+pBan->m_Info.m_Addr.ip[2]+pBan->m_Info.m_Addr.ip[3]+
					pBan->m_Info.m_Addr.ip[4]+pBan->m_Info.m_Addr.ip[5]+pBan->m_Info.m_Addr.ip[6]+pBan->m_Info.m_Addr.ip[7]+
					pBan->m_Info.m_Addr.ip[8]+pBan->m_Info.m_Addr.ip[9]+pBan->m_Info.m_Addr.ip[10]+pBan->m_Info.m_Addr.ip[11]+
					pBan->m_Info.m_Addr.ip[12]+pBan->m_Info.m_Addr.ip[13]+pBan->m_Info.m_Addr.ip[14]+pBan->m_Info.m_Addr.ip[15])&0xff;
	char aAddrStr[NETADDR_MAXSTRSIZE];
	net_addr_str(&pBan->m_Info.m_Addr, aAddrStr, sizeof(aAddrStr));
	dbg_msg("netserver", "removing ban on %s", aAddrStr);
	MACRO_LIST_UNLINK(pBan, m_BanPool_FirstUsed, m_pPrev, m_pNext);
	MACRO_LIST_UNLINK(pBan, m_aBans[IpHash], m_pHashPrev, m_pHashNext);
	MACRO_LIST_LINK_FIRST(pBan, m_BanPool_FirstFree, m_pPrev, m_pNext);
}

int CNetServer::BanRemove(NETADDR Addr)
{
	int IpHash = (Addr.ip[0]+Addr.ip[1]+Addr.ip[2]+Addr.ip[3]+Addr.ip[4]+Addr.ip[5]+Addr.ip[6]+Addr.ip[7]+
					Addr.ip[8]+Addr.ip[9]+Addr.ip[10]+Addr.ip[11]+Addr.ip[12]+Addr.ip[13]+Addr.ip[14]+Addr.ip[15])&0xff;
	CBan *pBan = m_aBans[IpHash];

	MACRO_LIST_FIND(pBan, m_pHashNext, net_addr_comp(&pBan->m_Info.m_Addr, &Addr) == 0);

	if(pBan)
	{
		BanRemoveByObject(pBan);
		return 0;
	}

	return -1;
}

int CNetServer::BanAdd(NETADDR Addr, int Seconds, const char *pReason)
{
	int IpHash = (Addr.ip[0]+Addr.ip[1]+Addr.ip[2]+Addr.ip[3]+Addr.ip[4]+Addr.ip[5]+Addr.ip[6]+Addr.ip[7]+
					Addr.ip[8]+Addr.ip[9]+Addr.ip[10]+Addr.ip[11]+Addr.ip[12]+Addr.ip[13]+Addr.ip[14]+Addr.ip[15])&0xff;
	int Stamp = -1;
	CBan *pBan;

	// remove the port
	Addr.port = 0;

	if(Seconds)
		Stamp = time_timestamp() + Seconds;

	// search to see if it already exists
	pBan = m_aBans[IpHash];
	MACRO_LIST_FIND(pBan, m_pHashNext, net_addr_comp(&pBan->m_Info.m_Addr, &Addr) == 0);
	if(pBan)
	{
		// adjust the ban
		pBan->m_Info.m_Expires = Stamp;
		return 0;
	}

	if(!m_BanPool_FirstFree)
		return -1;

	// fetch and clear the new ban
	pBan = m_BanPool_FirstFree;
	MACRO_LIST_UNLINK(pBan, m_BanPool_FirstFree, m_pPrev, m_pNext);

	// setup the ban info
	pBan->m_Info.m_Expires = Stamp;
	pBan->m_Info.m_Addr = Addr;
	str_copy(pBan->m_Info.m_Reason, pReason, sizeof(pBan->m_Info.m_Reason));

	// add it to the ban hash
	MACRO_LIST_LINK_FIRST(pBan, m_aBans[IpHash], m_pHashPrev, m_pHashNext);

	// insert it into the used list
	{
		if(m_BanPool_FirstUsed)
		{
			CBan *pInsertAfter = m_BanPool_FirstUsed;
			MACRO_LIST_FIND(pInsertAfter, m_pNext, Stamp < pInsertAfter->m_Info.m_Expires);

			if(pInsertAfter)
				pInsertAfter = pInsertAfter->m_pPrev;
			else
			{
				// add to last
				pInsertAfter = m_BanPool_FirstUsed;
				while(pInsertAfter->m_pNext)
					pInsertAfter = pInsertAfter->m_pNext;
			}

			if(pInsertAfter)
			{
				MACRO_LIST_LINK_AFTER(pBan, pInsertAfter, m_pPrev, m_pNext);
			}
			else
			{
				MACRO_LIST_LINK_FIRST(pBan, m_BanPool_FirstUsed, m_pPrev, m_pNext);
			}
		}
		else
		{
			MACRO_LIST_LINK_FIRST(pBan, m_BanPool_FirstUsed, m_pPrev, m_pNext);
		}
	}

	// drop banned clients
	{
		char Buf[128];
		NETADDR BanAddr;

		if(Stamp > -1)
		{
			int Mins = (Seconds + 59) / 60;
			if(Mins <= 1)
				str_format(Buf, sizeof(Buf), "You have been banned for 1 minute (%s)", pReason);
			else
				str_format(Buf, sizeof(Buf), "You have been banned for %d minutes (%s)", Mins, pReason);
		}
		else
			str_format(Buf, sizeof(Buf), "You have been banned for life (%s)", pReason);

		for(int i = 0; i < MaxClients(); i++)
		{
			BanAddr = m_aSlots[i].m_Connection.PeerAddress();
			BanAddr.port = 0;

			if(net_addr_comp(&Addr, &BanAddr) == 0)
				Drop(i, Buf);
		}
	}
	return 0;
}

int CNetServer::Update()
{
	int Now = time_timestamp();
	for(int i = 0; i < MaxClients(); i++)
	{
		m_aSlots[i].m_Connection.Update();
		if(m_aSlots[i].m_Connection.State() == NET_CONNSTATE_ERROR)
			Drop(i, m_aSlots[i].m_Connection.ErrorString());
	}

	// remove expired bans
	while(m_BanPool_FirstUsed && m_BanPool_FirstUsed->m_Info.m_Expires > -1 && m_BanPool_FirstUsed->m_Info.m_Expires < Now)
	{
		CBan *pBan = m_BanPool_FirstUsed;
		BanRemoveByObject(pBan);
	}

	return 0;
}

SECURITY_TOKEN CNetServer::GetToken(const NETADDR &Addr)
{
	md5_state_t md5;
	md5_byte_t digest[16];
	SECURITY_TOKEN SecurityToken;
	md5_init(&md5);
 	md5_append(&md5, (unsigned char*)m_SecurityTokenSeed, sizeof(m_SecurityTokenSeed));
	md5_append(&md5, (unsigned char*)&Addr, sizeof(Addr));
 	md5_finish(&md5, digest);
	SecurityToken = ToSecurityToken(digest);
 	if (SecurityToken == NET_SECURITY_TOKEN_UNKNOWN ||
		SecurityToken == NET_SECURITY_TOKEN_UNSUPPORTED)
			SecurityToken = 1;
 	return SecurityToken;
}

void CNetServer::SendControl(NETADDR &Addr, int ControlMsg, const void *pExtra, int ExtraSize, SECURITY_TOKEN SecurityToken)
{
	CNetBase::SendControlMsg(m_Socket, &Addr, 0, ControlMsg, pExtra, ExtraSize, SecurityToken);
}

int CNetServer::NumClientsWithAddr(NETADDR Addr)
{
	NETADDR ThisAddr = Addr, OtherAddr;
 	int FoundAddr = 0;
	ThisAddr.port = 0;
 	for(int i = 0; i < MaxClients(); ++i)
	{
		if(m_aSlots[i].m_Connection.State() == NET_CONNSTATE_OFFLINE)
			continue;
 		OtherAddr = m_aSlots[i].m_Connection.PeerAddress();
		OtherAddr.port = 0;
		if(!net_addr_comp(&ThisAddr, &OtherAddr))
			FoundAddr++;
	}
 	return FoundAddr;
}

int CNetServer::TryAcceptClient(NETADDR &Addr, SECURITY_TOKEN SecurityToken, bool VanillaAuth)
{
	// check for sv_max_clients_per_ip
	if (NumClientsWithAddr(Addr) + 1 > m_MaxClientsPerIP)
	{
		char aBuf[128];
		str_format(aBuf, sizeof(aBuf), "Only %d players with the same IP are allowed", m_MaxClientsPerIP);
		CNetBase::SendControlMsg(m_Socket, &Addr, 0, NET_CTRLMSG_CLOSE, aBuf, sizeof(aBuf), SecurityToken);
		return -1; // failed to add client
	}
 	int Slot = -1;
	for(int i = 0; i < MaxClients(); i++)
	{
		if(m_aSlots[i].m_Connection.State() == NET_CONNSTATE_OFFLINE)
		{
			Slot = i;
			break;
		}
	}
 	if (Slot == -1)
	{
		const char FullMsg[] = "This server is full";
		CNetBase::SendControlMsg(m_Socket, &Addr, 0, NET_CTRLMSG_CLOSE, FullMsg, sizeof(FullMsg), SecurityToken);
 		return -1; // failed to add client
	}
 	// init connection slot
	m_aSlots[Slot].m_Connection.DirectInit(Addr, SecurityToken);
 	if (VanillaAuth)
	{
		// client sequence is unknown if the auth was done
		// connection-less
		m_aSlots[Slot].m_Connection.SetUnknownSeq();
		// correct sequence
		m_aSlots[Slot].m_Connection.SetSequence(6);
	}
 	if (g_Config.m_Debug)
	{
		char aAddrStr[NETADDR_MAXSTRSIZE];
		net_addr_str(&Addr, aAddrStr, sizeof(aAddrStr));
		dbg_msg("security", "Client accepted %s", aAddrStr);
	}
 	if (VanillaAuth)
		m_pfnNewClientNoAuth(Slot, m_UserPtr);
	else
		m_pfnNewClient(Slot, m_UserPtr);
 	return Slot; // done
}

void CNetServer::SendMsgs(NETADDR &Addr, const CMsgPacker *Msgs[], int num)
{
	CNetPacketConstruct m_Construct;
	mem_zero(&m_Construct, sizeof(m_Construct));
	unsigned char *pChunkData = &m_Construct.m_aChunkData[m_Construct.m_DataSize];
 	for (int i = 0; i < num; i++)
	{
		const CMsgPacker *pMsg = Msgs[i];
		CNetChunkHeader Header;
		Header.m_Flags = NET_CHUNKFLAG_VITAL;
		Header.m_Size = pMsg->Size();
		Header.m_Sequence = i+1;
		pChunkData = Header.Pack(pChunkData);
		mem_copy(pChunkData, pMsg->Data(), pMsg->Size());
		*((unsigned char*)pChunkData) <<= 1;
		*((unsigned char*)pChunkData) |= 1;
		pChunkData += pMsg->Size();
		m_Construct.m_NumChunks++;
	}
 	//
	m_Construct.m_DataSize = (int)(pChunkData-m_Construct.m_aChunkData);
	CNetBase::SendPacket(m_Socket, &Addr, &m_Construct, GetToken(Addr));
}

// connection-less msg packet without token-support
void CNetServer::OnPreConnMsg(NETADDR &Addr, CNetPacketConstruct &Packet)
{
	bool IsCtrl = Packet.m_Flags&NET_PACKETFLAG_CONTROL;
	int CtrlMsg = m_RecvUnpacker.m_Data.m_aChunkData[0];
 	// log flooding
	//TODO: remove
	if (g_Config.m_Debug)
	{
		int64 Now = time_get();
 		if (Now - m_TimeNumConAttempts > time_freq())
			// reset
			m_NumConAttempts = 0;
 		m_NumConAttempts++;
 		if (m_NumConAttempts > 100)
		{
			dbg_msg("security", "flooding detected");
 			m_TimeNumConAttempts = Now;
			m_NumConAttempts = 0;
		}
	}
 	if (IsCtrl && CtrlMsg == NET_CTRLMSG_CONNECT)
	{
		if (g_Config.m_SvVanillaAntiSpoof)
		{
			// simulate accept
			SendControl(Addr, NET_CTRLMSG_CONNECTACCEPT, SECURITY_TOKEN_MAGIC,
						sizeof(SECURITY_TOKEN_MAGIC), NET_SECURITY_TOKEN_UNSUPPORTED);
 			// Begin vanilla compatible token handshake
			// The idea is to pack a security token in the gametick
			// parameter of NETMSG_SNAPEMPTY. The Client then will
			// return the token/gametick in NETMSG_INPUT, allowing
			// us to validate the token.
			// https://github.com/eeeee/ddnet/commit/b8e40a244af4e242dc568aa34854c5754c75a39a
 			// Before we can send NETMSG_SNAPEMPTY, the client needs
			// to load a map, otherwise it might crash. The map
			// should be as small as is possible and directly available
			// to the client. Therefor a dummy map is sent in the same
			// packet.
 			// send mapchange + map data + con_ready + 3 x empty snap (with token)
			CMsgPacker MapChangeMsg(NETMSG_MAP_CHANGE);
 			MapChangeMsg.AddString("dummy", 0);
			MapChangeMsg.AddInt(DummyMapCrc);
			MapChangeMsg.AddInt(sizeof(g_aDummyMapData));
 			CMsgPacker MapDataMsg(NETMSG_MAP_DATA);
 			MapDataMsg.AddInt(1); // last chunk
			MapDataMsg.AddInt(DummyMapCrc); // crc
			MapDataMsg.AddInt(0); // chunk index
			MapDataMsg.AddInt(sizeof(g_aDummyMapData)); // map size
			MapDataMsg.AddRaw(g_aDummyMapData, sizeof(g_aDummyMapData)); // map data
 			CMsgPacker ConReadyMsg(NETMSG_CON_READY);
 			CMsgPacker SnapEmptyMsg(NETMSG_SNAPEMPTY);
			SECURITY_TOKEN SecurityToken = GetVanillaToken(Addr);
			SnapEmptyMsg.AddInt((int)SecurityToken);
			SnapEmptyMsg.AddInt((int)SecurityToken + 1);
 			// send all chunks/msgs in one packet
			const CMsgPacker *Msgs[] = {&MapChangeMsg, &MapDataMsg, &ConReadyMsg,
										&SnapEmptyMsg, &SnapEmptyMsg, &SnapEmptyMsg};
			SendMsgs(Addr, Msgs, 6);
		}
		else
		{
			// accept client directy
			SendControl(Addr, NET_CTRLMSG_CONNECTACCEPT, SECURITY_TOKEN_MAGIC,
						sizeof(SECURITY_TOKEN_MAGIC), NET_SECURITY_TOKEN_UNSUPPORTED);
 			TryAcceptClient(Addr, NET_SECURITY_TOKEN_UNSUPPORTED);
		}
	}
	else if(!IsCtrl && g_Config.m_SvVanillaAntiSpoof)
	{
		CNetChunkHeader h;
 		unsigned char *pData = Packet.m_aChunkData;
		pData = h.Unpack(pData);
		CUnpacker Unpacker;
		Unpacker.Reset(pData, h.m_Size);
		int Msg = Unpacker.GetInt() >> 1;
 		if (Msg == NETMSG_INPUT)
		{
			SECURITY_TOKEN SecurityToken = Unpacker.GetInt();
			if (SecurityToken == GetVanillaToken(Addr))
			{
				if (g_Config.m_Debug)
					dbg_msg("security", "new client (vanilla handshake)");
				// try to accept client skipping auth state
				TryAcceptClient(Addr, NET_SECURITY_TOKEN_UNSUPPORTED, true);
			}
			else if (g_Config.m_Debug)
				dbg_msg("security", "invalid token (vanilla handshake)");
 		}
		else
		{
			if (g_Config.m_Debug)
			{
				dbg_msg("security", "invalid preconn msg %d", Msg);
			}
		}
	}
}

void CNetServer::OnTokenCtrlMsg(NETADDR &Addr, int ControlMsg, const CNetPacketConstruct &Packet)
{
	if (ClientExists(Addr))
		return; // silently ignore
 	if (ControlMsg == NET_CTRLMSG_CONNECT)
	{
		bool SupportsToken = Packet.m_DataSize >=
								(int)(1 + sizeof(SECURITY_TOKEN_MAGIC) + sizeof(SECURITY_TOKEN)) &&
								!mem_comp(&Packet.m_aChunkData[1], SECURITY_TOKEN_MAGIC, sizeof(SECURITY_TOKEN_MAGIC));
 		if (SupportsToken)
		{
			// response connection request with token
			SECURITY_TOKEN Token = GetToken(Addr);
			SendControl(Addr, NET_CTRLMSG_CONNECTACCEPT, SECURITY_TOKEN_MAGIC, sizeof(SECURITY_TOKEN_MAGIC), Token);
		}
	}
	else if (ControlMsg == NET_CTRLMSG_ACCEPT && Packet.m_DataSize == 1 + sizeof(SECURITY_TOKEN))
	{
		SECURITY_TOKEN Token = ToSecurityToken(&Packet.m_aChunkData[1]);
		if (Token == GetToken(Addr))
		{
			// correct token
			// try to accept client
			if (g_Config.m_Debug)
				dbg_msg("security", "new client (ddnet token)");
			TryAcceptClient(Addr, Token);
		}
		else
		{
			// invalid token
			if (g_Config.m_Debug)
				dbg_msg("security", "invalid token");
		}
	}
}

bool CNetServer::ClientExists(const NETADDR &Addr)
{
	for(int i = 0; i < MaxClients(); i++)
	{
		NETADDR test = m_aSlots[i].m_Connection.PeerAddress();
		if(m_aSlots[i].m_Connection.State() != NET_CONNSTATE_OFFLINE &&
			net_addr_comp(&test, &Addr) == 0)
		{
			// found
			return true;
		}
	}
 	// doesn't exist
	return false;
}

/*
	TODO: chopp up this function into smaller working parts
*/
int CNetServer::Recv(CNetChunk *pChunk)
{
	unsigned Now = time_timestamp();

	while(1)
	{
		NETADDR Addr;

		// check for a chunk
		if(m_RecvUnpacker.FetchChunk(pChunk))
			return 1;

		// TODO: empty the recvinfo
		int Bytes = net_udp_recv(m_Socket, &Addr, m_RecvUnpacker.m_aBuffer, NET_MAX_PACKETSIZE);

		// no more packets for now
		if(Bytes <= 0)
			break;

		if(CNetBase::UnpackPacket(m_RecvUnpacker.m_aBuffer, Bytes, &m_RecvUnpacker.m_Data) == 0)
		{
			CBan *pBan = 0;
			NETADDR BanAddr = Addr;
			int IpHash = (BanAddr.ip[0]+BanAddr.ip[1]+BanAddr.ip[2]+BanAddr.ip[3]+BanAddr.ip[4]+BanAddr.ip[5]+BanAddr.ip[6]+BanAddr.ip[7]+
							BanAddr.ip[8]+BanAddr.ip[9]+BanAddr.ip[10]+BanAddr.ip[11]+BanAddr.ip[12]+BanAddr.ip[13]+BanAddr.ip[14]+BanAddr.ip[15])&0xff;
			BanAddr.port = 0;

			// search a ban
			for(pBan = m_aBans[IpHash]; pBan; pBan = pBan->m_pHashNext)
			{
				if(net_addr_comp(&pBan->m_Info.m_Addr, &BanAddr) == 0)
					break;
			}

			// check if we just should drop the packet
			if(pBan)
			{
				// banned, reply with a message
				char BanStr[128];
				if(pBan->m_Info.m_Expires > -1)
				{
					int Mins = ((pBan->m_Info.m_Expires - Now)+59)/60;
					if(Mins <= 1)
						str_format(BanStr, sizeof(BanStr), "Banned for 1 minute (%s)", pBan->m_Info.m_Reason);
					else
						str_format(BanStr, sizeof(BanStr), "Banned for %d minutes (%s)", Mins, pBan->m_Info.m_Reason);
				}
				else
					str_format(BanStr, sizeof(BanStr), "Banned for life (%s)", pBan->m_Info.m_Reason);
				CNetBase::SendControlMsg(m_Socket, &Addr, 0, NET_CTRLMSG_CLOSE, BanStr, str_length(BanStr) + 1, NET_SECURITY_TOKEN_UNSUPPORTED);
				continue;
			}

			if(m_RecvUnpacker.m_Data.m_Flags&NET_PACKETFLAG_CONNLESS)
			{
				pChunk->m_Flags = NETSENDFLAG_CONNLESS;
				pChunk->m_ClientID = -1;
				pChunk->m_Address = Addr;
				pChunk->m_DataSize = m_RecvUnpacker.m_Data.m_DataSize;
				pChunk->m_pData = m_RecvUnpacker.m_Data.m_aChunkData;
				return 1;
			}
			else
			{
				// normal packet, find matching slot
				bool Found = false;
				for(int i = 0; i < MaxClients(); i++)
				{
					NETADDR target = m_aSlots[i].m_Connection.PeerAddress();
					if(net_addr_comp(&target, &Addr) == 0)
					{
						if(m_aSlots[i].m_Connection.State() == NET_CONNSTATE_OFFLINE ||
							m_aSlots[i].m_Connection.State() == NET_CONNSTATE_ERROR)
							continue;
						Found = true;
						if(m_aSlots[i].m_Connection.Feed(&m_RecvUnpacker.m_Data, &Addr))
						{
							if(m_RecvUnpacker.m_Data.m_DataSize)
								m_RecvUnpacker.Start(&Addr, &m_aSlots[i].m_Connection, i);
						}
					}
				}
				if (!Found)
				{
					if(m_RecvUnpacker.m_Data.m_Flags&NET_PACKETFLAG_CONTROL &&
						m_RecvUnpacker.m_Data.m_DataSize > 1)
						// got control msg with extra size (should support token)
						OnTokenCtrlMsg(Addr, m_RecvUnpacker.m_Data.m_aChunkData[0], m_RecvUnpacker.m_Data);
					else
						// got connection-less ctrl or sys msg
						OnPreConnMsg(Addr, m_RecvUnpacker.m_Data);
				}
			}
		}
	}
	return 0;
}

int CNetServer::Send(CNetChunk *pChunk)
{
	if(pChunk->m_DataSize >= NET_MAX_PAYLOAD)
	{
		dbg_msg("netserver", "packet payload too big. %d. dropping packet", pChunk->m_DataSize);
		return -1;
	}

	if(pChunk->m_Flags&NETSENDFLAG_CONNLESS)
	{
		// send connectionless packet
		CNetBase::SendPacketConnless(m_Socket, &pChunk->m_Address, pChunk->m_pData, pChunk->m_DataSize);
	}
	else
	{
		int Flags = 0;
		dbg_assert(pChunk->m_ClientID >= 0, "errornous client id");
		dbg_assert(pChunk->m_ClientID < MaxClients(), "errornous client id");

		if(pChunk->m_Flags&NETSENDFLAG_VITAL)
			Flags = NET_CHUNKFLAG_VITAL;

		if(m_aSlots[pChunk->m_ClientID].m_Connection.QueueChunk(Flags, pChunk->m_DataSize, pChunk->m_pData) == 0)
		{
			if(pChunk->m_Flags&NETSENDFLAG_FLUSH)
				m_aSlots[pChunk->m_ClientID].m_Connection.Flush();
		}
		else
		{
			Drop(pChunk->m_ClientID, "Error sending data");
		}
	}
	return 0;
}

void CNetServer::SetMaxClientsPerIP(int Max)
{
	// clamp
	if(Max < 1)
		Max = 1;
	else if(Max > NET_MAX_CLIENTS)
		Max = NET_MAX_CLIENTS;

	m_MaxClientsPerIP = Max;
}
