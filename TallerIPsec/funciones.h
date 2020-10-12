/* 
 * File:   funciones.h
 * Author: root
 *
 * Created on 12 de julio de 2010, 18:52
 */

#ifndef _FUNCIONES_H
#define	_FUNCIONES_H

#define	MAXWAIT		10	/* max time to wait for response, sec. */
#define	MAXPACKET	4096	/* max icmp packet size */
#define	MAXDATA		4100	/* max packet size */
#define VERBOSE		1	/* verbose flag */
#define QUIET		2	/* quiet flag */
#define FLOOD		4	/* floodping flag */
#define SIGALRM		5
#define SIGINT		5
#define ENCALG		"3DES-CBC"
#define ENCKEY		"ips3ctasi1key3descbcin01"
#define DECALG		"3DES-CBC"
#define DECKEY		"ips3ctasi1key3descbcin02"
#define SPI		htonl(0x00000100)

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	64
#endif


void decrypt (unsigned char* EncData, int datalen, const char* encAlg, const char* encKey);
void encrypt (unsigned char* EncData, unsigned char* data, int datalen, const char* encAlg, const char* encKey);

#endif	/* _FUNCIONES_H */

