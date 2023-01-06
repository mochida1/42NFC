/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nfc_defs.h                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/27 18:18:53 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/04 18:49:03 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NFC_DEFS_H
# define NFC_DEFS_H

#include <PCSC/pcsclite.h>

# define	RCV_BUF_MAX	18 //receive buffer max lenght
# define	MIFARE1K_MAX_BLOCKS	63

//ERRORS
# define	NFC_OK		0
# define	INIT_ERROR	1
# define	NFC_ERROR	2
# define	PLACEHOLDER	4

//CARD TYPES
# define	UNKOWN_CARD	0
# define	MIFARE1K	1
# define	NTAG21X		2

//LED/BUZZER
# define	LED_PANIC			-2	//turns panic mode on. (use for security)
# define	LED_UNK_ERR			-1	//unknown error
# define	LED_INVALID_CARD	0	//invalid card
# define	LED_VALID_CARD		1	//valid card
# define	LED_END_ERR			2	//error during transactions
# define	LED_END_OK			3	//transactions completed successfully

//BLOCKS
# define	BLOCK_CARGO			7

typedef struct	s_nfc
{
	int					rv;
	SCARDCONTEXT		hContext;
	unsigned long		dwReaders;
	LPSTR				mszReaders;
	char				**readers;
	int					nbReaders;
	SCARDHANDLE			hCard;
	unsigned long		dwActiveProtocol;
	unsigned long		dwReaderLen;
	unsigned long		dwState;
	unsigned long		dwProt;
	unsigned long		dwAtrLen;
	char				pbReader[MAX_READERNAME];
	int					reader_nb;
	const				SCARD_IO_REQUEST *pioSendPci;
	SCARD_IO_REQUEST	pioRecvPci;
}	t_nfc;

#endif //NFC_DEFS_H