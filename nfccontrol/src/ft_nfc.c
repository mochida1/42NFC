/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nfc.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/10 15:09:04 by mochida           #+#    #+#             */
/*   Updated: 2023/01/05 22:06:01 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "ft_nfc.h"
#include "nfc_defs.h"
#include "nfc_debug.h"
#include "ft_nfc_transactions.h"
#include "ft_messages.h"
#include "nfc_security.h"
#include "mifare1k.h"

extern int	verbose;
int			g_card_type;

/*
	Initializes NFC stuff, returning a structure that must be freed on exit;
	Must be used before any other NFC function call.
	On error prints the erro and exits.
*/
t_nfc	*ft_nfc_init(void)
{
	t_nfc	*context;
	char	*ptr;

	context = calloc (1, sizeof (t_nfc));
	if (!context)
	{
		exit(EXIT_FAILURE);
	}
	if (verbose)
		printf("Establishing context...\n");
	context->rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &context->hContext);
	if (context->rv != SCARD_S_SUCCESS)
		exit(EXIT_FAILURE);
	if (verbose)
		printf("Context successfully initiated;\n");

	/* 
	** Retrieve the available readers list.
	*/
	context->dwReaders = SCARD_AUTOALLOCATE;
	context->rv = SCardListReaders(context->hContext, NULL, (LPSTR)&context->mszReaders, &context->dwReaders);
	if (context->rv != SCARD_S_SUCCESS)
	{
		nfc_cleanup_before_exit(context);
		exit(EXIT_FAILURE);
	}
	if (verbose)
		printf("Card reader table successfully loaded;\n");

	/* 
	** Extract readers from the null separated string and get the total number of readers
	*/
	context->nbReaders = 0;
	ptr = context->mszReaders;
	while (*ptr != '\0')
	{
		ptr += strlen(ptr)+1;
		context->nbReaders++;
	}

	if (context->nbReaders == 0)
	{
		exit(EXIT_FAILURE);
	}

	/* allocate the readers table */
	context->readers = calloc(context->nbReaders, sizeof(char *));
	if (NULL == context->readers)
	{
		exit(EXIT_FAILURE);
	}

	/* fill the readers table */
	context->nbReaders = 0;
	ptr = context->mszReaders;
	while (*ptr != '\0')
	{
		context->readers[context->nbReaders] = ptr;
		ptr += strlen(ptr)+1;
		context->nbReaders++;
	}
	context->dwAtrLen = MAX_ATR_SIZE;
	context->dwActiveProtocol = -1;
	context->rv = 1;
	if (verbose)
		printf("Context successfully initiated.\n");
	return context;
}

/*
	Makes the connection to a card, after the card was powered on by the ACR122U device.
	Returns 0 on succes, 1 on error;
*/
int		nfc_connect(t_nfc *context)
{
	// if (verbose)
	// 	printf ("Trying to connect...\n");
	context->rv = SCardConnect(context->hContext, context->readers[context->reader_nb], SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &context->hCard, &context->dwActiveProtocol);
	if (context->rv != SCARD_S_SUCCESS)
	{
		// if (verbose)
		// 	fprintf (stderr, "No card connected\n");
		sleep (1);
		return (1);
	}
	return (0);
}

/*
	Reconnects connected card, restarting the whole transaction process.
	Returns 0 on succes, 1 on error;
*/
int		nfc_reconnect(t_nfc *context)
{
	unsigned long	rv;

	if (verbose)
		printf("Trying to reconnect to card;\n");
	rv = SCardReconnect(context->hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, SCARD_LEAVE_CARD, &context->dwActiveProtocol);
	if (rv != SCARD_S_SUCCESS)
	{
		if (verbose)
			debug_print_error("nfc_reconnect", rv);
		nfc_cleanup_before_exit(context);
		return (1);
	}
	return (0);
}

/*
	Disconnects connected card, making it effectivelly ending the process.
	Returns 0 on succes, 1 on error;
*/
int		nfc_disconnect(t_nfc *context)
{
	SCARD_READERSTATE rgReaderStates[1];

	rgReaderStates[0].szReader = context->pbReader;
	if (verbose)
		printf("Disconnecting card...\n");
	context->rv = SCardDisconnect(context->hCard, SCARD_EJECT_CARD);
	if (context->rv != SCARD_S_SUCCESS)
	{
		if (verbose)
			fprintf(stderr, "ERROR: couldnt disconnect card;\n");
		nfc_cleanup_before_exit(context);
		return (1);
	}
	rgReaderStates[0].dwCurrentState = SCARD_STATE_EMPTY;
	printf ("Waiting for card to be removed\n");
	while (!SCardGetStatusChange(context->hContext, 10, rgReaderStates, 1))
		continue ;
	if (verbose)
		printf("Card successfully disconnected.\n");
	return (0);
}

/*
	Gets the card type as specified in nfc_defs.h(card types).
	Returns card type, 0 if unknown card type.
*/
int		nfc_validate_card_type(t_nfc *context)
{
	unsigned char	pbAtr[MAX_ATR_SIZE];
	unsigned char	Mifare1KATR[] =	{ 0x3B, 0x8f, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x6A }; //mifare 1k hardcoded
	unsigned char	ntag21x[] =		{ 0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x68 };

	if (verbose)
		printf ("getting card ATR\n");
	memset (pbAtr, 0, MAX_ATR_SIZE);
	nfc_get_card_atr(context, pbAtr);
	/* verifies if card type is mifare classic 1k/4k'ish*/
	if (!memcmp(pbAtr, Mifare1KATR, 20))
	{
		if (verbose)
		{
			printf("Card type detected: Mifare1kClassic\n");
		}
		g_card_type = MIFARE1K;
		return (MIFARE1K);
	}
	if (!memcmp(pbAtr, ntag21x, 20))
	{
		if (verbose)
		{
			printf("Card type detected: NTAG21X\n");
		}
		g_card_type = NTAG21X;
		return (NTAG21X);
	}
	return (UNKOWN_CARD);
}

/*
	Gets card ATR.
	Returns 0 on sucess, a positive integer otherwise.
*/
int		nfc_get_card_atr(t_nfc *context, unsigned char *pbAtr)
{
	context->dwReaderLen = sizeof(context->pbReader);
	memset(pbAtr, 0, MAX_ATR_SIZE);
	context->rv = SCardStatus(context->hCard, /*NULL*/ context->pbReader, &context->dwReaderLen, &context->dwState, &context->dwProt, pbAtr, &context->dwAtrLen);
	if (verbose)
		debug_print_hex_bytebuffer(pbAtr, MAX_ATR_SIZE);
	if (context->rv != SCARD_S_SUCCESS)
	{
		debug_print_error("ScardSTatus", context->rv);
		return (1);
	}
	switch(context->dwActiveProtocol)
	{
		case SCARD_PROTOCOL_T0:
			context->pioSendPci = SCARD_PCI_T0;
			break;
		case SCARD_PROTOCOL_T1:
			context->pioSendPci = SCARD_PCI_T1;
			break;
		default:
			return (1);
	}
	return (0);
}

int		nfc_do_panic(t_nfc *context)
{
	extern int			g_card_type;
	int					is_disconnected;
	unsigned long		dwSendLength;
	unsigned long		dwRecvLength;
	unsigned char		pbRecvBuffer[20];
	unsigned char		send_buffer[] = { 0xFF, 0x00, 0x40, /*LED CONTROL*/0b10010000, 0x04, /*T1 duration*/5, /*T2 duration*/1, /*blink times*/0x0a, /*link to buzzer*/0x01 };
	t_udata				user_data;

	dwSendLength = sizeof(send_buffer);
	dwRecvLength = sizeof(pbRecvBuffer);
	printf ("PANIC!\n");
	msg_log("---------PANIC!---------");
	context->rv = SCardTransmit(context->hCard, context->pioSendPci, send_buffer, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);
	if (context->rv)
		debug_print_error("Panic LED:", context->rv);
	nfc_disconnect(context);
	while (1)
	{
		sleep(1);
		system("date");
		is_disconnected = nfc_connect(context);
		if (!is_disconnected)
		{
			g_card_type = nfc_validate_card_type(context);
			if (g_card_type == MIFARE1K)
			{
				nfc_start_transaction(context);
				msg_get_udata(&user_data);
				nfc_read_user_data(context, &user_data);
				sec_validate_crc(context, &user_data);
				if (!strcmp((const char *) user_data.group, "Bocal"))
				{
					nfc_end_transaction(context);
					nfc_disconnect(context);
					nfc_cleanup_before_exit(context);
					exit (42);
				}
			}
			printf("You are not from bocal!\n");
			memset(&user_data, 0, sizeof(t_udata));
			nfc_end_transaction(context);
			nfc_disconnect(context);
			g_card_type = UNKOWN_CARD;
		}
		printf("PANIC! CALL A STAFF MEMBER!\n");
		sleep(1);
	}
}

int		nfc_led(t_nfc *context, int led_status)
{
	unsigned long	dwSendLength;
	unsigned long	dwRecvLength;
	unsigned char	send_buffer[] =			{ 0xFF, 0x00, 0x40, /*LED CONTROL*/0b10010000, 0x04, /*T1 duration*/3, /*T2 duration*/1, /*blink times*/0x05, /*link to buzzer*/0x01 };
	unsigned char	valid_card_beep[] =		{0xff, 0x00, 0x40, 0b10000010, 0x04, 1, 1, 1, 0x00};
	unsigned char	invalid_card_beep[] =	{0xff, 0x00, 0x40, 0b00000101, 0x04, 2, 2, 2, 0x03};
	unsigned char	end_err_beep[] =		{0xff, 0x00, 0x40, 0b00000101, 0x04, 1, 3, 2, 0x03};
	unsigned char	end_ok_beep[] =			{0xff, 0x00, 0x40, 0b11101101, 0x04, 3, 1, 1, 0x01};
	unsigned char	pbRecvBuffer[20];

	dwSendLength = sizeof(send_buffer);
	dwRecvLength = sizeof(pbRecvBuffer);
	if (led_status == LED_PANIC)
	{
		nfc_do_panic(context);
		return (1);
	}
	else if (led_status == LED_UNK_ERR)
	{
		dwSendLength = sizeof(valid_card_beep);
		if (verbose)
			printf("Unknown error beep.\n");
		context->rv = SCardTransmit(context->hCard, context->pioSendPci, send_buffer, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);	
		return (context->rv);
	}
	else if (led_status == LED_VALID_CARD)
	{
		dwSendLength = sizeof(valid_card_beep);
		if (verbose)
			printf("Valid card beep.\n");
		context->rv = SCardTransmit(context->hCard, context->pioSendPci, valid_card_beep, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);	
		return (context->rv);
	}
	else if (led_status == LED_INVALID_CARD)
	{
		dwSendLength = sizeof(invalid_card_beep);
		if (verbose)
			printf("Invalid card beep.\n");
		context->rv = SCardTransmit(context->hCard, context->pioSendPci, invalid_card_beep, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);	
		return (context->rv);
	}
	else if (led_status == LED_END_ERR)
	{
		dwSendLength = sizeof(invalid_card_beep);
		if (verbose)
			printf("Transaction error beep.\n");
		context->rv = SCardTransmit(context->hCard, context->pioSendPci, end_err_beep, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);	
		return (context->rv);
	}
	else if (led_status == LED_END_OK)
	{
		dwSendLength = sizeof(invalid_card_beep);
		if (verbose)
			printf("Transaction ok beep.\n");
		context->rv = SCardTransmit(context->hCard, context->pioSendPci, end_ok_beep, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);	
		return (context->rv);
	}
	context->rv = SCardTransmit(context->hCard, context->pioSendPci, send_buffer, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);
	return (context->rv);
}

int		nfc_cleanup_before_exit(t_nfc *context)
{
	unsigned long	rv;

	/* free allocated memory */
	if (context->mszReaders)
		SCardFreeMemory(context->hContext, context->mszReaders);
	/* We try to leave things as clean as possible */
	rv = SCardReleaseContext(context->hContext);
	if (context->readers)
	{
		free(context->readers);
		context->readers = NULL;
	}
	free(context);
	return (rv);
}
