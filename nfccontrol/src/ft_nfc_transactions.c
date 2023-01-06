/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nfc_transactions.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/25 14:51:15 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 19:31:12 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <string.h>
#include <PCSC/winscard.h>
#include "nfc_defs.h"
#include "ft_nfc_transactions.h"

/*
	This source file contains the abstractions to commonly used 
	transaction functions used by the ACR122U:
	* Load sector authentication keys;
	* Authenticate sector;
	* Read block;
	* Write on block;
	* Original read, write, increment, decrement value_blocks; (this is actually really bad, don't used it);
	* LED/buzzer control;

	should work with all ISO 14443 compliant tags (13.56MHz).
*/


/*
	Starts transactions on smartcard, making it only accessible by the application;
	Returns 0 on success, 1 on failure.
*/
int	nfc_start_transaction(t_nfc *context)
{
	context->rv = SCardBeginTransaction(context->hCard);
	if (context->rv != SCARD_S_SUCCESS)
	{
		nfc_cleanup_before_exit(context);
		return (1);
	}
	return (0);
}

/*
	Ends transactions on smartcard and disconnects it, releasing it for other applications usage;
	Returns 0 on success, 1 on failure.
*/
int	nfc_end_transaction(t_nfc *context)
{
	if (verbose)
		printf("Ending transaction.\n");
	context->rv = SCardEndTransaction(context->hCard, SCARD_LEAVE_CARD);
	if (context->rv != SCARD_S_SUCCESS)
	{
		if (verbose)
			debug_print_error("nfc_end_transaction", context->rv);
		nfc_cleanup_before_exit(context);
		return (1);
	}
	return (0);
}

/*
	Loads a password into reader's volatile memmory. If NULL is passed as password, goes to default password.
	**params**
	context: pcsc context;
	key_type: either AUTH_A, AUTH_B or AUTH_X for both passwords;
	block: block to be unlocked;
	password_a: first password;
	password_b: second(optional) password;
	Returns 0 on sucess, a positive integer otherwise.
*/
int	nfc_load_auth_key(t_nfc *context, char key_type, unsigned char *password_a, unsigned char *password_b)
{
	unsigned char	pbRecvBuffer[RCV_BUF_MAX];
	unsigned long	dwSendLength, dwRecvLength;
	unsigned char	load_key[] = { 0xFF, 0x82, 0x00, 0x00, 0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // loads default key A into reader volatile memory
	
	dwSendLength = sizeof(load_key);
	dwRecvLength = sizeof(pbRecvBuffer);
	if (!key_type || key_type > 3)
	{
		if (verbose)
			printf("Error: Invalid key type!\n");
		exit (1);
	}
	if (key_type & AUTH_A)
	{
		if (password_a)
			memcpy(&load_key[5], password_a, 6);
		memset (pbRecvBuffer, 0, RCV_BUF_MAX);
		if (verbose)
		{
			printf("Loading key A...\n");
			debug_print_hex_bytebuffer(&load_key[5], 6);
		}
		context->rv = SCardTransmit(context->hCard, context->pioSendPci, load_key, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (context->rv != SCARD_S_SUCCESS)
		{
			if (verbose)
				debug_print_error("AUTH A", context->rv);
			nfc_cleanup_before_exit(context);
			exit (1);
		}
		if (verbose)
			printf("AUTH A:%0X\n", pbRecvBuffer[0]);
	}
	if (key_type & AUTH_B)
	{
		if (password_b)
			memcpy(&load_key[5], password_a, 6);
		else
			memset(&load_key[5], 0xff, 6);
		load_key[3] = 1;
		memset (pbRecvBuffer, 0, RCV_BUF_MAX);
		if (verbose)
		{
			printf("Loading key B...");
			debug_print_hex_bytebuffer(&load_key[5], 6);
		}
		context->rv = SCardTransmit(context->hCard, context->pioSendPci, load_key, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (context->rv != SCARD_S_SUCCESS)
		{
			if (verbose)
				debug_print_error("AUTH A", context->rv);
			nfc_cleanup_before_exit(context);
			exit (1);
		}
		if (verbose)
			printf("AUTH B:%0X\n", pbRecvBuffer[0]);
	}
	return (0);
}

/*
	Tries to authenticate a loaded key of key_type(AUTH_A, AUTH_B, AUTH_X) into given block.
	Returns 0 on sucess, a positive integer otherwise.
*/
int nfc_auth_key(t_nfc *context, char key_type, char block)
{
	unsigned char	pbRecvBuffer[RCV_BUF_MAX];
	unsigned long	dwSendLength, dwRecvLength;
	unsigned char	auth_key[] = { 0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, /*bloco*/0, /*A ou B*/0x60, /*key number*/0x00 }; // autentica o bloco 0x04 do cartão
	int				rv;

	rv = 0;
	auth_key[7] = block;
	dwSendLength = sizeof(auth_key);
	dwRecvLength = sizeof(pbRecvBuffer);
	if (verbose)
		printf("At block %02d: ", block);
	if (key_type & AUTH_A)
	{
		memset (pbRecvBuffer, 0, RCV_BUF_MAX);
		if (verbose)
		{
			printf("authenticating key A: ");
			debug_print_hex_bytebuffer(auth_key, 10);
		}
		context->rv = SCardTransmit(context->hCard, context->pioSendPci, auth_key, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (context->rv != SCARD_S_SUCCESS)
		{
			if (verbose)
				debug_print_error("AUTH A", context->rv);
			nfc_cleanup_before_exit(context);
			exit (1);
		}
		if (pbRecvBuffer[0] == 0x63)
		{
			rv = 1;
			if (verbose)
				printf ("auth A failed! \n");
		}
		else if (pbRecvBuffer[0] == 0x90)
		{
			if (verbose)
			{
				printf ("auth A ok!\n");
			}
		}
		else
		{
			printf("Something really weird happened at \"nfc_auth_key()\"\n");
			exit(1);
		}
	}
	if (key_type & AUTH_B)
	{
		auth_key[8] = 0x61;
		memset (pbRecvBuffer, 0, RCV_BUF_MAX);
		if (verbose)
		{
			printf("Authenticating key B: ");
			debug_print_hex_bytebuffer(auth_key, 10);
		}
		context->rv = SCardTransmit(context->hCard, context->pioSendPci, auth_key, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (context->rv != SCARD_S_SUCCESS)
		{
			if (verbose)
				debug_print_error("AUTH B", context->rv);
			nfc_cleanup_before_exit(context);
			exit (1);
		}
		if (pbRecvBuffer[0] == 0x63)
		{
			if (verbose)
				printf ("Auth B failed! \n");
			rv = 2;
		}
		else if (pbRecvBuffer[0] == 0x90)
		{
			if (verbose)
				printf ("Auth B ok!\n");
		}
		else
		{
			printf ("Something really weird happened at \"nfc_auth_key()\"\n");
			exit (1);
		}
	}
	return (rv);
}

/*
	Reads a *block* of data from the card, copying it to dest.
	Returns 0 on sucess, a positive integer otherwise.
*/
int nfc_read_block(t_nfc *context, unsigned char *dest, char block)
{
	unsigned char	pbRecvBuffer[RCV_BUF_MAX];
	unsigned long	dwSendLength, dwRecvLength;
	unsigned char	pbSendBuffer[] = { 0xFF, 0xb0, 0x00, 0, 0x10 }; //reads from block 04, 16 bytes

	dwSendLength = sizeof(pbSendBuffer);
	dwRecvLength = sizeof(pbRecvBuffer);
	memset (pbRecvBuffer, 0, RCV_BUF_MAX);
	if (verbose)
		printf("Reading Block %02d\n", block);
	pbSendBuffer[3] = block;
	context->rv = SCardTransmit(context->hCard, context->pioSendPci, pbSendBuffer, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);
	if (context->rv != SCARD_S_SUCCESS)
	{
		if (verbose)
			debug_print_error("Read blk", context->rv);
		nfc_cleanup_before_exit(context);
		exit (1);
	}
	if (verbose)
		debug_print_hex_bytebuffer(pbRecvBuffer, RCV_BUF_MAX);
	if (pbRecvBuffer[0] == 0x63 && pbRecvBuffer[16] != 0x90)
		return (1);
	if (pbRecvBuffer[16] == 0x90)
	{
		memset(dest, 0, 16);
		memcpy(dest, pbRecvBuffer, 16);
		return (0);
	}
	return (2);
}

/*
	Writes strictly 16bytes of *data* into given *block*;
	returns 0 on sucess, 1 on failure.
*/
int nfc_write_block(t_nfc *context, unsigned char data[], char block)
{
	unsigned char	pbRecvBuffer[RCV_BUF_MAX];
	unsigned long	dwSendLength, dwRecvLength;
	unsigned char	pbSendBuffer[] = {0xff, 0xd6, 0x00, /*block*/0, /*numbytes*/16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	if (((block + 1)%4) == 0)
	{
		printf("ERROR: Tried normal write on AUTH BLOCK %d\n", block);
		return (1);
	}
	dwSendLength = sizeof(pbSendBuffer);
	dwRecvLength = sizeof(pbRecvBuffer);
	memset (pbRecvBuffer, 0, RCV_BUF_MAX);
	if (verbose)
		printf("Writing Block %02d\n", block);
	pbSendBuffer[3] = block;
	memcpy(&pbSendBuffer[5], data, 16);
	context->rv = SCardTransmit(context->hCard, context->pioSendPci, pbSendBuffer, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);
	if (context->rv != SCARD_S_SUCCESS)
	{
		if (verbose)
			debug_print_error("Write blk", context->rv);
		nfc_cleanup_before_exit(context);
		return (1);
	}
	if (pbRecvBuffer[0] == 0x63 && pbRecvBuffer[16] != 0x90)
	{
		if (verbose)
			debug_print_hex_bytebuffer(pbRecvBuffer, RCV_BUF_MAX);
		return (1);
	}
	if (pbRecvBuffer[0] == 0x90)
	{
		if (verbose)
			debug_print_hex_bytebuffer(pbRecvBuffer, RCV_BUF_MAX);
		return (0);
	}
	return (2);
}

/*
	Writes strictly 16bytes of *data* into given *block*;
	returns 0 on sucess, 1 on failure.
*/
int nfc_write_auth_block(t_nfc *context, unsigned char pass_a[6], unsigned char pass_b[6], char block)
{
	unsigned char	pbRecvBuffer[RCV_BUF_MAX];
	unsigned long	dwSendLength, dwRecvLength;
	unsigned char	pbSendBuffer[] = {0xff, 0xd6, 0x00, /*block*/0, /*numbytes*/16,  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0x80, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if (((block + 1)%4) != 0)
	{
		printf("ERROR: Tried normal auth write on normal block %d\n", block);
		return (1);
	}
	dwSendLength = sizeof(pbSendBuffer);
	dwRecvLength = sizeof(pbRecvBuffer);
	memset (pbRecvBuffer, 0, RCV_BUF_MAX);
	if (verbose)
		printf("Writing AUTH Block %02d\n", block);
	pbSendBuffer[3] = block;
	if (pass_a)
		memcpy(&pbSendBuffer[5], pass_a, 6);
	if (pass_b)		
		memcpy(&pbSendBuffer[16], pass_b, 6);
	context->rv = SCardTransmit(context->hCard, context->pioSendPci, pbSendBuffer, dwSendLength, &context->pioRecvPci, pbRecvBuffer, &dwRecvLength);
	if (context->rv != SCARD_S_SUCCESS)
	{
		if (verbose)
			debug_print_error("Write auth blk", context->rv);
		nfc_cleanup_before_exit(context);
		return (1);
	}
	if (pbRecvBuffer[0] == 0x63 && pbRecvBuffer[16] != 0x90)
	{
		if (verbose)
			debug_print_hex_bytebuffer(pbRecvBuffer, RCV_BUF_MAX);
		return (1);
	}
	if (pbRecvBuffer[0] == 0x90)
	{
		if (verbose)
			debug_print_hex_bytebuffer(pbRecvBuffer, RCV_BUF_MAX);
		return (0);
	}
	return (2);
}