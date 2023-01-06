/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   single_op.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/04 19:13:24 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 03:41:50 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

/* This program reads/writes a single block from a mifare1k*/
#include <string.h>
#include <stdio.h>
#include "../headers/nfc_defs.h"
#include "../headers/nfc_debug.h"
#include "../headers/ft_nfc_transactions.h"
#include "../headers/ft_nfc.h"

#define NFC_READ	1
#define NFC_WRITE	2

int verbose;

int main (void)
{
	t_nfc			*context;
	unsigned char	buffer[256];
	int				read_write;
	unsigned char	send_string[256];
	int				block;
	unsigned int	password[7];
	unsigned char	pwd[7];
	unsigned char	new_pwd[7];
	int				ctrl;
	unsigned char	mifare1KATR[] =	{ 0x3B, 0x8f, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x6A };
	int				card_present;

	verbose = 1;
	read_write = 0;
	block = 0;
	ctrl = 0;
	card_present = 0;
	context = ft_nfc_init();
	while (1)
	{
		read_write = 0;
		block = 0;
		ctrl = 0;
		memset(buffer, 0, 256);
		printf("Insert card\n");
		while(!card_present /* !ctrl */)
		{
			if(nfc_connect(context))
				continue ;
			nfc_get_card_atr(context, buffer);
			if (memcmp(buffer, mifare1KATR, 20))
			{
				printf("Invalid card type.\n");
				nfc_disconnect(context);
				continue ;
			}
			card_present = 1;
			ctrl = 1;
		}
		ctrl = 0;
		// Chose wether to read or write;
		while (!read_write)
		{
			printf("\nread or write? (r/w)\n");
			memset(buffer, 0, 256);
			fgets ((char *)buffer, 255, stdin);
			fflush(stdin);
			if (buffer[0] == 'r')
				read_write = NFC_READ;
			if (buffer[0] == 'w')
				read_write = NFC_WRITE;
		}
		// Gets the block;
		while (!block)
		{
			memset(buffer, 0, 256);
			printf("\nblock to %s:\n", (read_write == 1) ? "read" : "write");
			fgets ((char *)buffer, 255, stdin);
			fflush(stdin);
			block = atoi((char *)buffer);
			if (block > 63)
				continue ;
		}
		// Authenticates the block;
		nfc_start_transaction(context);
		while (!ctrl)
		{
			memset(buffer, 0, 256);
			memset(password, 0, sizeof(password));
			printf("\nPassword to block %2d in hex (AA 99 00 FF F9 0A):\n", block);
			fgets ((char *)buffer, 255, stdin);
			fflush(stdin);
			if (strlen ((char *)buffer) > 18)
			{
				printf("Wrong format\n");
				continue ;
			}
			sscanf((char*) buffer, "%X %X %X %X %X %X\n", &password[0], &password[1], &password[2], &password[3], &password[4], &password[5]);
			for (int i = 0; i < 6 ; i++)
				pwd[i] = (char) password[i];
			pwd[7] = 0;
			printf("password: ");
			for (int i = 0; i < 6 ; i++)
				printf("0x%2X ", pwd[i]);
			printf("\n");
			if (nfc_load_auth_key(context, AUTH_A, pwd, NULL))
			{
				printf("ERROR: Couldn't load auth key\n");
				exit (1);
			}
			if (nfc_auth_key(context, AUTH_A, block))
			{
				printf("Invalid password!\n");
				continue ;
			}
			printf("Password OK!\n");
			ctrl = 1;
		}
		ctrl = 0;
		// Writes new password to authenticated block;
		if (read_write == NFC_WRITE && (block + 1) % 4 == 0)
		{
			while (!ctrl)
			{
				memset(buffer, 0, 256);
				memset(password, 0, sizeof(password));
				printf("\nNew password:\n");
				fgets ((char *)buffer, 255, stdin);
				fflush(stdin);
				if (strlen ((char *)buffer) > 18)
				{
					printf("Wrong format\n");
					continue ;
				}
				sscanf((char*) buffer, "%X %X %X %X %X %X\n", &password[0], &password[1], &password[2], &password[3], &password[4], &password[5]);
				ctrl = 1;
				for (int i = 0; i < 6 ; i++)
					new_pwd[i] = (char) password[i];
			}
			printf("\n\nWrite password (");
			for (int i = 0; i < 6 ; i++)
				printf("0x%02X ", new_pwd[i]);
			printf(") to block %02d?\n", block);
			memset(buffer, 0, 256);
			printf("Press enter to continue and overwrite password.\n");
			fgets((char *) buffer, 256, stdin);
			fflush(stdin);
			if (nfc_write_auth_block(context, new_pwd, NULL, block))
			{
				printf("OPERATION FAILED!\n");
				memset(new_pwd, 0, 7);
			}
			else
			{
				printf("Operaton concluded successfully!\n");
				memset(buffer, 0, 256);
				nfc_read_block(context, buffer, block);
				printf("new password in block %d", block);
				debug_print_hex_bytebuffer(new_pwd, 6);
				memset(new_pwd, 0, 7);
				memset(buffer, 0, 256);
				while (!ctrl)
				{
					printf("Make another transaction? (y/n)");
					fgets((char *) buffer, 256, stdin);
					fflush(stdin);
					if (buffer[0] == 'y' || buffer[0] == 'n')
						ctrl = 1;
				}
				ctrl = 0;
				read_write = 0;
				if (buffer[0] == 'n')
				{
					nfc_end_transaction(context);
					nfc_disconnect(context);
					nfc_cleanup_before_exit(context);
					exit (0);
				}
			}
		}
		// Writes new string to authenticated block;
		if (read_write == NFC_WRITE && (block + 1) % 4 != 0)
		{
			ctrl = 0;
			while(!ctrl)
			{
				memset(buffer, 0, 256);
				memset(send_string, 0, 256);
				printf("String to write;\n");
				fgets((char *) send_string, 256, stdin);
				if (strlen((char *)send_string) > 17)
				{
					printf("Error: string too big; Max 16 bytes.\n");
					continue ;
				}
				ctrl = 1;
			}
			ctrl = 0;
			nfc_read_block(context, buffer, block);
			if (nfc_write_block(context, send_string, block))
			{
				printf("Failed to write '%s' on block %02d", send_string, block);
			}
			nfc_read_block(context, buffer, block);
			buffer[17] = 0;
			printf ("Block %02d now contains \"%s\"\n",block, buffer);
			memset(buffer, 0, 256);
			memset(send_string, 0, 256);
			while (!ctrl)
			{
				printf("Make another transaction? (y/n)");
				fgets((char *) buffer, 256, stdin);
				fflush(stdin);
				if (buffer[0] == 'y' || buffer[0] == 'n')
					ctrl = 1;
			}
			read_write = 0;
			if (buffer[0] == 'n')
			{
				nfc_end_transaction(context);
				nfc_disconnect(context);
				nfc_cleanup_before_exit(context);
				exit (0);
			}
		}
		// Reads from authenticated block;
		if (read_write == NFC_READ)
		{
			memset(buffer, 0, 256);
			if (nfc_read_block(context, buffer, block))
			{
				printf("Error: failed to read block %02d\n", block);
				debug_print_error("Read Block", context->rv);
			}
			printf("Operaton concluded successfully!\n");
			debug_print_bytebuffer(buffer, 16);
			debug_print_hex_bytebuffer(buffer, 16);
			memset(buffer, 0, 256);
			while (!ctrl)
			{
				printf("Make another transaction? (y/n)");
				fgets((char *) buffer, 256, stdin);
				fflush(stdin);
				if (buffer[0] == 'y' || buffer[0] == 'n')
					ctrl = 1;
			}
			read_write = 0;
			ctrl = 0;
			if (buffer[0] == 'n')
			{
				nfc_end_transaction(context);
				nfc_disconnect(context);
				nfc_cleanup_before_exit(context);
				exit (0);
			}
		}
		nfc_end_transaction(context);
		nfc_reconnect(context);
	}
	nfc_disconnect(context);
	nfc_cleanup_before_exit(context);
	printf ("now leaving...\n");
	exit (0);
}