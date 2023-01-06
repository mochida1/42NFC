/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nfc_security.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/31 05:50:16 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/06 16:41:46 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <inttypes.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include "nfc_defs.h"
#include "mifare1k.h"
#include "ft_nfc_transactions.h"
#include "ft_messages.h"

/* PROTOTYPES*/
unsigned int sec_crc8(unsigned int crc, unsigned char const *data, size_t len);

void	*check_for_ssh(void)
{
	FILE	*fd;
	char	buffer[200];

	while (1)
	{
		fd = popen("who | grep pts | wc -l", "r");
		fgets(buffer, 200, fd);
		pclose(fd);
		if (buffer[0] != '0' || strlen(buffer) > 2) // Certifies there aren't more than 10 terminals opened
		{
			msg_log("CRITICAL: SSH CONNECTION DETECTED.\n", FT_MSG_SEC);
			fd = popen("w", "r");
			while (fgets(buffer, 200, fd))
			{
				msg_log(buffer, FT_MSG_SEC);
			}
			pclose(fd);
			system("echo 1 > /proc/sys/kernel/sysrq"); //reboots the system;
			system("echo s > /proc/sysrq-trigger");
			sleep(1);
			system("echo o > /proc/sysrq-trigger");
		}
		sleep(2);
	}
}

/*
	uses the elements CRCs as a single 16 byte crc_string;
*/
int	sec_get_crc_string(unsigned char crc_string[], unsigned int *crc, int elements)
{
	size_t			size;
	int				i;
	unsigned char	*ptr;

	ptr = (unsigned char *) crc;
	size = sizeof(unsigned int) * elements;
	i = 0;
	memset(crc_string, 0, 17);
	while(i < (int) size)
	{
		crc_string[i] = ptr[i];
		i++;
	}
	return (0);
}

#define CRC_

int				sec_nfc_update_crc(t_nfc *context, t_udata *user_data)
{
	unsigned int	crc[4];
	unsigned char	const_data[65];
	unsigned char	crc_string[17];
	nfc_load_auth_key(context, AUTH_A, user_data->hash1_psw, NULL);
	nfc_auth_key(context, AUTH_A, user_data->hash1_block);
	memset(const_data, 0 , 65);
	strncat((char *)const_data, (const char *)user_data->login, 16);
	strncat((char *)const_data, (const char *)user_data->group, 16);
	strncat((char *)const_data, (const char *)user_data->campus, 16);
	strncat((char *)const_data, (const char *)user_data->cohort, 16);
	crc[0] = sec_crc8(user_data->login_block, const_data, 64);			// generates crc digest of login+group+campus+cohort
	crc[1] = sec_crc8(user_data->date_block, user_data->date, 16);		// crc date
	crc[2] = sec_crc8(user_data->weekly_block, user_data->weekly, 16);	// crc weekly
	memset(const_data,0 , 65);
	strncat((char *)const_data, (const char *)user_data->uuid1, 16);
	strncat((char *)const_data, (const char *)user_data->uuid2, 16);
	strncat((char *)const_data, (const char *)user_data->uuid3, 16);
	crc[3] = sec_crc8(user_data->uuid1_block, const_data, 16);

	sec_get_crc_string(crc_string, crc, 4);	
	if (verbose)
		debug_print_hex_bytebuffer(crc_string, 16);
	if (nfc_write_block(context, crc_string, user_data->hash1_block))
	{
		msg_log("------CRITICAL-------", FT_MSG_ERR);
		msg_log((char *) user_data->login, FT_MSG_ERR);
		msg_log("crc update failed!", FT_MSG_ERR);
		fprintf(stderr, "CRITICAL ERROR: Couldn't update CRC;\n");
		return (1);
	}
	return (0);
}

/*
	Returns a CRC from data of size len using a seed CRC;
*/
unsigned int sec_crc8(unsigned int crc, unsigned char const *data, size_t len)
{
	if (data == NULL)
		return 0;
	crc = ~crc & 0xff;
	while (len--) {
		crc ^= *data++;
		for (unsigned k = 0; k < 8; k++)
			crc = crc & 1 ? (crc >> 1) ^ 0xb2 : crc >> 1;
	}
	return crc ^ 0xff;
}

int		sec_validate_crc(t_nfc *context, t_udata *user_data)
{
	unsigned int	crc[4];
	unsigned char	empty_string[17];
	unsigned char	const_data[65];
	unsigned char	crc_string[17];

	msg_log("starting CRC validation", FT_MSG_SEC);
	if (verbose)
		printf("Validating CRC\n");
	memset(empty_string, 0, 17);
	memset(const_data, 0 , 65);
	strncat((char *)const_data, (const char *)user_data->login, 16);
	strncat((char *)const_data, (const char *)user_data->group, 16);
	strncat((char *)const_data, (const char *)user_data->campus, 16);
	strncat((char *)const_data, (const char *)user_data->cohort, 16);
	crc[0] = sec_crc8(user_data->login_block, const_data, 64);			// generates crc digest of login+group+campus+cohort
	crc[1] = sec_crc8(user_data->date_block, user_data->date, 16);		// crc date
	crc[2] = sec_crc8(user_data->weekly_block, user_data->weekly, 16);	// crc weekly
	memset(const_data,0 , 65);
	strncat((char *)const_data, (const char *)user_data->uuid1, 16);
	strncat((char *)const_data, (const char *)user_data->uuid2, 16);
	strncat((char *)const_data, (const char *)user_data->uuid3, 16);
	crc[3] = sec_crc8(user_data->uuid1_block, const_data, 16);			//crc uuid1+uuid2+uuid3;

	//ccheck if CRCs are valid;
	sec_get_crc_string(crc_string, crc, 4);
	if (verbose)
	{
		printf ("CRC: ");
		debug_print_hex_bytebuffer(crc_string, 64);
	}
	if (!memcmp(empty_string, user_data->hash1, 16) && !memcmp("DATE", user_data->date, 4)) // if it's the 1st time the card was presented
	{
		msg_log("card is fresh, no CRC", FT_MSG_SEC);
		if (verbose)
			printf("Card is new. CRC not yet set.\n");
		return (0);
	}
	else if (memcmp(crc_string, user_data->hash1, 16)) // checks the crc;
	{
		//possible tampering detected!
		msg_log("INVALID CRC, PANIC", FT_MSG_SEC);
		msg_log((char *) user_data->login, FT_MSG_SEC);
		if (verbose)
			fprintf(stderr, "CRC DIDN'T MATCH! PANIC!.\n");
		nfc_led(context, LED_PANIC);
		return (1);
	}
	if (verbose)
			printf("CRC validation ok.\n");
	msg_log("CRC validation ok", FT_MSG_SEC);
	return (0);
}

