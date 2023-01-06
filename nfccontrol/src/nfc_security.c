/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nfc_security.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/31 05:50:16 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 18:09:02 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <inttypes.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include "nfc_defs.h"
#include "mifare1k.h"
#include "ft_nfc_transactions.h"

void	check_for_ssh(void)
{
	//se houver conexão por SSH, desliga o pc.
}

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

int				sec_nfc_update_crc(void) /*(t_nfc *context, t_udata *user_data)*/
{
	return (0);
}

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

	if (verbose)
		printf("Validating CRC\n");
	memset(empty_string, 0, 17);
	memset(const_data, 0 , 65);
	strncat((char *)const_data, (const char *)user_data->login, 16);
	strncat((char *)const_data, (const char *)user_data->group, 16);
	strncat((char *)const_data, (const char *)user_data->campus, 16);
	strncat((char *)const_data, (const char *)user_data->cohort, 16);
	crc[0] = sec_crc8(user_data->login_block, const_data, 64);			// faz o crc de login+group+campus+cohort
	crc[1] = sec_crc8(user_data->date_block, user_data->date, 16);		// crc date
	crc[2] = sec_crc8(user_data->weekly_block, user_data->weekly, 16);	// crc weekly
	memset(const_data,0 , 65);
	strncat((char *)const_data, (const char *)user_data->uuid1, 16);
	strncat((char *)const_data, (const char *)user_data->uuid2, 16);
	strncat((char *)const_data, (const char *)user_data->uuid3, 16);
	crc[3] = sec_crc8(user_data->uuid1_block, const_data, 16);			//crc uuid1+uuid2+uuid3;

	//checa os CRC's
	sec_get_crc_string(crc_string, crc, 4);
	if (verbose)
	{
		printf ("CRC: ");
		debug_print_hex_bytebuffer(crc_string, 64);
	}
	if (!memcmp(empty_string, user_data->hash1, 16) && !memcmp("DATE", user_data->date, 4)) // if it's the 1st time the card was presented
	{
		if (verbose)
			printf("Card is new. CRC not yet set.\n");
		return (0);
	}
	else if (memcmp(crc_string, user_data->hash1, 16)) // checks the crc;
	{
		//possible tampering detected!
		if (verbose)
			fprintf(stderr, "CRC DIDN'T MATCH! PANIC!.\n");
		nfc_led(context, LED_PANIC);
		return (1);
	}
	if (verbose)
			printf("CRC validation ok.\n");
	return (0);
}

