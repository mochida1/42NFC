/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_messages.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/04 15:33:49 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 19:39:54 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <time.h>
#include <string.h>
#include <stdio.h>
#include "mifare1k.h"
#include "nfc_defs.h"

#ifndef STANDALONE
#define STANDALONE
#endif //standalone

extern int	verbose;

void	msg_connect_to_broker(void)
{
	#ifdef ZEROMQ
	#endif //ZEROMQ
	
	#ifdef PLAIN_SOCKET
	#endif //PLAIN_SOCKET

	#ifdef STANDALONE
	#endif //STANDALONE
	return ;
}

/* 
	appends current date 
*/
int	msg_log(char *message)
{
	#ifdef ZEROMQ
	#endif //ZEROMQ

	#ifdef PLAIN_SOCKET
	#endif //PLAIN_SOCKET

	#ifdef STANDALONE
	#endif //STANDALONE
	(void) message;
	return (0);
}

int	msg_get_udata(t_udata *user_data)
{
	unsigned long int rc;

	rc = 0;
	memset(user_data, 0, sizeof(t_udata));
	#ifdef ZEROMQ
	#endif //ZEROMQ

	#ifdef PLAIN_SOCKET
	#endif //PLAIN_SOCKET

	#ifdef STANDALONE
		char default_pwd[6] =	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
		char pwd_7[6] =			{ 0x42, 0x42, 0x42, 0x42, 0x42, 0x42 };
		char pwd_11[6] =		{ 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A };
		char pwd_59[6] =		{ 0x74, 0xE5, 0xB4, 0x4C, 0xAC, 0xDC };
		char pwd_63[6] =		{ 0xC0, 0xDA, 0xDE, 0xAD, 0xBE, 0xEF };
		user_data->name_block = 1;
		user_data->name2_block = 2;
		user_data->login_block = 4;
		user_data->date_block = 5;
		user_data->group_block = 6;
		user_data->campus_block = 8;
		user_data->cohort_block = 9;
		user_data->weekly_block = 10;
		user_data->hash1_block = 56;
		user_data->hash2_block = 57;
		user_data->hash3_block = 58;
		user_data->uuid1_block = 60;
		user_data->uuid2_block = 61;
		user_data->uuid3_block = 62;
		memcpy(user_data->name_psw, default_pwd, 6);
		memcpy(user_data->name2_psw, default_pwd, 6);
		memcpy(user_data->login_psw, pwd_7, 6);
		memcpy(user_data->date_psw, pwd_7, 6);
		memcpy(user_data->group_psw, pwd_7, 6);
		memcpy(user_data->campus_psw, pwd_11, 6);
		memcpy(user_data->cohort_psw, pwd_11, 6);
		memcpy(user_data->weekly_psw, pwd_11, 6);
		memcpy(user_data->hash1_psw, pwd_59, 6);
		memcpy(user_data->hash2_psw, pwd_59, 6);
		memcpy(user_data->hash3_psw, pwd_59, 6);
		memcpy(user_data->uuid1_psw, pwd_63, 6);
		memcpy(user_data->uuid2_psw, pwd_63, 6);
		memcpy(user_data->uuid3_psw, pwd_63, 6);
	#endif //STANDALONE
	if (rc)
	{
		if (verbose)
			fprintf(stderr, "ERROR: Couldn't retrieve user data from server.\n");
		return (1);
	}
	return (0);

}

int	msg_validate_uuid(t_udata *user_data)
{
	(void) user_data;
	return (0);
}