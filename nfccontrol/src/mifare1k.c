/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   mifare1k.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/27 21:24:30 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 22:03:07 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <PCSC/winscard.h>
#include <unistd.h>
#include "nfc_defs.h"
#include "ft_nfc.h"
#include "ft_nfc_transactions.h"
#include "string.h"
#include "mifare1k.h"
#include "ft_messages.h"
#include "nfc_security.h"
#include "utils.h"

extern int	verbose;

int	nfc_read_user_data(t_nfc *context, t_udata *user_data);

void welcome_message(t_udata *user_data)
{
	printf("Welcome %s %s!\n", user_data->name, user_data->name2);
}

int	nfc_read_user_data(t_nfc *context, t_udata *user_data)
{
	int	err_flag;

	err_flag = 0;
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->name_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->name_block))
	{
		if (nfc_read_block(context, user_data->name, user_data->name_block))
			err_flag = 1;
	}
	else
	{
		err_flag = 1;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->name2_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->name2_block))
	{
		if (nfc_read_block(context, user_data->name2, user_data->name2_block))
			err_flag = 2;
	}
	else
	{
		err_flag = 2;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->login_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->login_block))
	{
		if (nfc_read_block(context, user_data->login, user_data->login_block))
			err_flag = 3;
	}
	else
	{
			err_flag = 3;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->date_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->date_block))
	{
		if (nfc_read_block(context, user_data->date, user_data->date_block))
			err_flag = 4;
	}
	else
	{
			err_flag = 4;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->group_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->group_block))
	{
		if (nfc_read_block(context, user_data->group, user_data->group_block))
			err_flag = 5;
	}
	else
	{
			err_flag = 5;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->campus_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->campus_block))
	{
		if (nfc_read_block(context, user_data->campus, user_data->campus_block))
			err_flag = 6;
	}
	else
	{
			err_flag = 6;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->cohort_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->cohort_block))
	{
		if (nfc_read_block(context, user_data->cohort, user_data->cohort_block))
			err_flag = 7;
	}
	else
	{
			err_flag = 7;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->weekly_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->weekly_block))
	{
		if (nfc_read_block(context, user_data->weekly, user_data->weekly_block))
			err_flag = 8;
	}
	else
	{
			err_flag = 8;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->hash1_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->hash1_block))
	{
		if (nfc_read_block(context, user_data->hash1, user_data->hash1_block))
			err_flag = 9;
	}
	else
	{
			err_flag = 9;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->hash2_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->hash2_block))
	{
		if (nfc_read_block(context, user_data->hash2, user_data->hash2_block))
			err_flag = 10;
	}
	else
	{
			err_flag = 10;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->hash3_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->hash3_block))
	{
		if (nfc_read_block(context, user_data->hash3, user_data->hash3_block))
			err_flag = 11;
	}
	else
	{
			err_flag = 11;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->uuid1_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->uuid1_block))
	{
		if (nfc_read_block(context, user_data->uuid1, user_data->uuid1_block))
			err_flag = 12;
	}
	else
	{
			err_flag = 12;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->uuid2_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->uuid2_block))
	{
		if (nfc_read_block(context, user_data->uuid2, user_data->uuid2_block))
			err_flag = 13;
	}
	else
	{
			err_flag = 13;
	}
	usleep(100);
	nfc_load_auth_key(context, AUTH_A, user_data->uuid3_psw, NULL);
	if (!nfc_auth_key(context, AUTH_A, user_data->uuid3_block))
	{
		if (nfc_read_block(context, user_data->uuid3, user_data->uuid3_block))
			err_flag = 14;
	}
	else
	{
		err_flag = 14;
	}
	if (err_flag && verbose)
	{
		fprintf(stderr, "ERROR: Couldn't read from card! Error code = %2d\n", err_flag);
	}
	return (err_flag);
}

int	nfc_update_presence(t_nfc *context, t_udata *user_data)
{
	unsigned char	current_time[17];

	if (!memcmp(user_data->date, "DATE", 4))
	{
		memset(current_time, 0 , 17);
		current_time[0] = '1';
		current_time[1] = ' ';
		get_current_time((char *) &current_time[2]);
		printf("current_time: |%s|\n", (char *)current_time);
		// nfc_write_block(context, current_time, user_data->date_block);
		return(USER_ENTER);
		(void) context;
	}
	return (USER_EXIT);
}

int	routine_mifare(t_nfc *context)
{
	t_udata			user_data;
	int				rc;
	int				presence;
	
	presence = USER_UNK;
	printf("Card is MIFARE1K\n");
	/* begin transaction */
	nfc_start_transaction(context);

	/* Gets relevant blocks information*/
	rc = msg_get_udata(&user_data);
	if (rc)
	{
		nfc_led(context, LED_INVALID_CARD);
		usleep(100);
		nfc_end_transaction(context);
		return (1);
	}
	rc = nfc_read_user_data(context, &user_data);
	if (rc)
	{
		nfc_led(context, LED_INVALID_CARD);
		usleep(100);
		nfc_end_transaction(context);
		return (1);
	}
	rc = sec_validate_crc(context, &user_data);
	rc = msg_validate_uuid(&user_data);
	if (rc)
		return (1);
	presence = nfc_update_presence(context, &user_data);
	printf("Presence: %d\n", presence);
	/* show welcome message */
	welcome_message(&user_data);

	/* end transaction */
	printf ("END TRANSACTION\n");
	nfc_led(context, LED_END_OK);
	nfc_end_transaction(context);
	return (0);
}