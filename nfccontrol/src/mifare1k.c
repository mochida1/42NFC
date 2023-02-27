/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   mifare1k.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/27 21:24:30 by hmochida          #+#    #+#             */
/*   Updated: 2023/02/26 20:31:30 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <PCSC/winscard.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "nfc_defs.h"
#include "ft_nfc.h"
#include "ft_nfc_transactions.h"
#include "mifare1k.h"
#include "ft_messages.h"
#include "nfc_security.h"
#include "utils.h"

extern int	verbose;

/* PROTOTYPES*/
int	nfc_read_user_data(t_nfc *context, t_udata *user_data);
int nfc_update_weekly(t_nfc *context, t_udata *user_data, char current_time[]);


/* Displays a welcome message :) */
void welcome_message(t_udata *user_data)
{
	printf("\n\nWelcome %s (%s)!\n\n", user_data->name, user_data->name2);
}

void farewell_message(t_udata *user_data)
{
	printf("Bye, %s!\n", (char *)user_data->login);
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
		{
			err_flag = 3;
		}
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

/* deals with date block*/
int	nfc_update_presence(t_nfc *context, t_udata *user_data)
{
	unsigned char	current_time[17];
	char			zmq_msg[256];

	msg_log((char *) user_data->login, FT_MSG_GENERAL);
	msg_log((char *) user_data->login, FT_MSG_USERACT);
	if (!memcmp(user_data->date, "DATE", 4)) // if a new card is presented;
	{
		memset(current_time, 0 , 17);
		memcpy(current_time, "1 ", 2);
		get_seconds_time((char *) &current_time[2]);
		if (verbose)
			printf("current_time: %s\n", (char *)current_time);
		nfc_load_auth_key(context, AUTH_A, user_data->date_psw, NULL);
		nfc_auth_key(context, AUTH_A, user_data->date_block);
		if (!nfc_write_block(context, current_time, user_data->date_block))
		{
			msg_log("login\n", FT_MSG_USERACT);
			return(USER_ENTER);
		}
		msg_log("Unknown error at nfc_update_presence: nfc_read_block not performed", FT_MSG_ERR);
		fprintf(stderr, "ERROR: Something really weird happenned when updating date. Please call a staff member.\n");
		nfc_led(context, LED_PANIC);
		return (USER_UNK);
	}
	else if (user_data->date[0] == '1') // if user is leaving
	{
		memset(current_time, 0, 17);
		memcpy(current_time, "0 ", 2);
		get_seconds_time((char *) &current_time[2]);
		if (verbose)
		{
			printf("Updating date block to exit.\n");
			printf("current_time: %s\n", (char *)current_time);
		}
		nfc_load_auth_key(context, AUTH_A, user_data->date_psw, NULL);
		nfc_auth_key(context, AUTH_A, user_data->date_block);
		if (nfc_write_block(context, current_time, user_data->date_block))
		{
			msg_log("unable to write exit time", FT_MSG_ERR);
			fprintf(stderr, "ERROR: Couldn't write updated exit time.\n");
			nfc_led(context, LED_PANIC);
			return (USER_UNK);
		}
		nfc_update_weekly(context, user_data, (char *)current_time);
		msg_log("logout\n", FT_MSG_USERACT);
		sprintf(zmq_msg, "%s\t1\t%s", user_data->login, &current_time[2]);
		msg_log (zmq_msg, FT_ZMQ_LOG);
		return (USER_EXIT);
	}
	else if (user_data->date[0] == '0') // if user is entering
	{
		memset(current_time, 0, 17);
		memcpy(current_time, "1 ", 2);
		get_seconds_time((char *) &current_time[2]);
		if (verbose)
		{
			printf("Updating date block to entrance.\n");
			printf("current_time: %s\n", (char *)current_time);
		}
		nfc_load_auth_key(context, AUTH_A, user_data->date_psw, NULL);
		nfc_auth_key(context, AUTH_A, user_data->date_block);
		if (nfc_write_block(context, current_time, user_data->date_block))
			fprintf(stderr, "ERROR: Couldn't write updated entrance time.\n");
		msg_log("login\n", FT_MSG_USERACT);
		sprintf(zmq_msg, "%s\t0\t%s", user_data->login, &current_time[2]);
		msg_log (zmq_msg, FT_ZMQ_LOG);
		return (USER_ENTER);
	}
	nfc_led(context, LED_PANIC); // If DATE[0] block is not equal DATE or '1' or '0', it means something is afoul;
	return (USER_UNK);
}

int nfc_update_weekly(t_nfc *context, t_udata *user_data, char current_time[])
{
	unsigned int	week;
	unsigned char	buffer[17];
	char			logfile[200];
	unsigned long	current_weekly;
	unsigned long	new_weekly;
	int				fd;
	int				sec;
	int				total_min;
	int				min;
	int				hours;

	week = get_week();
	current_weekly = atol((char *)&user_data->weekly[3]);
	new_weekly = current_weekly + atol(&current_time[2]) - atol((char *)&user_data->date[2]);

	if (atoi((char *)user_data->weekly) != (int) week)
	{
		sec = new_weekly % 60;
		total_min = (new_weekly - sec) / 60;
		min = total_min % 60;
		hours = (total_min - min) / 60;

		// writes to log the updated last week presence time;
		memset(logfile, 0, 200);
		snprintf(logfile, 200, "/ft_beep/%s.tim", (char *)user_data->login);
		if (verbose)
			printf("Openinig file %s\n", logfile);
		fd = open(logfile, O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
		if (fd < 0)
			fprintf(stderr, "ERROR: Couldn't open/create user file!\n");
		memset(logfile, 0, 200);
		snprintf(logfile, 200, "%s\t%02d %lu %03d:%02d:%02d\n", (char *)user_data->login, atoi((char *)user_data->weekly), new_weekly, hours, min, sec);
		write(fd, logfile, strlen(logfile));

		// reseta bloco weekly (XX 0\0\0\0\0...)
		memset(buffer, 0, 17);
		snprintf((char *) buffer, 17,  "%02d 0", week);
		nfc_load_auth_key(context, AUTH_A, user_data->weekly_psw, NULL);
		nfc_auth_key(context, AUTH_A, user_data->weekly_block);
		nfc_write_block(context, buffer, user_data->weekly_block);
		return (0);
	}
	memset(buffer, 0, 17);
	snprintf((char *) buffer, 17,  "%02d %lu", week, new_weekly);
	nfc_load_auth_key(context, AUTH_A, user_data->weekly_psw, NULL);
	nfc_auth_key(context, AUTH_A, user_data->weekly_block);
	nfc_write_block(context, buffer, user_data->weekly_block);
	return (0);
}

/* 
	Routines in case a mifare1k card is presented and recognized
	Does every transaction here.
*/
int	routine_mifare(t_nfc *context)
{
	t_udata			user_data;
	int				rc;
	int				presence;
	
	presence = USER_UNK;
	printf("Please wait.\n");
	msg_log("card type is MIFARE1k", FT_MSG_GENERAL);
	/* begin transaction */
	nfc_start_transaction(context);

	/* Gets relevant blocks information*/
	rc = msg_get_udata(&user_data);
	msg_log("getting user data", FT_MSG_GENERAL);
	if (rc)
	{
		msg_log("unable to get user data from server", FT_MSG_ERR);
		nfc_led(context, LED_INVALID_CARD);
		usleep(100);
		nfc_end_transaction(context);
		return (1);
	}
	rc = nfc_read_user_data(context, &user_data);
	if (rc)
	{
		msg_log("unable to read user data from card", FT_MSG_ERR);
		nfc_led(context, LED_INVALID_CARD);
		usleep(100);
		nfc_end_transaction(context);
		return (1);
	}
	msg_log((char *) user_data.login, FT_MSG_USERACT);
	msg_log("accessing...", FT_MSG_USERACT);
	msg_log("user data acquisition successful", FT_MSG_GENERAL);
	msg_log((char *) user_data.login, FT_MSG_GENERAL);
	msg_log("starting security validations", FT_MSG_GENERAL);
	rc = sec_validate_crc(context, &user_data);
	rc = msg_validate_uuid(&user_data);
	msg_log("security validations ok", FT_MSG_GENERAL);
	if (rc)
		return (1);
	nfc_reconnect(context);
	msg_log("---starting WRITING operations---", FT_MSG_GENERAL);
	msg_log("updating date", FT_MSG_GENERAL);
	presence = nfc_update_presence(context, &user_data);
	msg_log("updating date ok", FT_MSG_GENERAL);
	msg_log("updating crc", FT_MSG_GENERAL);
	rc = nfc_read_user_data(context, &user_data);
	if (!sec_nfc_update_crc(context, &user_data))
		msg_log("updating crc ok", FT_MSG_GENERAL);
	msg_log("---finished WRITING operations---", FT_MSG_GENERAL);
	if (presence == USER_ENTER)
		welcome_message(&user_data);
	else if (presence == USER_EXIT)
		farewell_message(&user_data);
	
	if (!strcmp((char *)user_data.group, "Bocal"))
	{
		msg_log("BOCAL ACCESS", FT_MSG_SEC);
		msg_log((char *) user_data.login, FT_MSG_SEC);
		nfc_end_transaction(context);
		nfc_disconnect(context);
		nfc_cleanup_before_exit(context);
		exit (42);
	}
	/* end transaction */
	printf ("END TRANSACTION\n");
	nfc_led(context, LED_END_OK);
	if (presence == USER_EXIT)
		nfc_led(context, LED_END_OK);
	nfc_end_transaction(context);
	return (0);
}
