/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_messages.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/04 15:33:49 by hmochida          #+#    #+#             */
/*   Updated: 2023/02/26 22:23:21 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zmq.h>
#include <ctype.h>
#include "mifare1k.h"
#include "nfc_defs.h"
#include "ft_messages.h"
#include "dirent.h"
#include "utils.h"

#ifndef STANDALONE
#define STANDALONE
#endif //standalone
#define ZEROMQ

extern int	verbose;

void	msg_connect_to_broker(void)
{
	#ifdef ZEROMQ
	#endif //ZEROMQ
	
	#ifdef PLAIN_SOCKET
	#endif //PLAIN_SOCKET

	#ifdef STANDALONE
		struct stat st = {0};

		if (stat("/ft_beep", &st) == -1) 
		{
			mkdir("/ft_beep", 0700);
		}
	#endif //STANDALONE
	return ;
}

void	get_endpoint_from_config_file(char *endpoint_name, char *dest_buffer)
{
	FILE	*fd;
	int		name_len;
	char	rd_buff[256];
	int		i;

	i = 0;
	name_len = (int) strlen(endpoint_name);
	fd = fopen("/etc/ft_beep/endpoints.cfg","r");
	while(fgets(rd_buff, 256, fd))
	{
		if (strncmp(endpoint_name, rd_buff, name_len))
			continue;
		else
		while(rd_buff[name_len + i])
		{
			if(isprint(rd_buff[name_len + i]))
				dest_buffer[i] = rd_buff[name_len + i];
			i++;
		}
	}
	printf ("Server: %s\n", dest_buffer);
	fclose(fd);
}

// FT_MSG_ERR 	 	-1
// FT_MSG_GENERAL	0
// FT_MSG_SEC 		1
// FT_MSG_USERACT	2 

int	msg_log(char *message, int type)
{
	char					buffer[256];
	char					rcv_buffer[256];
	char					date[17];
	static unsigned int		message_number;
	static unsigned int		is_connect;
	
	memset(buffer, 0, 256);
	get_current_time(date);
	snprintf(buffer, 256, "%06u %s %s\n", message_number, date, message);

	#ifdef ZEROMQ
	static void	*zmq_ctx;
	static void	*req_sock;

	if (!zmq_ctx) //gambiarra para não ter que declarar os endpoints como globais
		zmq_ctx = zmq_ctx_new();
	if (!req_sock)
		req_sock = zmq_socket(zmq_ctx, ZMQ_REQ);
	if (!is_connect)
	{
		// get_endpoint_from_config_file("piscine_server", rcv_buffer); //ZMQ não está conectando a nao ser com uma literal.
		if (!zmq_connect (req_sock, ZMQ_SERVER_ENDP))
			is_connect = 1;
		// memset(rcv_buffer, 0 , 256);
	}
	if (type == FT_MSG_GENERAL)
		if (!strcmp(message, "Exit successful"))
		{
			zmq_close(req_sock);
			zmq_ctx_destroy(zmq_ctx);
		}
	if (type == FT_ZMQ_LOG)
	{
		zmq_send(req_sock, message, 256, 0);
		zmq_recv(req_sock, rcv_buffer, 256, 0);
	}
	//FAZER TRATATIVAS DE RETORNO DO SERVER AQUI
	#endif //ZEROMQ

	#ifdef PLAIN_SOCKET
	#endif //PLAIN_SOCKET

	#ifdef STANDALONE
		int	fd;
		if (type == FT_MSG_ERR)
			fd = open("/ft_beep/error.log", O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
		else if (type == FT_MSG_GENERAL)
			fd = open("/ft_beep/log.log", O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
		else if (type == FT_MSG_SEC)
			fd = open("/ft_beep/sec.log", O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
		else if (type == FT_MSG_USERACT)
			fd = open("/ft_beep/usr.log", O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
		else
			fd = open("/ft_beep/mystery.log", O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
		write(fd, buffer, strlen(buffer));
		close (fd);
	#endif //STANDALONE
	message_number++;
	if (message_number > 999999)
		message_number = 0;
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
	// msg_log("validating uuid. jk, not implemented", FT_MSG_SEC);
	(void) user_data;
	return (0);
}
