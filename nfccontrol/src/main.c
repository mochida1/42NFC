/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/10 15:11:16 by hmochida          #+#    #+#             */
/*   Updated: 2023/02/26 19:55:57 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <pthread.h>

#include <PCSC/winscard.h>
#include "ft_nfc.h"
#include "nfc_debug.h"
#include "ft_nfc_transactions.h"
#include "mifare1k.h"
#include "ft_messages.h"
#include "nfc_security.h"
#include "utils.h"

#ifndef TRUE
# define TRUE 1
# define FALSE 0
#endif //TRUE

int			verbose;
void		*zmq_ctx;


int	routine_ntag21x(t_nfc *context)
{
	msg_log("card is of type ntag21X. Too bad.", FT_MSG_GENERAL);
	nfc_start_transaction(context);
	printf("Module not yet implemented. Sorry.\n");
	nfc_led(context, LED_INVALID_CARD);
	nfc_end_transaction(context);
	return (1);
}

int	nfc(void)
{
	#ifndef STANDALONE
	#define STANDALONE
	#endif //standalone
	t_nfc		*context;
	extern int	g_card_type;
	int			(*card_routine[3])();
	int			rc;

	/* Here we assign functions for different card types */
	card_routine[UNKOWN_CARD] = NULL;
	card_routine[MIFARE1K] = &routine_mifare;
	card_routine[NTAG21X] = &routine_ntag21x;
	context = ft_nfc_init();
	msg_log("NFC service initialized", FT_MSG_GENERAL);
	g_card_type = 0;
	rc = 0;
	
	/* connect to a card */
	while (1)
	{
		printf("Waiting for card\n");
		msg_log("reader waiting for card", FT_MSG_GENERAL);
		while (nfc_connect(context))
		{
			
			//	aqui deve checar a conexão com o broker também
			//	se não estiver, led fica vermelho
			
			sleep (1);
		}
		/* get card atr */
		if (verbose)
			printf("Starting operations\n");
		g_card_type = nfc_validate_card_type(context);
		if (g_card_type == UNKOWN_CARD)
		{
			rc = 1;
			msg_log("Unknown card type detected", FT_MSG_ERR);
			nfc_led(context,LED_INVALID_CARD);
			if (verbose)
				fprintf(stderr, "NOT A VALID CARD!\n");
		}
		else if (g_card_type)
		{
			msg_log("Known card type detected", FT_MSG_GENERAL);
			rc = card_routine[g_card_type](context);
		}
		/* card disconnect */
		if (rc && verbose)
			fprintf(stderr, "------Error: operations could not be concluded\n");
		if (rc)
			msg_log("operations failure", FT_MSG_ERR);
		printf ("ENDING\n\n");
		nfc_disconnect(context);
		system("clear");
		msg_log("Card disconnected", FT_MSG_GENERAL);
	}
	nfc_cleanup_before_exit(context);
	msg_log("Exit issued", FT_MSG_GENERAL);
	return EXIT_SUCCESS;
}

void daemonize(void)
{
	/*
	** comeca a deamonizacao do servico
	*/
	pid_t		pid;
	pid_t		sid;
	pid = fork();
	if (pid < 0)
		exit (1);
	if (pid > 0)
		exit (0);
	umask(0);
	sid = setsid();
	if (sid < 0)
		exit (1);
	chdir("/");
	/* ignora os signals */

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGKILL, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGSTOP, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/*
	** fim da daemonizacao
	*/
}

void ft_exit(void)
{
	msg_log("Exit successful", FT_MSG_GENERAL);
	printf("NOW LEAVING\n");
}

int main (void)
{
	// pthread_t *tid;

	// tid = malloc (sizeof(pthread_t));
	// if (pthread_create(tid, NULL, (void *)check_for_ssh, NULL))
	#ifdef VERBOSE
	verbose = 1; 
	#endif //VERBOSE
	// daemonize();
	msg_connect_to_broker();
	msg_log("Program started", FT_MSG_GENERAL);
	atexit (ft_exit);
	nfc();
	return (0);
}