/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/10 15:11:16 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 21:15:06 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include <PCSC/winscard.h>
#include "ft_nfc.h"
#include "nfc_debug.h"
#include "ft_nfc_transactions.h"
#include "mifare1k.h"
#include "ft_messages.h"

#ifndef TRUE
# define TRUE 1
# define FALSE 0
#endif //TRUE

char		g_broker_connected;
char		g_broker_down;
char		g_bocal_access;
int			g_rc;
int			verbose;

int	routine_ntag21x(t_nfc *context)
{
	nfc_start_transaction(context);
	printf("Module not yet implemented. Sorry.\n");
	nfc_led(context, LED_PANIC);
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
	g_card_type = 0;
	rc = 0;
	
	/* connect to a card */
	while (!g_bocal_access)
	{
		//seta led para verde
		while (nfc_connect(context))
		{
			
			//	aqui deve checar a conexão com o broker também
			//	se não estiver, led fica vermelho
			
			sleep (1);
		}
		/* get card atr */
		if (verbose)
			printf("------Starting operations\n");
		g_card_type = nfc_validate_card_type(context);
		if (g_card_type == UNKOWN_CARD)
		{
			rc = 1;
			nfc_led(context,LED_INVALID_CARD);
			if (verbose)
				fprintf(stderr, "NOT A VALID CARD!\n");
		}
		else if (g_card_type)
		{
			//set led to yellow
			rc = card_routine[g_card_type](context);
		}
		/* card disconnect */
		if (rc && verbose)
			fprintf(stderr, "------Error: operations could not be concluded\n");
		printf ("ENDING\n\n");
		nfc_disconnect(context);
	}

	nfc_cleanup_before_exit(context);
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
	printf("NOW LEAVING\n");
}


/*
if ("who | wc -l" != 1) 
	beepa até cartão do bocal ser ativado;
*/
int main (void)
{
	#define VERBOSE VERBOSE
	#ifdef VERBOSE
	verbose = 1;
	#endif //VERBOSE
	// daemonize();
	msg_connect_to_broker();
	atexit (ft_exit);
	nfc();
	return (0);
}