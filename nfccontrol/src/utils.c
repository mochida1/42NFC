/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/05 18:27:47 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/06 07:17:57 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <time.h>
#include <stdlib.h>

extern int	verbose;
/*
	Writes the equivalent of a shell 'date "+%m%d%y %H%M%S"' (14 bytes) to buffer;
	returns 0 if success, 1 otherwise;
*/
int get_current_time(char *buffer)
{
	FILE	*fd;

	fd = popen("date \"+%m%d%y %H%M%S\"", "r");
	if (fd == NULL)
	{
		if (verbose)
			fprintf(stderr, "ERROR: Couldn't get date from system!\n");
	}
	fgets(buffer, 14, fd);
	if (verbose)
		printf("Date: %s\n", buffer);
	pclose(fd);
	return(0);
}

int	get_seconds_time(char *buffer)
{
	time_t t;

	t = time(NULL);
	snprintf(buffer, 15, "%lu", t +725760);
	return (0);
}

unsigned int get_week(void)
{
	char buffer[15];
	FILE *fd;

	system("date \"+%W\" > /etc/ft_beep/weeks.cfg");
	fd = fopen("/etc/ft_beep/weeks.cfg", "r");
	fgets(buffer, 15, fd);
	fclose(fd);
	return (2);
	return (atoi(buffer));
}