/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/05 18:27:47 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 19:26:39 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>

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