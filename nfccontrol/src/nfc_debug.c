/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nfc_debug.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/27 19:19:23 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/04 19:11:31 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <stdio.h>

/*
Prints every byte in the buffer as a hexadecimal value;
****arguments****
[BYTE *buffer] -> pointer to buffer to be printed;
[size_t] buffer_len -> number of elements inside buffer;
*/
void debug_print_hex_bytebuffer(BYTE *buffer, size_t buffer_len)
{
		size_t  i;

		i = 0;
		printf ("%p:", buffer);
		printf ("{ ");
		while (i < buffer_len)
		{
				if (i == buffer_len - 1)
						printf("0x%02X }\n", buffer[i]);
				else
						printf("0x%02X, ", buffer[i]);
				i++;
		}
}

/*
Prints the ascii characters stored in the buffer;
****arguments****
[BYTE *buffer] -> pointer to buffer to be printed;
[size_t] buffer_len -> number of elements inside buffer;
*/
void debug_print_bytebuffer(BYTE *buffer, size_t buffer_len)
{
		size_t  i;

		i = 0;
		printf ("Buffer of size %ld at %p: ", buffer_len, buffer);
		while (i <= buffer_len)
		{
				printf("%c", buffer[i]);
				i++;
		}
		printf("\n");
}

/*
Prints the corresponding error, if any.
****arguments****
[const char *function_name] -> name of the function previously called;
[LONG ret] -> return value of given function;
*/
void debug_print_error(const char *function_name, LONG ret)
{
		if (ret)
			printf("%s: %s (0x%lX)\n", function_name, pcsc_stringify_error(ret), ret);
}