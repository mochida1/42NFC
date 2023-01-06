/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nfc_debug.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/27 19:19:53 by hmochida          #+#    #+#             */
/*   Updated: 2022/12/27 19:20:46 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef		NFC_DEBUG_H
# define	NFC_DEBUG_H

void debug_print_hex_bytebuffer(BYTE *buffer, size_t buffer_len);
void debug_print_error(const char *function_name, LONG ret);
void debug_print_bytebuffer(BYTE *buffer, size_t buffer_len);

#endif