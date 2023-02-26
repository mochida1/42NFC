/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_messages.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/04 15:34:11 by hmochida          #+#    #+#             */
/*   Updated: 2023/02/26 19:43:16 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_MESSAGES_H
# define FT_MESSAGES_H

#include "mifare1k.h"

/* Message types */
#define FT_MSG_ERR 		-1
#define FT_MSG_GENERAL	0
#define FT_MSG_SEC 		1
#define FT_MSG_USERACT	2
#define	FT_ZMQ_LOG		3

int 	msg_get_udata(t_udata *user_data);
int		msg_log(char *message, int type);
void	msg_connect_to_broker(void);
int		msg_validate_uuid(t_udata *user_data);

#endif //FT_MESSAGES_H