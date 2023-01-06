/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nfc.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/27 14:24:32 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 21:08:42 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef		FT_NFC_H
# define	FT_NFC_H

#include "nfc_defs.h"

extern int	verbose;

t_nfc	*ft_nfc_init(void);
int		nfc_connect(t_nfc *context);
int		nfc_reconnect(t_nfc *context);
int		nfc_disconnect(t_nfc *context);
int		nfc_get_card_atr(t_nfc *context, unsigned char pbAtr[]);
int		nfc_validate_card_type(t_nfc *context);
int		nfc_cleanup_before_exit(t_nfc *context);
int		nfc_led(t_nfc *context, int led_status);

#endif //FT_NFC_H