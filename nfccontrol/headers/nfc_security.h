/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nfc_security.h                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/05 16:35:26 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 16:36:11 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NFC_SECURITY_H
# define NFC_SECURITY_H

int		sec_validate_crc(t_nfc *context, t_udata *user_data);

#endif //NFC_SECURITY_H