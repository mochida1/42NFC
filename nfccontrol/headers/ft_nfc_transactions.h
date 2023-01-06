/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nfc_transactions.h                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/25 15:10:08 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/04 20:25:33 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NFC_TRANSACTIONS_H
# define FT_NFC_TRANSACTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include "nfc_debug.h"
#include "ft_nfc.h"

#define AUTH_A  1
#define AUTH_B  2
#define AUTH_X  3

extern int	verbose;

int	nfc_start_transaction(t_nfc *context);
int	nfc_end_transaction(t_nfc *context);
int	nfc_load_auth_key(t_nfc *context, char key_type, unsigned char *password_a, unsigned char *password_b);
int	nfc_auth_key(t_nfc *context, char key_type, char block);
int	nfc_read_block(t_nfc *context, unsigned char *dest, char block);
int nfc_write_block(t_nfc *context, unsigned char data[], char block);
int nfc_write_auth_block(t_nfc *context, unsigned char pass_a[6], unsigned char pass_b[6], char block);


// unsigned char pbSendBuffer[] = { 0xFF, 0xb0, 0x00, 0x04, 0x10 };
// unsigned char load_key_a[] = { 0xFF, 0x82, 0x00, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }; // loads key A into reader volatile memory
// unsigned char auth_key_a_bl04[] = { 0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x60, 0x00 }; // autentica o bloco 0x04 do cartão
// unsigned char Mifare1KATR[] = { 0x3B, 0x8f, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x6A }; //mifare 1k hardcoded
// unsigned char hardCodedStr[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x90, 0x00 }; // string de validação do bloco 0x04 do cartão
// unsigned char cartao_invalido[] = { 0xFF, 0x00, 0x40, 0x5E, 0x04, 0x02, 0x01, 0x02, 0x02 }; // pisca vermelho e bipa 2x em caso de cartão de tipo errado
// unsigned char cartao_aceito[] = {0xFF, 0x00, 0x40, 0xFE, 0x04, 0x05, 0x01, 0x01, 0x02}; // brilha amarelo por 1/2 segundo e emite um bipe após



#endif //FT_NFC_TRANSACTIONS_H