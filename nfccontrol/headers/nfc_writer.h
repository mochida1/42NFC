/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nfc_writer.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/01/01 18:36:13 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/03 20:24:13 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NFC_WRITE_H
# define NFC_WRITE_H

# ifndef MIFARE_STRING_SIZE
#  define MIFARE_STRING_SIZE 17
# endif //MIFARE_STRING_SIZE

typedef struct s_writer
{
	int				block;
	char			type[20];
	char			string[17];
	unsigned int	senha[6];
} t_writer;

typedef struct s_user_data
{
	char	name[MIFARE_STRING_SIZE];
	char	name2[MIFARE_STRING_SIZE];
	char	login[MIFARE_STRING_SIZE];
	char	cohort[MIFARE_STRING_SIZE];
	char	group[MIFARE_STRING_SIZE];
	char	campus[MIFARE_STRING_SIZE];
}t_user_data;

#endif //NFC_WRITE_H