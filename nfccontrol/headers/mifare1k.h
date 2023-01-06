/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   mifare1k.h                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/27 21:24:34 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 21:09:10 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef MIFARE1K_H
# define MIFARE1K_H

# include "nfc_defs.h"

# ifndef MIFARE_STRING_SIZE
#  define	MIFARE_STRING_SIZE	17
#  define	MIFARE_PSW_SIZE		7
# endif //MIFARE_STRING_SIZE

# ifndef USER_ENTER
#  define	USER_UNK			00
#  define	USER_ENTER			1
#  define	USER_EXIT			2
# endif //USER_ENTER


typedef struct s_user_data
{
	unsigned char	name[MIFARE_STRING_SIZE];
	unsigned char	name2[MIFARE_STRING_SIZE];
	unsigned char	login[MIFARE_STRING_SIZE];
	unsigned char	date[MIFARE_STRING_SIZE];
	unsigned char	group[MIFARE_STRING_SIZE];
	unsigned char	campus[MIFARE_STRING_SIZE];
	unsigned char	cohort[MIFARE_STRING_SIZE];
	unsigned char	weekly[MIFARE_STRING_SIZE];
	unsigned char	hash1[MIFARE_STRING_SIZE];
	unsigned char	hash2[MIFARE_STRING_SIZE];
	unsigned char	hash3[MIFARE_STRING_SIZE];
	unsigned char	uuid1[MIFARE_STRING_SIZE];
	unsigned char	uuid2[MIFARE_STRING_SIZE];
	unsigned char	uuid3[MIFARE_STRING_SIZE];
	int		name_block;
	int		name2_block;
	int		login_block;
	int		date_block;
	int		group_block;
	int		campus_block;
	int		cohort_block;
	int		weekly_block;
	int		hash1_block;
	int		hash2_block;
	int		hash3_block;
	int		uuid1_block;
	int		uuid2_block;
	int		uuid3_block;
	unsigned char	name_psw[MIFARE_PSW_SIZE];
	unsigned char	name2_psw[MIFARE_PSW_SIZE];
	unsigned char	login_psw[MIFARE_PSW_SIZE];
	unsigned char	date_psw[MIFARE_PSW_SIZE];
	unsigned char	group_psw[MIFARE_PSW_SIZE];
	unsigned char	campus_psw[MIFARE_PSW_SIZE];
	unsigned char	cohort_psw[MIFARE_PSW_SIZE];
	unsigned char	weekly_psw[MIFARE_PSW_SIZE];
	unsigned char	hash1_psw[MIFARE_PSW_SIZE];
	unsigned char	hash2_psw[MIFARE_PSW_SIZE];
	unsigned char	hash3_psw[MIFARE_PSW_SIZE];
	unsigned char	uuid1_psw[MIFARE_PSW_SIZE];
	unsigned char	uuid2_psw[MIFARE_PSW_SIZE];
	unsigned char	uuid3_psw[MIFARE_PSW_SIZE];
}t_udata;

int		routine_mifare(t_nfc *context);
int		nfc_do_panic(t_nfc *context);

#endif //MIFARE1K_H
