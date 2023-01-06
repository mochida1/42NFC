/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   me.c                                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hmochida <hmochida@student.42sp.org.br>    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2022/12/31 08:15:33 by hmochida          #+#    #+#             */
/*   Updated: 2023/01/05 19:05:17 by hmochida         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

/*
	This program validates if a mifare1k classic card is blank, 
	then writes all data from a file into it.
	It expects the user won't try to fuck up the inputs and therefore
	I didnt spent much time on user input validation.
*/

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "ft_nfc.h"
#include "ft_nfc_transactions.h"
#include "nfc_defs.h"
#include "nfc_writer.h"

int verbose;

void	check_arguments(int argc, char *argv[])
{
	FILE	*fd;

	printf("Checking arguments...\n");
	if(argc == 1)
	{
		fprintf(stderr ,"Error: program needs a template file.\n");
		printf("Usage: %s [path/to/file]\n", argv[0]);
		exit (1);
	}
	if(argc > 2)
	{
		fprintf(stderr, "ERROR: too many arguments!\n");
		exit (2);
	}
	fd = fopen(argv[1], "r");
	if (!fd)
	{
		perror("fopen");
		exit (3);
	}
	fclose(fd);
	printf("Arguments ok!\n");
}

void	validate_file(char *path_to_file)
{
	FILE		*fd;
	char		buffer[256];
	char		*ctrl;
	int			line;
	int			i;
	t_writer	data;
	int			flag_error;

	line = 1;
	flag_error = 0;
	ctrl = buffer;
	printf("Validing template file (%s).\n", path_to_file);
	fd = fopen(path_to_file, "r");
	fseek(fd, 0, SEEK_SET);
	memset (&data, 0, sizeof(data));
	while (ctrl)
	{
		memset(buffer, 0 , 256);
		ctrl = fgets(buffer, 256, fd);
		sscanf(buffer, "%d %s", &data.block, data.type);
		if (data.block < 0 || data.block > 63)
		{
			printf("\033[31;1mERROR: invalid block number(%d) at line %2d!\033[0m\n", data.block, line);
			flag_error = 1;
		}
		if (!strcmp(data.type, "var"))
			sscanf(buffer, "%d %s %s", &data.block, data.type, data.string);
		else if (!strcmp(data.type, "string"))
			sscanf(buffer, "%d %s %s", &data.block, data.type, data.string);
		else if (!strcmp(data.type, "senha"))
		{
			i = 0;
			sscanf(buffer, "%d %s %x %x %x %x %x %x", &data.block, data.type, &data.senha[0], &data.senha[1], &data.senha[2], &data.senha[3], &data.senha[4], &data.senha[5]);
			while (i < 6)
			{
				if (data.senha[i] > 0xFF)
				{
					printf("\033[31;1mERROR: Invalid password byte (0x%2X) at line %2d!\033[0m\n",data.senha[i], line);
				}
				i++;
			}
		}
		else if (!strcmp(data.type, "default"))
			memset(data.string, 0 , MIFARE_STRING_SIZE);
		else
		{
			printf("\033[31;1mERROR: invalid type(%s) at line %2d!\033[0m\n", data.type, line);
			flag_error = 1;
		}
		line++;
	}
	fclose(fd);
	if (flag_error)
		exit (1);
	printf("\033[32;1mFile %s seems to be valid.\033[0m\n", path_to_file);
}

int		check_if_card_is_empty(t_nfc *context)
{
	int		block;
	int		rc;
	unsigned char	rcv_buffer[MIFARE_STRING_SIZE];
	unsigned char	atr[MAX_ATR_SIZE];
	char	warning_buffer[20];
	int		warning_flag;

	warning_flag = 1;
	printf("Please insert valid blank card to continue.\n");
	while (nfc_connect(context))
	{
		if (verbose)
		printf("trying to connect to card;\n");
		sleep (1);
	}
	if (verbose)
		printf("getting card ATR;\n");
	rc = nfc_get_card_atr(context, atr);
	if (rc)
	{
		fprintf(stderr, "ERROR: Couldn't get card ATR");
		return (1);
	}
	if (verbose)
		debug_print_hex_bytebuffer(atr, MAX_ATR_SIZE);
	rc = nfc_validate_card_type(context);
	if (rc != MIFARE1K)
	{
		fprintf(stderr, "ERROR: Wrong card type!\n");
		rc = nfc_disconnect(context);
		return (1);
	}
	if (verbose)
		printf("Loading default authentication keys;\n");
	rc = nfc_load_auth_key(context, AUTH_A, NULL, NULL);
	if (rc)
	{
		fprintf(stderr, "ERROR: Couldn't load default auth keys.\n");
		rc = nfc_disconnect(context);
		return (1);
	}
	if (verbose)
		printf("Starting transactions...\n");
	rc = nfc_start_transaction(context);
	if (rc)
	{
		fprintf(stderr, "Couldn't begin transaction!");
		rc = nfc_disconnect(context);
		return (1);
	}

	// AUTH and READ all blocks
	block = 1;
	while (block < 64)
	{
		memset(rcv_buffer, 0, MIFARE_STRING_SIZE);
		rc = nfc_auth_key(context, AUTH_A, block);
		if (rc)
			{
				fprintf(stderr, "ERROR: could not auth block %2d.\n", block);
				rc = nfc_end_transaction(context);
				rc = nfc_disconnect(context);
				return (1);
			}
		rc = nfc_read_block(context, rcv_buffer, block);
		if (rc)
			{
				fprintf(stderr, "ERROR: could not read from block %2d.\n", block);
				rc = nfc_end_transaction(context);
				rc = nfc_disconnect(context);
				return (1);
			}
		if (verbose && rc == 0)
			debug_print_hex_bytebuffer(rcv_buffer, MIFARE_STRING_SIZE);
		if (warning_flag && (block + 1) %4 != 0)
		{
			for (int i = 0; i < 17; i++)
				if (rcv_buffer[i])
				{
					fprintf(stderr, "\033[31mWARNING: There is already data in block %2d.\033[0m\n", block);
					memset(warning_buffer, 0, 20);
					printf("\033[31mContinue? yes/no/ignore all (y/n/i) \033[0m\n");
					fgets(warning_buffer, 20, stdin);
					if (warning_buffer[0] == 'y')
						break ;
					else if (warning_buffer[0] == 'n')
					{
						rc = nfc_end_transaction(context);
						rc = nfc_disconnect(context);
						return (1);
					}
					else if (warning_buffer[0] == 'i')
					{
						warning_flag = 0;
						break ;
					}
					else
					{
						rc = nfc_end_transaction(context);
						rc = nfc_disconnect(context);
						return (1);
					}
				}
		}
		block++;
	}
	printf("\n\033[92mValid card detected!\033[0m\n");
	printf("\033[91mDO NOT REMOVE CARD!\033[0m\n");
	rc = nfc_end_transaction(context);
	// rc = nfc_disconnect(context);
	printf("\n\n\033[33;1mNow proceeding to get user input");
	usleep(500000);
	printf(".");
	usleep(500000);
	printf(".");
	usleep(500000);
	printf(".\n");
	sleep(1);
	printf("\n---press return when ready---\033[0m\n");
	getchar();
	return (0);
}

void	get_cohort(char cohort[])
{
	char	buffer[200];
	char	*cohort_tab[11] = {
		"Transferencia",
		"Bocal",
		"Piscine 01/20",
		"Basecamp 02/21",
		"Basecamp 05/21",
		"Basecamp 07/21",
		"Basecamp 08/21",
		"Basecamp 04/22",
		"Basecamp 05/25",
		"Piscine 09/22",
		NULL
	};
	char	yn[20];
	int		cohort_max;
	int		i;

	i = 0;
	while (cohort_tab[i])
		i++;
	cohort_max = i;
	i = 0;
	if (!cohort)
	{
		fprintf(stderr, "ERROR: Something weird happened: Could't get cohort entries.\n");
		exit (1);
	}
	while (yn[0] != 'y')
	{
		memset(yn, 0, 20);
		i = 0;
		printf("\033[32m\n5 - Please select your cohort:\033[0m\n");
		while (i < cohort_max)
		{
			printf("\033[32m\t %c) %s;\033[0m\n", 'a'+i, cohort_tab[i]);
			i++;
		}
		printf ("\033[33mSelect one (a-%c): \033[0m", 'a'+cohort_max - 1);
		fgets(buffer, 200, stdin);
		i = 0;
		if (strlen(buffer) != 2)
		{
			printf("Please, type only one letter;\n");
			continue ;
		}
		while (i < cohort_max)
		{
			if (buffer[0] == 'a' + i)
			{
				memset(cohort, 0, MIFARE_STRING_SIZE);
				memcpy(cohort, cohort_tab[i], strlen(cohort_tab[i]));
				printf("\n\033[33;44m%s\033[0m\033[33m, is that right? (y/n)\033[0m\n", cohort);
				fgets(yn, 20, stdin);
				if (yn[1] == '\n')
					yn[1] = 0;
				for(char *p = yn; *p; ++p)
					*p = *p > 0x40 && *p < 0x5b ? *p | 0x60 : *p;
			}
			i++;
		}
	}
}

void	get_group(char group[])
{
	char	buffer[200];
	char	*group_tab[4] = {
		"Pisciner",
		"Cadet",
		"Bocal",
		NULL
	};
	char	yn[20];
	int		group_max;
	int		i;

	i = 0;
	while (group_tab[i])
		i++;
	group_max = i;
	i = 0;
	if (!group)
	{
		fprintf(stderr, "EROR: Something weird happened: Could't get group entries.\n");
		exit (1);
	}
	while (yn[0] != 'y')
	{
		memset(yn, 0, 20);
		printf("\033\n[32m6 - Select user group:\033[0m\n");
		i = 0;
		while (i < group_max)
		{
			printf("\033[32m\t %c) %s;\033[0m\n", 'a'+i, group_tab[i]);
			i++;
		}
		printf ("\033[33mSelect one (a-%c): \033[0m", 'a'+group_max - 1);
		fgets(buffer, 200, stdin);
		i = 0;
		if (strlen(buffer) != 2)
		{
			printf("Please, type only one letter;\n");
			continue ;
		}
		while (i < group_max)
		{
			if (buffer[0] == 'a' + i)
			{
				memset(group, 0, MIFARE_STRING_SIZE);
				memcpy(group, group_tab[i], strlen(group_tab[i]));
				printf("\n\033[33;44m%s\033[0m\033[33m, is that right? (y/n)\033[0m\n", group);
				fgets(yn, 20, stdin);
				if (yn[1] == '\n')
					yn[1] = 0;
				for(char *p = yn; *p; ++p)
					*p = *p > 0x40 && *p < 0x5b ? *p | 0x60 : *p;
			}
			i++;
		}
	}
}

void	get_campus(char *campus)
{
	char	buffer[200];
	char	*campus_tab[4] = {
		"SP",
		"BH",
		"Rio",
		NULL
	};
	char	yn[20];
	int		campus_max;
	int		i;

	i = 0;
	while (campus_tab[i])
		i++;
	campus_max = i;
	i = 0;
	if (!campus)
	{
		fprintf(stderr, "ERROR: Something weird happened: Could't get campus entries.\n");
		exit (1);
	}
	memset(yn, 0, 20);
	while (yn[0] != 'y')
	{
		memset(yn, 0, 20);
		printf("\033\n[32m6 - Select user campus:\033[0m\n");
		i = 0;
		while (i < campus_max)
		{
			printf("\033[32m\t %c) %s;\033[0m\n", 'a'+i, campus_tab[i]);
			i++;
		}
		printf ("\033[33mSelect one (a-%c): \033[0m", 'a'+campus_max - 1);
		fgets(buffer, 200, stdin);
		i = 0;
		if (strlen(buffer) != 2)
		{
			printf("Please, type only one letter;\n");
			continue ;
		}
		while (i < campus_max)
		{
			if (buffer[0] == 'a' + i)
			{
				memset(campus, 0, MIFARE_STRING_SIZE);
				memcpy(campus, campus_tab[i], strlen(campus_tab[i]));
				printf("\n\033[33;44m%s\033[0m\033[33m, is that right? (y/n)\033[0m\n", campus);
				fgets(yn, 20, stdin);
				if (yn[1] == '\n')
					yn[1] = 0;
				for(char *p = yn; *p; ++p)
					*p = *p > 0x40 && *p < 0x5b ? *p | 0x60 : *p;
			}
			i++;
		}
	}
}

void	get_user_input(t_user_data *user_data)
{
	char	login_check[MIFARE_STRING_SIZE];
	char	yn[20];

	system("clear");
	memset(yn, 0, 20);
	memset(user_data->name, 0, MIFARE_STRING_SIZE);
	memset(user_data->name2, 0, MIFARE_STRING_SIZE);
	memset(user_data->login, 0, MIFARE_STRING_SIZE);
	memset(user_data->cohort, 0, MIFARE_STRING_SIZE);
	memset(user_data->group, 0, MIFARE_STRING_SIZE);
	memset(user_data->campus, 0, MIFARE_STRING_SIZE);

	while (yn[0] != 'y')
	{
		memset(yn, 0, 20);
		printf("\n\033[32m1 - How should we call you: (max 16 chars - don't worry you can add another name afterwards)\n\033[0m");
		fgets(user_data->name, 16, stdin);
		for (int i = 0; i < MIFARE_STRING_SIZE; i++)
		{
			if (user_data->name[i] == '\n')
				user_data->name[i] = 0;
		}
		if (strlen(user_data->name) > MIFARE_STRING_SIZE)
		{
			printf("\033[32;1mSorry, too many letters :/\n\033[0m");
			continue ;
		}
		printf("\n\033[33;44m%s\033[0m\033[33m, is that right? (y/n)\033[0m\n", user_data->name);
		fgets(yn, 20, stdin);
		for(char *p = yn; *p; ++p)
			*p = *p > 0x40 && *p < 0x5b ? *p | 0x60 : *p;
	}
	memset(yn, 0, 20);
	while (yn[0] != 'y')
	{
		printf("\n\033[32m2 - You have another 16 free bytes to call your own!\n\033[0m");
		fgets(user_data->name2, MIFARE_STRING_SIZE, stdin);
		for (int i = 0; i < MIFARE_STRING_SIZE; i++)
		{
			if (user_data->name2[i] == '\n')
				user_data->name2[i] = 0;
		}
		if (strlen(user_data->name2) > MIFARE_STRING_SIZE)
		{
			printf("\033[31;1mSorry, too many letters :/\n\033[0m");
			continue ;
		}
		printf("\n\033[33;44m%s\033[0m\033[33m, is that right? (y/n)\033[0m\n", user_data->name2);
		fgets(yn, 20, stdin);
		for(char *p = yn; *p; ++p)
			*p = *p > 0x40 && *p < 0x5b ? *p | 0x60 : *p;
	}
	memset(yn, 0, 20);
	while (yn[0] != 'y')
	{
		printf("\n\033[32m3 - Please, tell us your intra login.\n\033[0m");
		fgets(user_data->login, MIFARE_STRING_SIZE, stdin);
		for (int i = 0; i < MIFARE_STRING_SIZE; i++)
		{
			if (user_data->login[i] == '\n')
				user_data->login[i] = 0;
		}
		printf("\n\033[32m4 - Lets make a redundancy check. Write it again, please.\n\033[0m");
		fgets(login_check, MIFARE_STRING_SIZE, stdin);
		for (int i = 0; i < MIFARE_STRING_SIZE; i++)
		{
			if (login_check[i] == '\n')
				login_check[i] = 0;
		}
		if (strcmp(user_data->login, login_check))
		{
			printf("\033[31;1mThere seems to be a typo\n\033[0m");
			continue ;
		}
		if (strlen(user_data->login) > MIFARE_STRING_SIZE)
		{
			printf("\033[31;1mSorry, too many letters :/\n\033[0m");
			continue ;
		}
		printf("\n\033[33;44m%s\033[0m\033[33m, is that right? (y/n)\033[0m\n", user_data->login);
		fgets(yn, 20, stdin);
		for(char *p = yn; *p; ++p)
			*p = *p > 0x40 && *p < 0x5b ? *p | 0x60 : *p;
	}
	get_cohort(user_data->cohort);
	get_group(user_data->group);
	get_campus(user_data->campus);
}

int	confirm_user_input(t_user_data *user_data)
{
	char	yn[20];

	memset(yn, 0, 20);

	printf ("\n-------------------------\n");
	printf("\n\033[33mName1:\t\033[0m\033[33;44m%s\033[0m\n", user_data->name);
	printf("\033[33mName2:\t\033[0m\033[33;44m%s\033[0m\n", user_data->name2);
	printf("\033[33mLogin:\t\033[0m\033[33;44m%s\033[0m\n", user_data->login);
	printf("\033[33mCohort:\t\033[0m\033[33;44m%s\033[0m\n", user_data->cohort);
	printf("\033[33mGroup:\t\033[0m\033[33;44m%s\033[0m\n", user_data->group);
	printf("\033[33mCampus:\t\033[0m\033[33;44m%s\033[0m\n", user_data->campus);

	printf("\n\033[0m\033[33mIs everything right? (y/n)\033[0m\n");
		fgets(yn, 20, stdin);
		for(char *p = yn; *p; ++p)
			*p = *p > 0x40 && *p < 0x5b ? *p | 0x60 : *p;
	if (yn[0] == 'y')
		return(0);
	return (1);
}

int register_card(t_user_data *user_data, char *path_to_file, t_nfc *context)
{
	FILE			*fd;
	char			buffer[256];
	unsigned char	rcv_buffer[20];
	unsigned char	password[7];
	t_writer		data;
	char			*ctrl;
	int				i;

	nfc_reconnect(context);
	memset(buffer, 0, 256);
	fd = fopen(path_to_file, "r");
	fseek(fd, 0, SEEK_SET);
	if (nfc_reconnect(context))
		exit(1);
	if (nfc_load_auth_key(context, AUTH_A, NULL, NULL))
		exit (1);
	nfc_start_transaction(context);
	printf("Now writing. Please wait...\n");
	ctrl = buffer;
	while (ctrl)
	{
		memset(buffer, 0 , 256);
		memset(&data, 0, sizeof(data));
		ctrl = fgets(buffer, 256, fd);
		printf ("file read: %s \n", buffer);
		sscanf(buffer, "%d %s", &data.block, data.type);
		printf("block: %d\ttype:%s\n", data.block, data.type);
		if (!strcmp(data.type, "var"))
		{
			sscanf(buffer, "%d %s %s", &data.block, data.type, data.string);
			if (!strcmp(data.string, "$nome"))
			{
				nfc_auth_key(context, AUTH_A, data.block);
				memset(rcv_buffer, 0, 20);
				nfc_write_block(context, (unsigned char *)user_data->name, data.block);
				if (verbose)
				{
					nfc_read_block(context, rcv_buffer, data.block);
					debug_print_bytebuffer(rcv_buffer, 16);
				}
			}
			else if (!strcmp(data.string, "$nome2"))
			{
				nfc_auth_key(context, AUTH_A, data.block);
				memset(rcv_buffer, 0, 20);
				nfc_write_block(context, (unsigned char *)user_data->name2, data.block);
				if (verbose)
				{
					nfc_read_block(context, rcv_buffer, data.block);
					debug_print_bytebuffer(rcv_buffer, 16);
				}
			}
			else if (!strcmp(data.string, "$login"))
			{
				nfc_auth_key(context, AUTH_A, data.block);
				memset(rcv_buffer, 0, 20);
				nfc_write_block(context, (unsigned char *)user_data->login, data.block);
				if (verbose)
				{
					nfc_read_block(context, rcv_buffer, data.block);
					debug_print_bytebuffer(rcv_buffer, 16);
				}
			}
			else if (!strcmp(data.string, "$cohort"))
			{
				nfc_auth_key(context, AUTH_A, data.block);
				memset(rcv_buffer, 0, 20);
				nfc_write_block(context, (unsigned char *)user_data->cohort, data.block);
				if (verbose)
				{
					nfc_read_block(context, rcv_buffer, data.block);
					debug_print_bytebuffer(rcv_buffer, 16);
				}
			}
			else if (!strcmp(data.string, "$group"))
			{
				nfc_auth_key(context, AUTH_A, data.block);
				memset(rcv_buffer, 0, 20);
				nfc_write_block(context, (unsigned char *)user_data->group, data.block);
				if (verbose)
				{
					nfc_read_block(context, rcv_buffer, data.block);
					debug_print_bytebuffer(rcv_buffer, 16);
				}
			}
			else if (!strcmp(data.string, "$campus"))
			{
				nfc_auth_key(context, AUTH_A, data.block);
				memset(rcv_buffer, 0, 20);
				nfc_write_block(context, (unsigned char *)user_data->campus, data.block);
				if (verbose)
				{
					nfc_read_block(context, rcv_buffer, data.block);
					debug_print_bytebuffer(rcv_buffer, 16);
				}
			}
			else
			{
				fprintf(stderr, "File has likely changed during operations!\n");
				exit (1);
			}
		}
		else if (!strcmp(data.type, "string"))
		{
			sscanf(buffer, "%d %s %s", &data.block, data.type, data.string);
			nfc_auth_key(context, AUTH_A, data.block);
			memset(rcv_buffer, 0, 20);
			nfc_write_block(context, (unsigned char *)data.string, data.block);
			if (verbose)
			{
				nfc_read_block(context, rcv_buffer, data.block);
				debug_print_bytebuffer(rcv_buffer, 16);
			}
		}
		else if (!strcmp(data.type, "senha"))
		{
			i = 0;
			sscanf(buffer, "%d %s %x %x %x %x %x %x", &data.block, data.type, &data.senha[0], &data.senha[1], &data.senha[2], &data.senha[3], &data.senha[4], &data.senha[5]);
			memset(password, 0, sizeof(password));
			nfc_auth_key(context, AUTH_A, data.block);
			while (i < 7)
			{
				password[i] = (unsigned char) data.senha[i];
				i++;
			}
			i = 0;
			if (nfc_write_auth_block(context, password, NULL, data.block))
				{
					fprintf (stderr, "Couldn't write password at %d\n", data.block);
				}
			if (verbose)
			{
				printf("Password: ");
				debug_print_hex_bytebuffer(password, 6);
				nfc_read_block(context, rcv_buffer, data.block);
			}
			nfc_reconnect(context);
			nfc_load_auth_key(context, AUTH_A, password, NULL);
			if (nfc_auth_key(context, AUTH_A, data.block))
			{
				fprintf(stderr, "\033[32mUhoh...we have just fucked up a card.\033[0m\n");
				exit (1);
			}
			nfc_load_auth_key(context, AUTH_A, NULL, NULL);
		}
		else if (!strcmp(data.type, "default"))
		{
			memset(data.string, 0 , MIFARE_STRING_SIZE);
			nfc_auth_key(context, AUTH_A, data.block);
			nfc_write_block(context, (unsigned char *)data.string, data.block);
			if (verbose)
			{
				nfc_read_block(context, rcv_buffer, data.block);
				debug_print_bytebuffer(rcv_buffer, 16);
			}
		}
	}
	nfc_end_transaction(context);
	printf("\033[33mWriting operation successfull!\033[0m\n");
	nfc_disconnect(context);
	return (i);
}

int main(int argc, char *argv[])
{
	t_nfc	*context;
	char	buffer[200];
	t_user_data user_data;
	
	#ifdef VERBOSE
	verbose = 1;
	#endif
	verbose = 1;
	memset(&user_data, 0, sizeof(t_user_data));
	context = ft_nfc_init();
	if (!context)
	{
		fprintf(stderr, "ERROR: NFC could not be initialized!");
		exit (1);
	}
	check_arguments(argc, argv);
	validate_file(argv[1]);
	while (check_if_card_is_empty(context))
		continue ;
	while (1)
	{
		get_user_input(&user_data);
		if (!confirm_user_input(&user_data))
			break ;
		memset(&user_data, 0, sizeof(t_user_data));
	}
	printf("\nPress RETURN to proceed to card registry.\n");
	fgets(buffer, 200, stdin);
	register_card(&user_data, argv[1], context);
	nfc_cleanup_before_exit(context);
	printf("Press return to exit...\n");
	memset(buffer, 0, 200);
	fgets(buffer, 200, stdin);
	exit (0);
}