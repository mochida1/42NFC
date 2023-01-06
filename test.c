#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int get_current_time(char *buffer)
{
	FILE	*fd;

	fd = popen("date \"+%m%d%y %H%M%S\"", "r");
	fgets(buffer, 14, fd);

	pclose(fd);
	return(0);
}

int	msg_log(char *message, int type)
{
	int	fd;
	char buffer[256];
	static unsigned int	message_number;
	
	memset(buffer, 0, 256);
	snprintf(buffer, 7, "%06u", message_number);
	printf("buffer: %s\n", buffer);
	strncat(buffer, message, strlen(message));
	strncat(buffer,"\n", 2);
// 100000 
// 01234567
	if (type == 0)
		fd = open("/var/log.hdd/ft_beep/error.log", O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
	else if (type == 1)
		fd = open("/var/log.hdd/ft_beep/log.log", O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
	else if (type == 2)
		fd = open("/var/log.hdd/ft_beep/sec.log", O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
	else if (type == 3)
		fd = open("/var/log.hdd/ft_beep/usr.log", O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
	else
		fd = open("/var/log.hdd/ft_beep/mystery.log", O_RDWR | O_APPEND | O_CREAT, S_IRWXU);
	write(fd, buffer, strlen(buffer));
	close (fd);
	message_number++;
	if (message_number > 999999)
		message_number = 0;
	return (0);
}

int main(void)
{
	msg_log("teste error!", 0);
	msg_log("teste general!", 1);
	msg_log("teste sec!", 2);
	msg_log("teste usr!", 3);
	msg_log("teste mystery!", 4);
}