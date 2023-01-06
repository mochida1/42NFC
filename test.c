#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

unsigned int get_week(void)
{
	char buffer[15];
	FILE *fd;

	system("date \"+%W\" > /etc/ft_beep/weeks.cfg");
	fd = fopen("/etc/ft_beep/weeks.cfg", "r");
	fgets(buffer, 15, fd);
	fclose(fd);
	return (atoi(buffer));
}

int main(void)
{
	int week;
	int fd;
	FILE *file;
	char	buffer[200];
	
	week = -1;
	week = get_week();

	printf ("%d\n", week);
	fd = open("/var/log/ft_beep/hmochida.tim", O_WRONLY | O_APPEND | O_CREAT, S_IRWXU);
	printf ("fd: %d\n", fd);
	write(fd, "hello\n", 6);

	file = popen("w", "r");
	while (fgets(buffer, 200, file))
	{
		printf("%s", buffer);
	}
	pclose(file);
	return (0);
}