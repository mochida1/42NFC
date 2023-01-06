NAME = nfc_control
WRTR_NAME = nfc_writer
SIN_NAME = nfc_single
MAKEFLAGS = --no-print-directory
BUILDDIR = objs
WRTR_BUILDDIR = wrtr_objs
SIN_BUILDDIR = single_objs
VPATH = src

# headers
INCLUDES = -I ./headers/

# Lists sources. Manually because of norm...
SRC = main.c ft_nfc.c ft_nfc_transactions.c nfc_debug.c mifare1k.c nfc_security.c ft_messages.c utils.c
WRTR_SRC = wrtr.c ft_nfc.c ft_nfc_transactions.c nfc_debug.c mifare1k.c nfc_security.c ft_messages.c utils.c
SIN_SRC = single_op.c ft_nfc.c ft_nfc_transactions.c nfc_debug.c mifare1k.c nfc_security.c ft_messages.c utils.c

# Names sources
SOURCES = $(SRC)
WRTR_SOURCES = $(WRTR_SRC)
SIN_SOURCES = $(SIN_SRC)

# Names objects
OBJS = $(addprefix $(BUILDDIR)/, $(SOURCES:%.c=%.o))
WRTR_OBJS = $(addprefix $(WRTR_BUILDDIR)/, $(WRTR_SOURCES:%.c=%.o))
SIN_OBJS = $(addprefix $(SIN_BUILDDIR)/, $(SIN_SOURCES:%.c=%.o))

# Compiler
CC = gcc
CF = -Wall -Wextra -Werror
GDB = -ggdb
VAL = valgrind --trace-children=yes --leak-check=full --track-origins=yes ./$(NAME)
FSF = -fsanitize=address

$(NAME): $(BUILDDIR) $(OBJS)
	@printf "Compiling...\n"
	@$(CC) $(CF) $(OBJS) $(INCLUDES) -lpcsclite -lpthread -o $(NAME)
	@printf "Done!\n"

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.o: %.c
	@$(CC) $(CF) $(GDB) $(INCLUDES) -c $< -o $@

##################### NFC WRITER ######################

$(WRTR_NAME): $(WRTR_BUILDDIR) $(WRTR_OBJS)
	@printf "Compiling...\n"
	@$(CC) $(CF) $(WRTR_OBJS) $(INCLUDES) -lpcsclite -o $(WRTR_NAME)
	@printf "Done!\n"

$(WRTR_BUILDDIR):
	@mkdir -p $(WRTR_BUILDDIR)

$(WRTR_BUILDDIR)/%.o: %.c
	@$(CC) $(CF) $(GDB) $(INCLUDES) -c $< -o $@

##################### NFC SIN ######################

$(SIN_NAME): $(SIN_BUILDDIR) $(SIN_OBJS)
	@printf "Compiling...\n"
	@$(CC) $(CF) $(SIN_OBJS) $(INCLUDES) -lpcsclite -o $(SIN_NAME)
	@printf "Done!\n"

$(SIN_BUILDDIR):
	@mkdir -p $(SIN_BUILDDIR)

$(SIN_BUILDDIR)/%.o: %.c
	@$(CC) $(CF) $(GDB) $(INCLUDES) -c $< -o $@

#######################################################

all: $(NAME)

writer: $(WRTR_NAME)

sin: $(SIN_NAME)

clean:
	@rm -rf $(BUILDDIR)
	@rm -rf $(WRTR_BUILDDIR)
	@rm -rf $(SIN_BUILDDIR)
	@rm -f vgcore*

fclean: clean
	@rm -f $(NAME)
	@rm -f $(WRTR_NAME)
	@rm -f $(SIN_NAME)
	@rm -f $(NAME_FS)
	@rm -f vgcore*

re: fclean all

prepare: 
	sudo prepare.sh

run: all
	$(VAL)

fs: $(NAME_FS)
	./$(NAME_FS)

git: fclean
	git add -A
	git commit -m "make git"
	git push

PHONY:	all clean fclean re run