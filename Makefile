# file:        Makefile
# description: Aurora PAM library Makefile
# authors:     Cyrille TOULET <cyrille.toulet@linux.com>

# Configuration
#INSTALLATION_PATH = /lib/security
INSTALLATION_PATH = /lib/x86_64-linux-gnu/security


# Objects
OBJ = bin/pam_aurora_email.so


# Rules
all: $(OBJ)

bin/pam_aurora_email.so: src/pam_aurora_email.c
	gcc -fPIC -fno-stack-protector -o bin/pam_aurora_email.so -c src/pam_aurora_email.c -lconfig -lcurl -luuid -Wall


# Phony
install: $(OBJ)
	sudo ld -x --shared -o  $(INSTALLATION_PATH)/pam_aurora_email.so bin/pam_aurora_email.so -lconfig -lcurl -luuid

uninstall:
	sudo rm $(INSTALLATION_PATH)/pam_aurora_email.so

clean:
	rm -f $(OBJ)

.PHONY: clean install uninstall
