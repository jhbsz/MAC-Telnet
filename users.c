/*
    Mac-Telnet - Connect to RouterOS or mactelnetd devices via MAC address
    Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include "users.h"
#include "config.h"

LIST_HEAD(mt_users);

void read_userfile(void)
{
	char line[BUFSIZ];
	struct mt_credentials *cred;
	FILE *file = fopen(USERSFILE, "r");

	if (file == NULL) {
		perror(USERSFILE);
		exit(1);
	}

	while (fgets(line, sizeof line, file))
	{
		char *user;
		char *password;

		user = strtok(line, ":");
		password = strtok(NULL, "\n");

		if (!user || !password || *user == '#')
			continue;

		cred = calloc(1, sizeof(*cred));

		if (!cred)
			continue;

		strncpy(cred->username, user, sizeof(cred->username) - 1);
		strncpy(cred->password, password, sizeof(cred->password) - 1);

		list_add_tail(&cred->list, &mt_users);
	}

	fclose(file);
}

struct mt_credentials* find_user(char *username)
{
	struct mt_credentials *cred;

	list_for_each_entry(cred, &mt_users, list)
		if (!strcmp(cred->username, username))
			return cred;

	return NULL;
}


void drop_privileges(char *username)
{
	struct passwd *user = (struct passwd *) getpwnam(username);
	if (user == NULL) {
		fprintf(stderr, "Failed dropping privileges. The user %s is not a valid username on local system.\n", username);
		exit(1);
	}
	if (getuid() == 0) {
		/* process is running as root, drop privileges */
		if (setgid(user->pw_gid) != 0) {
			perror("setgid: Error dropping group privileges");
		    exit(1);
		}
		if (setuid(user->pw_uid) != 0) {
			perror("setuid: Error dropping user privileges");
		    exit(1);
		}
		/* Verify if the privileges were dropped. */
		if (setuid(0) != -1) {
			perror("Failed to drop privileges");
			exit(1);
		}
	}
	else {
		fprintf(stderr, "Failed dropping privileges. Not running as privileged user.\n");
		exit(1);
	}
}
