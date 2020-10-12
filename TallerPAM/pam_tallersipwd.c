#define PAM_SM_AUTH
#define PAM_SM_PASSWORD

#include <arpa/inet.h>
#include <gcrypt.h>
#include <ifaddrs.h>
#include <sys/file.h> 
#include <syslog.h>
#include <unistd.h>

/* Include PAM headers */
#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#define MAX_LOCAL_IP 10

/* Code for schemes*/
#define PLAIN_TEXT 0
#define MD5 1
#define SHA256 8
#define LK 3

struct user_info {
    char *username;
	unsigned int scheme;
    char *password;
    char *allow_hosts;
    char *allow_groups;
};

// This method compare 1 local ip vs all the allow host
//	Codes --> Match = 0, Not Match = 1
static int compare_ip(char *allow_hosts, char *local_ip) {
	int result = 1;
	char *ip =  strtok(allow_hosts, ",");
	while (ip != NULL) {
		if (strcmp(local_ip,ip) == 0) {
			result = 0;
			break;
		}
		ip = strtok(NULL, ",");
	}
	return result;
}

// This method get all the local ip and the compare with the allow hosts
//Codes --> Allow = 0, Deny = 1
static int validate_ip(char *allow_hosts) {
    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;
	int result = 1;
    getifaddrs(&ifAddrStruct);
    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4 is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
			result = compare_ip(allow_hosts, addressBuffer);
    		if (result == 0) {break;}

        }
    }
    if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);
    return result;
}

// This method validate the groups
//	Codes --> Allow = 0, Deny = 1
static int validate_group(char *allow_groups) {
	int result = 1;
	unsigned int groupId;
	unsigned int real_groupId = getgid();
	char *group =  strtok(allow_groups, ",");
	while (group != NULL && sscanf(group, "group%d", &groupId) == 1) {
		if (groupId == real_groupId) {
			result = 0;
			break;
		}
		group = strtok(NULL, ",");
	}
    return result;
}

// This method validate the password
//	Codes --> Allow = 0, Deny = 1, Error = 2
static int validate_password(const char *password, const int hash_algo, const char *real_password) {
	int msg_len = strlen( password );
	int result = 1;
    gcry_error_t err;
	gcry_md_hd_t hd; 
	unsigned char *hash;
	if (hash_algo == PLAIN_TEXT) {
		if (strcasecmp(password, real_password) == 0) {
			return 0;
		} else {
			return 1;
		}
	} 
	err = gcry_md_open(&hd, hash_algo,0);
	if (err) { return 2; }
	gcry_md_write(hd, password, msg_len);
	unsigned int l = gcry_md_get_algo_dlen(hash_algo); 
	hash = gcry_md_read(hd, hash_algo);
 	char *out = (char *) malloc( sizeof(char) * ((l*2)+1) );
  	char *p = out;
	unsigned int i;
  	for ( i = 0; i < l; i++, p += 2 ) {
    	snprintf ( p, 3, "%02x", hash[i] );
 	}
	if (strcasecmp(out, real_password) == 0) {
		result = 0;
	}
	gcry_md_close(hd);
	free(out);
	return result;
}

// This create a new hashed password
// Return NULL if error, else return the new password
static char* new_hashed_password(const char *password, const int hash_algo){
	if (hash_algo == PLAIN_TEXT) return strdup(password);
	
	int msg_len = strlen( password );
	unsigned int i;
	unsigned int l;
	unsigned char *hash;
	gcry_error_t err;
	gcry_md_hd_t hd; 

	err = gcry_md_open(&hd, hash_algo,0);
	if (err) { return NULL; }
	gcry_md_write(hd, password, msg_len);
	l = gcry_md_get_algo_dlen(hash_algo); 
	hash = gcry_md_read(hd, hash_algo);
	char *out = (char *) malloc( sizeof(char) * ((l*2)+1) );
	char *p = out;
	p = out;
	for ( i = 0; i < l; i++, p += 2 ) {
			snprintf ( p, 3, "%02x", hash[i] );
	}

	gcry_md_close(hd);
	return out;
}


/* Here start the implementation of the module */

/* Auth interface of the module */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;
	const char *username;
	const char *password;
	int debug = 0;

	char *path;
	struct user_info userData;
	char line[256];
	int next_is_database = 0;

	/* Set flag debug to display warnings if in debug mode, and get database path */
	for (int i = 0; i < argc; i++) {
		if (next_is_database ==  1) {
    		path = (char *) malloc(strlen(argv[i])+1);
    		strcpy(path,argv[i]);
			next_is_database = 0;
		} else {		
		if (strcasecmp(argv[i], "debug") == 0) debug = 1;
		if (strcasecmp(argv[i], "filedb") == 0)	next_is_database = 1;
		}
	}


	// Request username
	retval = pam_get_user(pamh, &username, "Enter your username: ");
 	if (retval != PAM_SUCCESS) {
	    if (debug) syslog(LOG_DEBUG, "Cannot determine username");    
		return retval;  
	}

	
	// Request password
	retval = pam_get_authtok(pamh, PAM_OLDAUTHTOK, &password, NULL);
	if (retval != PAM_SUCCESS) {
		if (debug) syslog(LOG_DEBUG, "Password (old) not obtained");    
		username = NULL;    
		return retval;
	}

	// Try to open the database file
	FILE* passwdFile = fopen(path, "r");
	if (passwdFile == NULL || flock(fileno(passwdFile), LOCK_EX) != 0) {
		if (debug) syslog(LOG_DEBUG, "Error with the database file: %s", path);
		username = password = NULL;    
		return PAM_SYSTEM_ERR;
	}

	// Try to get the username information 
	retval = 1;
	while ((fscanf(passwdFile, "%s\n", line)) != EOF) {
		userData.username = strtok(line, ":");
		// Check for username, if match then get all the data
		if (strcmp(username, userData.username) == 0) {
			userData.scheme = atoi(strtok(NULL, ":"));
			userData.password = strtok(NULL, "::::::");
			strtok(NULL, "=");
			userData.allow_hosts = strtok(NULL, ":");
			strtok(NULL, "=");
			userData.allow_groups = strtok(NULL, ":");
			retval = 0;
			break; 
		}
	}

	if (flock(fileno(passwdFile), LOCK_UN) !=0) {
		if (debug) syslog(LOG_DEBUG, "Error with the database file: %s", path);   
		username = password = NULL; 
		return PAM_SYSTEM_ERR;
	}
	fclose(passwdFile);

	// If the error return is 1 then the user was not found at the database
	if (retval == 1) {
		if (debug) syslog(LOG_DEBUG, "User <%s> not found at the database", username);
		username = password = NULL;    
		return PAM_USER_UNKNOWN;
	}

	// If user have LK as scheme, is block 
	if (userData.scheme == LK) {
		if (debug) syslog(LOG_DEBUG, "User <%s> try to log in and its block", username);
		username = password = NULL;    
		return PAM_AUTH_ERR;
	}

	// Check if local ip are at the allow hosts
	if (( userData.allow_hosts == NULL) && (userData.allow_hosts[0] == '\0')) { 
		if (debug) syslog(LOG_DEBUG, "Cant get the allow hosts of the user <%s> at the database", username);    
		username = password = NULL;    
		return PAM_AUTH_ERR;
	}
	retval = validate_ip(userData.allow_hosts);
	if (retval != 0) {
		if (debug) syslog(LOG_DEBUG, "User <%s> not allow at the allows host", username);
		username = password = NULL;    
		return PAM_PERM_DENIED;
	}

	// Check if real user group is allow, if there arent allow host then no check is need
	if (( userData.allow_hosts != NULL) && (userData.allow_hosts[0] != '\0')) { 
		retval = validate_group(userData.allow_groups);
		if (retval != 0) {
			if (debug) syslog(LOG_DEBUG, "User <%s> not allow at the allows gruop <%s>", username, userData.allow_groups);
			username = password = NULL;    
			return PAM_PERM_DENIED;
		}
	}

	// Validate old password
	retval = validate_password(password, userData.scheme, userData.password);
	if (retval != 0) {
		if (retval == 1) {
			if (debug) syslog(LOG_DEBUG, "User <%s> enter wrong password", userData.username);
		} else if (retval == 1) {
			if (debug) syslog(LOG_DEBUG, "Problems with glibcrpyt");
		}
		username = password = NULL;
		return PAM_AUTH_ERR;
	}
	
	// Success
	username = password = NULL;
	return PAM_SUCCESS;
}


/* Password interface of the module */
PAM_EXTERN int pam_sm_chauthtok( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;
	struct user_info userData;
	const char *user;
	const char *pass_old, *pass_new, *pass_real, *input;
	unsigned int scheme_real;
	struct pam_response *resp;
	struct pam_conv *conversation;
	struct pam_message message;
	const struct pam_message *pmessage;

	int debug = 0;
	char *path;
	char line[256];
	int next_is_database = 0;

	/* Set flag debug to display warnings if in debug mode, and get database path */
	for (int i = 0; i < argc; i++) {
		if (next_is_database ==  1) {
    		path = (char *) malloc(strlen(argv[i])+1);
    		strcpy(path,argv[i]);
			next_is_database = 0;
		} else {		
		if (strcasecmp(argv[i], "debug") == 0) debug = 1;
		if (strcasecmp(argv[i], "filedb") == 0)	next_is_database = 1;
		}
	}

	// Request username
	const char *dfwa ;
	retval = pam_get_user(pamh, &dfwa, "Enter your username: ");
 	if (retval != PAM_SUCCESS) {
	    if (debug) syslog(LOG_DEBUG, "Cannot determine username");    
		return retval;  
	}
	if (flags & PAM_PRELIM_CHECK) {
		// Request username
		retval = pam_get_user(pamh, &user, "Enter your username: ");
		if (retval != PAM_SUCCESS) {
			if (debug) syslog(LOG_DEBUG, "Cannot determine username");    
			return retval;  
		}

		// Request old password
		retval = pam_get_authtok(pamh, PAM_OLDAUTHTOK, &pass_old, NULL);
		if (retval != PAM_SUCCESS) {
			if (debug) syslog(LOG_DEBUG, "Password (old) not obtained");
			user = NULL;    
			return retval;
		}

		// Try to open the database file
		FILE* passwdFile = fopen(path, "r");
		if (passwdFile == NULL || flock(fileno(passwdFile), LOCK_EX) != 0) {
			if (debug) syslog(LOG_DEBUG, "Error with the database file: %s", path);
			pass_new = pass_old = user = NULL;
			return PAM_SYSTEM_ERR;
		}

		// Try to get the username information 
		retval = 1;
		while ((fscanf(passwdFile, "%s\n", line)) != EOF) {
			// Check for username, if match then get all the data
			if (strcmp(strtok(line, ":"),user) == 0) {
				scheme_real = atoi(strtok(NULL, ":"));
				pass_real = strtok(NULL, "::::::");
				retval = 0;
				break; 
			}	
		}
		if (flock(fileno(passwdFile), LOCK_UN) !=0) {
			if (debug) syslog(LOG_DEBUG, "Error reding the database file: %s", path);   
			pass_new = pass_old = pass_real = user = NULL;
			return PAM_SYSTEM_ERR;
		}
		fclose(passwdFile);


		// If the error return is 1 then the user was not found at the database
		if (retval == 1) {
			if (debug) syslog(LOG_DEBUG, "User <%s> not found at the database", user);
			pass_new = pass_old = user = NULL;
			return PAM_USER_UNKNOWN;
		}

		// If user have LK as scheme, is block 
		if (scheme_real == LK) {
			if (debug) syslog(LOG_DEBUG, "User <%s> try to log in and its block", user);
			pass_new = pass_old = user = NULL;
		}

		// Validate old password
		retval = validate_password(pass_old, scheme_real, pass_real);
		if (retval != 0) {
			if (retval == 1) {
				if (debug) syslog(LOG_DEBUG, "User <%s> enter wrong password", user);
			} else if (retval == 1) {
				if (debug) syslog(LOG_DEBUG, "Problems with glibcrpyt");
			}
			pass_new = pass_old = user = pass_real = NULL;
			return PAM_USER_UNKNOWN;
		}
	} else if (flags & PAM_UPDATE_AUTHTOK){	
		// Request new password
		retval = pam_get_authtok(pamh, PAM_AUTHTOK, &pass_new, NULL);
		if (pass_new == NULL || pass_new[0] == '\0' || (pass_old && !strcmp(pass_old, pass_new))) {
			if (debug) syslog(LOG_DEBUG, "New password its not acceptable");
			pass_new = pass_old = user = NULL;
			return PAM_AUTHTOK_ERR;
		}

		//Request new hash algorithm , Try to open a conversation
		pmessage = &message;
		message.msg_style = PAM_PROMPT_ECHO_ON;
		message.msg = "Enter the number for the required algoritm (1: Plaintext, 2: MD5 , 3: SHA-256 ): ";
		retval = pam_get_item(pamh, PAM_CONV, (const void **) &conversation);
		if (retval != PAM_SUCCESS) {
			if (debug) syslog(LOG_DEBUG, "Cannot start conversation");    
			return PAM_CONV_ERR;
		}

		// Request scheme
		retval = conversation->conv(1, &pmessage, &resp, conversation->appdata_ptr);
		if (retval != PAM_SUCCESS) {
			if (debug) syslog(LOG_DEBUG, "Cannot determine the scheme");    
			return PAM_CONV_AGAIN;
		}

		// Get the scheme
		if (resp) {
			if( (PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL ) {
					free( resp );
					if (debug) syslog(LOG_DEBUG, "Scheme is empty or null");   
					pass_new = pass_old = user = NULL; 
					return PAM_AUTH_ERR;
			}
			input = resp[0].resp;
			resp[0].resp = NULL; 		  				  
		} else {
			if (debug) syslog(LOG_DEBUG, "Cannot determine the scheme");    
			pass_new = pass_old = user = NULL;
			return PAM_CONV_ERR;
		}

		//Hash password
		char* pass_new_hash;
		unsigned int scheme_new;
		switch ( atoi(input) )	{
			case 1:
				for(long unsigned int k = 0; k <= strlen(pass_new); k++){
					if( pass_new[k] == '{' || pass_new[k] == ':' || pass_new[k] == ','){
						if (debug) syslog(LOG_DEBUG, "User <%s> enter a new password with ilegal characters", user);    
						pass_new = pass_old = user = NULL;
						return PAM_AUTH_ERR;
					}
					pass_new_hash = new_hashed_password(pass_new, PLAIN_TEXT);
				}
				scheme_new = 0;
				break;
			case 2:
				pass_new_hash = new_hashed_password(pass_new, MD5);
				scheme_new = MD5;
				break;
			case 3:
				pass_new_hash = new_hashed_password(pass_new, SHA256);
				scheme_new = SHA256;
				break;
			default:
				if (debug) syslog(LOG_DEBUG, "User <%s> enter a wrong schema", user);
				pass_new = pass_old = user = NULL;
				return PAM_AUTH_ERR;

		}
		if (pass_new_hash == NULL) {
			if (debug) syslog(LOG_DEBUG, "Problems with glibcrpyt");
			pass_new = pass_old = user = NULL;
			return PAM_AUTH_ERR;
		}

		// Try to open the database file
		FILE* passwdFile = fopen(path, "r+");
		if (passwdFile == NULL || flock(fileno(passwdFile), LOCK_EX) != 0) {
			if (debug) syslog(LOG_DEBUG, "Error with the database file: %s", path);
			pass_new = pass_old = user = NULL;
			return PAM_SYSTEM_ERR;
		}

		// Try to get the username information 
		retval = 1;
		while ((fscanf(passwdFile, "%s\n", line)) != EOF) {
			userData.username = strtok(line, ":");
			// Check for username, if match then get all the data
			if (strcmp(user, userData.username) == 0) {
				userData.scheme = atoi(strtok(NULL, ":"));
				userData.password = strtok(NULL, "::::::");
				strtok(NULL, "=");
				userData.allow_hosts = strtok(NULL, ":");
				strtok(NULL, "=");
				userData.allow_groups = strtok(NULL, ":");
				retval = 0;
				break; 
			}	
		}
		// If the error return is 1 then the user was not found at the database
		if (retval == 1) {
			if (debug) syslog(LOG_DEBUG, "User <%s> not found at the database", user);
			pass_new = pass_old = user = NULL;
			flock(fileno(passwdFile), LOCK_UN);
			return PAM_USER_UNKNOWN;
		}

		char *old_line, *new_line, *command;
		if ((asprintf (&old_line, "%s:%d:%s::::::allow_hosts=%s:allow_group=%s",userData.username, userData.scheme, userData.password, userData.allow_hosts,
		userData.allow_groups) < 0) || (asprintf (&new_line, "%s:%d:%s::::::allow_hosts=%s:allow_group=%s",userData.username, scheme_new, pass_new_hash, userData.allow_hosts,
		userData.allow_groups) < 0) || (asprintf (&command, "sed -i '/%s/c%s' %s", old_line, new_line,path) < 0) ){
			pass_new = pass_old = user = pass_real = NULL;
			flock(fileno(passwdFile), LOCK_UN);
			return PAM_AUTH_ERR;
		}

	
		system(command);
		if (flock(fileno(passwdFile), LOCK_UN) !=0) {
			if (debug) syslog(LOG_DEBUG, "Error with the database file: %s", path);   
			pass_new = pass_old = pass_real = user = NULL;
			return PAM_SYSTEM_ERR;
		}
		fclose(passwdFile);

	} else {
		if (debug) syslog(LOG_DEBUG, "Password received unknown request");   
		return PAM_SUCCESS;
	}
	

	return PAM_SUCCESS;
}	
