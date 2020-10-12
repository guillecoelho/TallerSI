#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

const struct pam_conv conv = {
	misc_conv,
	NULL
};

int main() {
	pam_handle_t* pamh = NULL;
	int retval_auth, retval_pass;

	printf("Validando modulo configurado en el archivo de configuracon PAM llamado 'tsi'\n\n");

	retval_auth = pam_start("tsi", NULL, &conv, &pamh);
	if (retval_auth == PAM_SUCCESS) {
		printf("Validando interfaz de autenticacion\n");
		retval_auth = pam_authenticate(pamh, 0);
	}
	if (retval_auth == PAM_SUCCESS) {
		printf("Usuario logeado con exito!!!\n");
	}
	if (pam_end(pamh, retval_auth) != PAM_SUCCESS) {
		pamh = NULL;
		exit(1);
	}

	retval_pass = pam_start("tsi", NULL, &conv, &pamh);
	if (retval_pass == PAM_SUCCESS) {
		printf("\nValidando interfaz de password'\n");
		retval_pass = pam_chauthtok(pamh, 0);
	}
	if (retval_pass == PAM_SUCCESS) {
		printf("Cambio de contrasenia con exito!!\n");
	}
	if (pam_end(pamh, retval_pass) != PAM_SUCCESS) {
		pamh = NULL;
		exit(1);
	}

	fprintf(stderr, "\nResultado de autenticacion: %s\n", pam_strerror(pamh, retval_auth));
	fprintf(stderr, "Resultado de cambio de password: %s\n", pam_strerror(pamh, retval_pass));

	return 1;
}